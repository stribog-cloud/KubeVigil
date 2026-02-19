package secrets

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// DefaultTypeChecker detects Secrets using the Opaque type where a more specific
// built-in Secret type would be appropriate. Kubernetes provides typed Secrets
// (e.g., kubernetes.io/tls, kubernetes.io/basic-auth) that enable better validation
// and tooling support.
type DefaultTypeChecker struct{}

// Name returns the kebab-case check ID.
func (c *DefaultTypeChecker) Name() string { return "secrets-default-type" }

// Description returns a human-readable description.
func (c *DefaultTypeChecker) Description() string {
	return "Detects Secrets using Opaque type where a more specific type exists based on the data keys."
}

// Categories returns the check categories.
func (c *DefaultTypeChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
func (c *DefaultTypeChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *DefaultTypeChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{SecretGVR}
}

// Run executes the secrets-default-type check against all Secrets in the cache.
func (c *DefaultTypeChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-default-type check: %w", err)
	}

	secrets := cache.List(SecretGVR)
	var findings []checker.Finding

	for i := range secrets {
		obj := &secrets[i]

		// Get the secret type. Empty string or "Opaque" both mean default/opaque.
		secretType, _, _ := unstructuredString(obj.Object, "type")
		if secretType != "" && secretType != "Opaque" {
			continue // already using a specific type
		}

		// Extract data keys.
		keys := extractDataKeys(obj.Object)
		if len(keys) == 0 {
			continue // no data, nothing to recommend
		}

		recommended := SecretTypeForKeys(keys)
		if recommended == "" {
			continue // no better type found
		}

		findings = append(findings, checker.Finding{
			Checker:   "secrets-default-type",
			Severity:  checker.SeverityLow,
			Resource:  obj.GetName(),
			Namespace: obj.GetNamespace(),
			Kind:      obj.GetKind(),
			Message: fmt.Sprintf(
				"Secret %q uses Opaque type but data keys suggest it should be %q.",
				obj.GetName(), recommended,
			),
			Remediation: fmt.Sprintf(
				"## Why This Matters\n\n"+
					"Kubernetes provides built-in Secret types (e.g., kubernetes.io/tls, kubernetes.io/basic-auth) "+
					"that enforce required key names and enable automatic validation. Using the generic Opaque type "+
					"bypasses these guardrails, making misconfigurations harder to catch and reducing interoperability "+
					"with tools like cert-manager, Ingress controllers, and kubectl.\n\n"+
					"## How to Fix\n\n"+
					"Change the Secret type to the recommended built-in type:\n\n"+
					"```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\ntype: %s    # Use the specific type\n```\n\n"+
					"Kubernetes will validate that the required data keys are present for the chosen type.\n\n"+
					"## Learn More\n\n"+
					"See the Kubernetes Secret types documentation for the full list of built-in types "+
					"and their required keys. CIS Benchmark recommends using typed secrets for better auditability.",
				recommended,
			),
			FieldPath: ".type",
		})
	}

	return findings, nil
}

// unstructuredString retrieves a string field from an unstructured object map.
func unstructuredString(obj map[string]interface{}, key string) (val string, ok bool, err error) {
	raw, found := obj[key]
	if !found {
		return "", false, nil
	}
	val, ok = raw.(string)
	if !ok {
		return "", true, fmt.Errorf("field %q is not a string", key)
	}
	return val, true, nil
}

// extractDataKeys returns the keys from the .data map of an unstructured Secret.
func extractDataKeys(obj map[string]interface{}) []string {
	dataRaw, found := obj["data"]
	if !found {
		return nil
	}
	dataMap, ok := dataRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(dataMap))
	for k := range dataMap {
		keys = append(keys, k)
	}
	return keys
}
