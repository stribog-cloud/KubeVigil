package secrets

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// InConfigMapChecker detects ConfigMaps containing values that look like secrets.
// ConfigMaps are not encrypted at rest, have weaker access controls than Secrets,
// and can be read by anyone with read access to the namespace.
type InConfigMapChecker struct{}

// Name returns the kebab-case check ID.
func (c *InConfigMapChecker) Name() string { return "secrets-in-configmap" }

// Description returns a human-readable description.
func (c *InConfigMapChecker) Description() string {
	return "Detects ConfigMaps containing values that look like secrets using key name matching, known pattern matching, and entropy analysis."
}

// Categories returns the check categories.
func (c *InConfigMapChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
func (c *InConfigMapChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *InConfigMapChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ConfigMapGVR}
}

// Run executes the secrets-in-configmap check against all ConfigMaps in the cache.
func (c *InConfigMapChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-in-configmap check: %w", err)
	}

	entropyThreshold := DefaultEntropyThreshold
	if policies := cache.Policies(); policies != nil && policies.Secrets.EntropyThreshold > 0 {
		entropyThreshold = policies.Secrets.EntropyThreshold
	}

	configMaps := cache.List(ConfigMapGVR)
	var findings []checker.Finding

	for i := range configMaps {
		cm := &configMaps[i]
		cmName := cm.GetName()
		cmNamespace := cm.GetNamespace()

		// Extract the .data map from the unstructured ConfigMap.
		dataObj, found, err := nestedStringMap(cm.Object, "data")
		if err != nil || !found {
			continue
		}

		for key, value := range dataObj {
			fieldPath := fmt.Sprintf(".data.%s", key)

			// Strategy 1: Key name matching.
			if IsSecretKeyName(key) {
				findings = append(findings, checker.Finding{
					Checker:   "secrets-in-configmap",
					Severity:  checker.SeverityHigh,
					Resource:  cmName,
					Namespace: cmNamespace,
					Kind:      "ConfigMap",
					Message:   fmt.Sprintf("ConfigMap %q has key %q that appears to contain a secret", cmName, key),
					Remediation: "## Why This Matters\n\n" +
						"ConfigMaps are not encrypted at rest and have weaker RBAC defaults than Secrets. " +
						"Any user with namespace read access can view ConfigMap data, making them an " +
						"inappropriate store for passwords, tokens, API keys, or private keys.\n\n" +
						"## How to Fix\n\n" +
						"Move sensitive values from the ConfigMap into a Secret resource:\n\n" +
						"```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\ntype: Opaque\nstringData:\n  password: \"<managed-externally>\"\n```\n\n" +
						"For production workloads, use an external secret manager (Vault, AWS Secrets " +
						"Manager, GCP Secret Manager) with the External Secrets Operator.\n\n" +
						"## Learn More\n\n" +
						"CIS Kubernetes Benchmark 5.4.1 requires secrets to be stored in Secret objects, " +
						"not ConfigMaps. See the Kubernetes Secrets documentation for proper usage.",
					FieldPath: fieldPath,
				})
				continue
			}

			// Strategy 2: Known pattern matching.
			if HasKnownSecretPattern(value) {
				findings = append(findings, checker.Finding{
					Checker:   "secrets-in-configmap",
					Severity:  checker.SeverityHigh,
					Resource:  cmName,
					Namespace: cmNamespace,
					Kind:      "ConfigMap",
					Message:   fmt.Sprintf("ConfigMap %q has value in key %q matching known secret pattern", cmName, key),
					Remediation: "## Why This Matters\n\n" +
						"ConfigMaps are not encrypted at rest and have weaker RBAC defaults than Secrets. " +
						"Any user with namespace read access can view ConfigMap data, making them an " +
						"inappropriate store for passwords, tokens, API keys, or private keys.\n\n" +
						"## How to Fix\n\n" +
						"Move sensitive values from the ConfigMap into a Secret resource:\n\n" +
						"```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\ntype: Opaque\nstringData:\n  password: \"<managed-externally>\"\n```\n\n" +
						"For production workloads, use an external secret manager (Vault, AWS Secrets " +
						"Manager, GCP Secret Manager) with the External Secrets Operator.\n\n" +
						"## Learn More\n\n" +
						"CIS Kubernetes Benchmark 5.4.1 requires secrets to be stored in Secret objects, " +
						"not ConfigMaps. See the Kubernetes Secrets documentation for proper usage.",
					FieldPath: fieldPath,
				})
				continue
			}

			// Strategy 3: Entropy analysis (skip config file keys).
			if !IsConfigFileKey(key) && IsLikelySecret(value, entropyThreshold) {
				findings = append(findings, checker.Finding{
					Checker:   "secrets-in-configmap",
					Severity:  checker.SeverityHigh,
					Resource:  cmName,
					Namespace: cmNamespace,
					Kind:      "ConfigMap",
					Message:   fmt.Sprintf("ConfigMap %q has high-entropy value in key %q (possible secret)", cmName, key),
					Remediation: "## Why This Matters\n\n" +
						"ConfigMaps are not encrypted at rest and have weaker RBAC defaults than Secrets. " +
						"Any user with namespace read access can view ConfigMap data, making them an " +
						"inappropriate store for passwords, tokens, API keys, or private keys.\n\n" +
						"## How to Fix\n\n" +
						"Move sensitive values from the ConfigMap into a Secret resource:\n\n" +
						"```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\ntype: Opaque\nstringData:\n  password: \"<managed-externally>\"\n```\n\n" +
						"For production workloads, use an external secret manager (Vault, AWS Secrets " +
						"Manager, GCP Secret Manager) with the External Secrets Operator.\n\n" +
						"## Learn More\n\n" +
						"CIS Kubernetes Benchmark 5.4.1 requires secrets to be stored in Secret objects, " +
						"not ConfigMaps. See the Kubernetes Secrets documentation for proper usage.",
					FieldPath: fieldPath,
				})
				continue
			}
		}
	}

	return findings, nil
}

// nestedStringMap extracts a map[string]string from a nested unstructured map path.
func nestedStringMap(obj map[string]interface{}, fields ...string) (result map[string]string, ok bool, err error) {
	current := obj
	for i, field := range fields {
		val, ok := current[field]
		if !ok {
			return nil, false, nil
		}
		if i == len(fields)-1 {
			// Last field — expect map[string]interface{} and convert to map[string]string.
			m, ok := val.(map[string]interface{})
			if !ok {
				return nil, false, fmt.Errorf("expected map at %q, got %T", field, val)
			}
			result := make(map[string]string, len(m))
			for k, v := range m {
				s, ok := v.(string)
				if !ok {
					continue
				}
				result[k] = s
			}
			return result, true, nil
		}
		nested, ok := val.(map[string]interface{})
		if !ok {
			return nil, false, fmt.Errorf("expected nested map at %q, got %T", field, val)
		}
		current = nested
	}
	return nil, false, nil
}
