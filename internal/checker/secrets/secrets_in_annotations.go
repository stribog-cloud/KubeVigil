package secrets

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// systemManagedAnnotationKeys are annotations written by Kubernetes itself or
// common controllers whose values are large serialized blobs, not secrets.
// They are excluded from entropy-based detection to avoid systematic false
// positives (e.g., kubectl's last-applied-configuration annotation embeds an
// entire JSON manifest, which can read as high entropy).
var systemManagedAnnotationKeys = map[string]bool{
	"kubectl.kubernetes.io/last-applied-configuration": true,
}

// InAnnotationsChecker detects workload resources (Deployments, Pods, etc.)
// with secret-looking values embedded directly in metadata.annotations or
// metadata.labels. Annotations and labels are readable by anyone with basic
// get/list RBAC on the resource type, entirely bypassing the tighter RBAC
// most clusters apply to the secrets resource — making this surface worse
// than the ConfigMap case already covered by [InConfigMapChecker].
type InAnnotationsChecker struct{}

// Name returns the kebab-case check ID.
func (c *InAnnotationsChecker) Name() string { return "secrets-in-annotations" }

// Description returns a human-readable description.
func (c *InAnnotationsChecker) Description() string {
	return "Detects workload resources with secret-looking values (API keys, tokens, high-entropy strings) embedded in metadata.annotations or metadata.labels."
}

// Categories returns the check categories.
func (c *InAnnotationsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
func (c *InAnnotationsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *InAnnotationsChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the secrets-in-annotations check against all workload resources in the cache.
func (c *InAnnotationsChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-in-annotations check: %w", err)
	}

	entropyThreshold := DefaultEntropyThreshold
	if p := cache.Policies(); p != nil && p.Secrets.EntropyThreshold > 0 {
		entropyThreshold = p.Secrets.EntropyThreshold
	}

	var findings []checker.Finding
	for _, gvr := range workload.GVRs() {
		resources := cache.List(gvr)
		for i := range resources {
			obj := &resources[i]
			findings = append(findings, scanMetadataValues(obj, "annotations", "annotation", obj.GetAnnotations(), entropyThreshold)...)
			findings = append(findings, scanMetadataValues(obj, "labels", "label", obj.GetLabels(), entropyThreshold)...)
		}
	}

	return findings, nil
}

// scanMetadataValues applies the same entropy/pattern-matching strategies
// used by [InConfigMapChecker] to a metadata.annotations or metadata.labels
// map, returning a Finding per matching key.
func scanMetadataValues(obj *unstructured.Unstructured, field, noun string, values map[string]string, entropyThreshold float64) []checker.Finding {
	if len(values) == 0 {
		return nil
	}

	name := obj.GetName()
	namespace := obj.GetNamespace()
	kind := obj.GetKind()

	var findings []checker.Finding
	for key, value := range values {
		if value == "" || systemManagedAnnotationKeys[key] {
			continue
		}

		var message string
		switch {
		case IsSecretKeyName(key):
			message = fmt.Sprintf("%s %q has %s %q whose key name suggests it contains a secret", kind, name, noun, key)
		case HasKnownSecretPattern(value):
			message = fmt.Sprintf("%s %q has %s %q with a value matching a known secret pattern", kind, name, noun, key)
		case !IsConfigFileKey(key) && IsLikelySecret(value, entropyThreshold):
			message = fmt.Sprintf("%s %q has %s %q with a high-entropy value (possible secret)", kind, name, noun, key)
		default:
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:     "secrets-in-annotations",
			Severity:    checker.SeverityHigh,
			Resource:    name,
			Namespace:   namespace,
			Kind:        kind,
			Message:     message,
			Remediation: secretsInAnnotationsRemediation,
			FieldPath:   fmt.Sprintf(".metadata.%s.%s", field, key),
		})
	}

	return findings
}

const secretsInAnnotationsRemediation = "## Why This Matters\n\n" +
	"Annotations and labels are readable by anyone with `get`/`list` RBAC on the resource type — " +
	"typically far broader than the RBAC applied to the `secrets` resource. A credential embedded " +
	"in a Deployment's annotations or labels is exposed to every user, CI job, or controller that " +
	"can read Deployments, entirely bypassing tighter Secret-specific access controls.\n\n" +
	"## How to Fix\n\n" +
	"Move the value into a Secret and reference it normally:\n\n" +
	"```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\ntype: Opaque\nstringData:\n  api-key: \"<managed-externally>\"\n```\n\n" +
	"Rotate any credential that was previously committed to an annotation or label, since it may " +
	"already be cached by API clients, audit logs, or GitOps tooling that snapshots object metadata.\n\n" +
	"## Learn More\n\n" +
	"CIS Kubernetes Benchmark 5.4.1 requires secrets to be stored in Secret objects. See the " +
	"Kubernetes RBAC documentation for how `get`/`list` on a resource type exposes its metadata."
