package secrets

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// StaleChecker detects Secrets that have not been rotated within a configurable period.
// Long-lived secrets increase the blast radius of a compromise. Regular rotation
// limits the window of exposure for leaked credentials.
type StaleChecker struct{}

// Name returns the kebab-case check ID.
func (c *StaleChecker) Name() string { return "secrets-stale" }

// Description returns a human-readable description.
func (c *StaleChecker) Description() string {
	return "Detects Secrets not rotated within a configurable period."
}

// Categories returns the check categories.
func (c *StaleChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
// Only live mode — manifests don't have reliable timestamps.
func (c *StaleChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *StaleChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{SecretGVR}
}

// Run executes the secrets-stale check against all Secrets in the cache.
func (c *StaleChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-stale check: %w", err)
	}

	maxAgeDays := DefaultMaxAgeDays
	if p := cache.Policies(); p != nil && p.Secrets.MaxAgeDays > 0 {
		maxAgeDays = p.Secrets.MaxAgeDays
	}

	secrets := cache.List(SecretGVR)
	var findings []checker.Finding

	for i := range secrets {
		obj := &secrets[i]

		// Skip secrets in kube-system namespace (system secrets).
		if obj.GetNamespace() == "kube-system" {
			continue
		}

		// Skip service-account-token secrets (auto-managed by Kubernetes).
		secretType, _, _ := unstructuredString(obj.Object, "type")
		if secretType == "kubernetes.io/service-account-token" { //nolint:gosec // Not a credential; Kubernetes Secret type constant.
			continue
		}

		// Determine the effective timestamp for staleness evaluation.
		timestamp := resolveRotationTimestamp(obj)
		if timestamp.IsZero() {
			continue
		}

		ageDays := int(time.Since(timestamp).Hours() / 24)
		if ageDays <= maxAgeDays {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "secrets-stale",
			Severity:  checker.SeverityMedium,
			Resource:  obj.GetName(),
			Namespace: obj.GetNamespace(),
			Kind:      obj.GetKind(),
			Message: fmt.Sprintf(
				"Secret %q in namespace %q is %d days old and may need rotation.",
				obj.GetName(), obj.GetNamespace(), ageDays,
			),
			Remediation: "## Why This Matters\n\n" +
				"Long-lived secrets increase the blast radius of a compromise. If a credential is " +
				"leaked, the exposure window equals the time since the last rotation. Regular " +
				"rotation limits attacker access even if credentials are stolen.\n\n" +
				"## How to Fix\n\n" +
				"Rotate the secret and record the rotation timestamp with an annotation:\n\n" +
				"```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\n  annotations:\n    kubevigil.io/last-rotated: \"2025-01-15T00:00:00Z\"\ntype: Opaque\nstringData:\n  password: \"<new-rotated-value>\"\n```\n\n" +
				"Automate rotation using Vault dynamic secrets, AWS Secrets Manager rotation " +
				"lambdas, or the External Secrets Operator's rotation features.\n\n" +
				"## Learn More\n\n" +
				"NIST SP 800-63B and CIS Benchmark recommend periodic credential rotation. " +
				"Configure the rotation period in `.kubevigil.yaml` under `policies.secrets.maxAgeDays`.",
			FieldPath: ".metadata.creationTimestamp",
		})
	}

	return findings, nil
}

// resolveRotationTimestamp checks for rotation annotations and falls back
// to the creation timestamp of the Secret.
func resolveRotationTimestamp(obj *unstructured.Unstructured) time.Time {
	annotations := obj.GetAnnotations()

	// Check known rotation annotations in priority order.
	for _, key := range []string{"kubevigil.io/last-rotated", "secret-rotated-at"} {
		if val, ok := annotations[key]; ok {
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				return t
			}
		}
	}

	// Fall back to creation timestamp.
	return obj.GetCreationTimestamp().Time
}
