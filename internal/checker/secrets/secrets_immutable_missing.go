package secrets

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ImmutableMissingChecker detects Secret resources that do not set
// immutable: true, missing the Kubernetes 1.21+ hardening feature that
// prevents accidental or malicious in-place modification of a Secret's data
// and reduces API server watch churn.
type ImmutableMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *ImmutableMissingChecker) Name() string { return "secrets-immutable-missing" }

// Description returns a human-readable description.
func (c *ImmutableMissingChecker) Description() string {
	return "Detects Secret resources without immutable: true, missing the hardening feature that prevents in-place modification of Secret data."
}

// Categories returns the check categories.
func (c *ImmutableMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
func (c *ImmutableMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ImmutableMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{SecretGVR}
}

// Run executes the secrets-immutable-missing check against all Secrets in the cache.
func (c *ImmutableMissingChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-immutable-missing check: %w", err)
	}

	secrets := cache.List(SecretGVR)
	var findings []checker.Finding

	for i := range secrets {
		obj := &secrets[i]
		if isSecretImmutable(obj) {
			continue
		}

		name := obj.GetName()

		findings = append(findings, checker.Finding{
			Checker:   "secrets-immutable-missing",
			Severity:  checker.SeverityLow,
			Resource:  name,
			Namespace: obj.GetNamespace(),
			Kind:      obj.GetKind(),
			Message:   fmt.Sprintf("Secret %q does not set immutable: true, allowing in-place modification of its data.", name),
			Remediation: "## Why This Matters\n\n" +
				"Without `immutable: true`, a Secret's data can be modified in place by anyone with " +
				"update access, whether accidentally or maliciously. Mutable Secrets also increase load " +
				"on the API server, since every kubelet watching the Secret must be notified and re-sync " +
				"on every change.\n\n" +
				"## How to Fix\n\n" +
				"Set `immutable: true` once the Secret's contents are finalized:\n\n" +
				"```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\nimmutable: true\ntype: Opaque\ndata:\n  password: <base64-value>\n```\n\n" +
				"Immutable Secrets must be deleted and recreated (or replaced under a new name) to " +
				"rotate their contents, which pairs naturally with GitOps and templated Secret names.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes documentation on Immutable Secrets and ConfigMaps for the full " +
				"rationale, including the API server load reduction this feature provides at scale.",
			FieldPath:    ".immutable",
			CurrentValue: false,
			DesiredValue: true,
			FixHint: &checker.FixHint{
				Safety:      checker.FixPotentiallyBreaking,
				Description: "Sets immutable: true on the Secret.",
				Impact: "Some controllers and operators (e.g. cert-manager renewals, credential rotation " +
					"tooling) intentionally patch Secret data in place. Once immutable, the Secret must be " +
					"deleted and recreated to change its contents, which breaks any such in-place update flow.",
				Operation: checker.FixOpSet,
			},
		})
	}

	return findings, nil
}

// isSecretImmutable returns true if the Secret's .immutable field is present and true.
func isSecretImmutable(obj *unstructured.Unstructured) bool {
	v, found, err := unstructured.NestedBool(obj.Object, "immutable")
	return err == nil && found && v
}
