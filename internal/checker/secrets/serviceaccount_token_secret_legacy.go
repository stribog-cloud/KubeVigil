package secrets

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// serviceAccountTokenSecretType is the legacy long-lived Secret type
// Kubernetes historically auto-created for every ServiceAccount. Since
// Kubernetes 1.24, these are no longer auto-created; any Secret with this
// type is presumed to be a manually created legacy token.
const serviceAccountTokenSecretType = "kubernetes.io/service-account-token" //nolint:gosec // Not a credential; a Kubernetes Secret type constant.

// ServiceAccountTokenSecretLegacyChecker detects Secret resources of type
// kubernetes.io/service-account-token still present in the cluster. Since
// Kubernetes 1.24, these Secrets are no longer auto-created per
// ServiceAccount; their presence indicates a legacy long-lived, non-expiring
// token pattern that should be migrated to the bound, auto-rotating
// projected-volume token.
type ServiceAccountTokenSecretLegacyChecker struct{}

// Name returns the kebab-case check ID.
func (c *ServiceAccountTokenSecretLegacyChecker) Name() string {
	return "serviceaccount-token-secret-legacy"
}

// Description returns a human-readable description.
func (c *ServiceAccountTokenSecretLegacyChecker) Description() string {
	return "Detects Secret resources of type kubernetes.io/service-account-token, a legacy long-lived token pattern superseded by bound projected-volume tokens."
}

// Categories returns the check categories.
func (c *ServiceAccountTokenSecretLegacyChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
func (c *ServiceAccountTokenSecretLegacyChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ServiceAccountTokenSecretLegacyChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{SecretGVR}
}

// Run executes the serviceaccount-token-secret-legacy check against all Secrets in the cache.
func (c *ServiceAccountTokenSecretLegacyChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("serviceaccount-token-secret-legacy check: %w", err)
	}

	secrets := cache.List(SecretGVR)
	var findings []checker.Finding

	for i := range secrets {
		obj := &secrets[i]

		secretType, _, _ := unstructuredString(obj.Object, "type")
		if secretType != serviceAccountTokenSecretType {
			continue
		}

		name := obj.GetName()

		findings = append(findings, checker.Finding{
			Checker:   "serviceaccount-token-secret-legacy",
			Severity:  checker.SeverityMedium,
			Resource:  name,
			Namespace: obj.GetNamespace(),
			Kind:      obj.GetKind(),
			Message: fmt.Sprintf(
				"Secret %q is of legacy type %q, a long-lived, non-expiring ServiceAccount token.",
				name, serviceAccountTokenSecretType,
			),
			Remediation: "## Why This Matters\n\n" +
				"Since Kubernetes 1.24, ServiceAccount token Secrets are no longer auto-created. A Secret " +
				"of this type still present in the cluster is a legacy, manually created, non-expiring " +
				"token — unlike the bound, audience-scoped, auto-rotating tokens issued via the " +
				"TokenRequest API and projected volumes. A leaked legacy token remains valid indefinitely " +
				"until manually revoked.\n\n" +
				"## How to Fix\n\n" +
				"Migrate workloads to the default projected volume token, which is bound to the pod's " +
				"lifetime and audience-scoped:\n\n" +
				"```yaml\nspec:\n  serviceAccountName: my-app\n  automountServiceAccountToken: true  # default projected volume token\n```\n\n" +
				"Once no workload depends on the legacy Secret, delete it. Verify no controller reads it " +
				"directly before removal — deleting a token still in use will break authentication for " +
				"anything relying on it.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes documentation on ServiceAccount token Secrets and the TokenRequest " +
				"API for migrating to bound, auto-rotating tokens.",
			FieldPath: ".type",
		})
	}

	return findings, nil
}
