package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TokenProjectionConfigChecker detects workloads that do not use explicitly
// configured projected ServiceAccount tokens with expiration and audience.
// Modern Kubernetes (1.22+) uses projected tokens by default, but without
// explicit configuration they lack audience restriction and use a default
// expiration, reducing the blast radius control.
type TokenProjectionConfigChecker struct{}

// Name returns the kebab-case check ID.
func (c *TokenProjectionConfigChecker) Name() string { return "token-projection-config" }

// Description returns a human-readable description.
func (c *TokenProjectionConfigChecker) Description() string {
	return "Detects workloads without explicitly configured projected ServiceAccount tokens with expiry and audience."
}

// Categories returns the check categories.
func (c *TokenProjectionConfigChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *TokenProjectionConfigChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TokenProjectionConfigChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the token-projection-config check against all workload resources in the cache.
func (c *TokenProjectionConfigChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("token-projection-config check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		// If automountServiceAccountToken is explicitly false, no token is mounted — skip.
		if info.Spec.AutomountServiceAccountToken != nil && !*info.Spec.AutomountServiceAccountToken {
			continue
		}

		// Look for a projected volume with a serviceAccountToken source that has expirationSeconds.
		if hasProjectedTokenWithExpiry(info) {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "token-projection-config",
			Severity:  checker.SeverityMedium,
			Resource:  info.ResourceName,
			Namespace: info.Namespace,
			Kind:      info.Kind,
			Message:   fmt.Sprintf("%s %q does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions.", info.Kind, info.ResourceName),
			Remediation: "## Why This Matters\n\n" +
				"Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: " +
				"no audience restriction and a long expiration. A stolen token remains valid for an extended period " +
				"and can be used against any API server endpoint, widening the blast radius of a compromise.\n\n" +
				"## How to Fix\n\n" +
				"Add a projected volume with explicit expiration and audience:\n\n" +
				"```yaml\nspec:\n  volumes:\n    - name: token\n      projected:\n        sources:\n          - serviceAccountToken:\n              expirationSeconds: 3600\n              audience: my-api\n              path: token\n  containers:\n    - name: app\n      volumeMounts:\n        - name: token\n          mountPath: /var/run/secrets/tokens\n          readOnly: true\n```\n\n" +
				"Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes documentation on projected volumes and service account token volume projection " +
				"for detailed configuration options.",
			FieldPath: ".spec.volumes",
		})
	}

	return findings, nil
}

// hasProjectedTokenWithExpiry checks whether the PodSpec contains a projected volume
// with a serviceAccountToken source that has expirationSeconds configured.
func hasProjectedTokenWithExpiry(info *workload.PodSpecInfo) bool {
	for j := range info.Spec.Volumes {
		vol := &info.Spec.Volumes[j]
		if vol.Projected == nil {
			continue
		}
		for k := range vol.Projected.Sources {
			src := &vol.Projected.Sources[k]
			if src.ServiceAccountToken != nil && src.ServiceAccountToken.ExpirationSeconds != nil {
				return true
			}
		}
	}
	return false
}
