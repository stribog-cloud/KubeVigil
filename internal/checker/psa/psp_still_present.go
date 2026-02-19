package psa

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// PSPStillPresentChecker detects deprecated PodSecurityPolicy (PSP) resources
// that are still present in the cluster. PSP was deprecated in Kubernetes 1.21
// and removed in 1.25. Lingering PSPs indicate an incomplete migration to Pod
// Security Admission (PSA) or Pod Security Standards (PSS).
type PSPStillPresentChecker struct{}

// Name returns the kebab-case check ID.
func (c *PSPStillPresentChecker) Name() string { return "psp-still-present" }

// Description returns a human-readable description.
func (c *PSPStillPresentChecker) Description() string {
	return "Detects deprecated PodSecurityPolicy resources still present in the cluster, indicating incomplete PSA migration."
}

// Categories returns the check categories.
func (c *PSPStillPresentChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryPSS}
}

// SupportedModes returns which scan modes this check supports.
func (c *PSPStillPresentChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PSPStillPresentChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{PodSecurityPolicyGVR}
}

// Run executes the PSP still present check against all PodSecurityPolicy resources in the cache.
func (c *PSPStillPresentChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("psp-still-present check: %w", err)
	}

	psps := resources.List(PodSecurityPolicyGVR)
	var findings []checker.Finding

	for i := range psps {
		psp := &psps[i]
		name := psp.GetName()

		findings = append(findings, checker.Finding{
			Checker:   "psp-still-present",
			Severity:  checker.SeverityInfo,
			Resource:  name,
			Namespace: "",
			Kind:      "PodSecurityPolicy",
			Message:   fmt.Sprintf("PodSecurityPolicy %q is still present; PSP was removed in Kubernetes 1.25.", name),
			Remediation: "## Why This Matters\n\n" +
				"PodSecurityPolicy was deprecated in Kubernetes 1.21 and fully removed in 1.25. " +
				"Lingering PSP resources indicate an incomplete migration to Pod Security Admission (PSA). On clusters running 1.25+, PSPs have no effect and provide zero security protection.\n\n" +
				"## How to Fix\n\n" +
				"Migrate to Pod Security Admission by applying PSA labels to each namespace, then delete the PSP resources:\n\n" +
				"```yaml\napiVersion: v1\nkind: Namespace\nmetadata:\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n    pod-security.kubernetes.io/audit: restricted\n    pod-security.kubernetes.io/warn: restricted\n```\n\n" +
				"After verifying PSA enforcement is active on all namespaces, remove PSP resources with `kubectl delete psp <name>`.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes PodSecurityPolicy deprecation notice and the PSA migration guide. " +
				"Plan your migration path from PSP to PSA before upgrading to Kubernetes 1.25+.",
			FieldPath: "",
		})
	}

	return findings, nil
}
