package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// DeprecatedAPIUsageChecker detects resources using deprecated API versions.
type DeprecatedAPIUsageChecker struct{}

// Name returns the kebab-case identifier for this check.
func (c *DeprecatedAPIUsageChecker) Name() string { return "deprecated-api-usage" }

// Description returns a human-readable summary of what this check detects.
func (c *DeprecatedAPIUsageChecker) Description() string {
	return "Detects resources using deprecated or removed API versions."
}

// Categories returns the security categories this check belongs to.
func (c *DeprecatedAPIUsageChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns the scan modes (manifest, live, or both) that support this check.
func (c *DeprecatedAPIUsageChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// deprecatedGVRs are the GVRs we actively scan for to detect deprecated API usage.
var deprecatedGVRs = []schema.GroupVersionResource{
	{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"},
}

// RequiredResources returns the Kubernetes GVRs this check needs to operate.
func (c *DeprecatedAPIUsageChecker) RequiredResources() []schema.GroupVersionResource {
	return deprecatedGVRs
}

// Run executes the check against cached resources and returns any findings.
func (c *DeprecatedAPIUsageChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("deprecated-api-usage check: %w", err)
	}

	var findings []checker.Finding

	// Check all resources in the cache for deprecated API versions.
	for gvr, msg := range gvrDeprecationMessages {
		objs := resources.List(gvr)
		for i := range objs {
			obj := &objs[i]
			findings = append(findings, checker.Finding{
				Checker:   "deprecated-api-usage",
				Severity:  checker.SeverityMedium,
				Resource:  obj.GetName(),
				Namespace: obj.GetNamespace(),
				Kind:      obj.GetKind(),
				Message:   fmt.Sprintf("%s %q uses deprecated API: %s", obj.GetKind(), obj.GetName(), msg),
				Remediation: "## Why This Matters\n\n" +
					"Deprecated APIs are removed in future Kubernetes versions. If your manifests still reference them, deployments will fail " +
					"during cluster upgrades, potentially causing outages. CI/CD pipelines using removed APIs will also break.\n\n" +
					"## How to Fix\n\n" +
					"Update the apiVersion field to the current stable API:\n\n" +
					"```yaml\n# Before (deprecated):\napiVersion: extensions/v1beta1\nkind: Deployment\n\n# After (current):\napiVersion: apps/v1\nkind: Deployment\n```\n\n" +
					"Run `kubectl convert` or use tools like `kubent` to scan your entire codebase for deprecated API versions before upgrading.\n\n" +
					"## Learn More\n\n" +
					"See https://kubernetes.io/docs/reference/using-api/deprecation-guide/ for a complete list of deprecated and removed APIs by Kubernetes version.",
				FieldPath: ".apiVersion",
			})
		}
	}

	return findings, nil
}

// gvrDeprecationMessages maps deprecated GVRs to their deprecation messages.
var gvrDeprecationMessages = map[schema.GroupVersionResource]string{
	{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"}: "PodSecurityPolicy is removed in Kubernetes 1.25; use Pod Security Admission.",
}
