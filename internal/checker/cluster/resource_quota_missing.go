package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ResourceQuotaMissingChecker detects namespaces without a ResourceQuota defined.
type ResourceQuotaMissingChecker struct{}

// Name returns the kebab-case identifier for this check.
func (c *ResourceQuotaMissingChecker) Name() string { return "resource-quota-missing" }

// Description returns a human-readable summary of what this check detects.
func (c *ResourceQuotaMissingChecker) Description() string {
	return "Detects namespaces without ResourceQuota; a namespace can consume unlimited cluster resources."
}

// Categories returns the security categories this check belongs to.
func (c *ResourceQuotaMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns the scan modes (manifest, live, or both) that support this check.
func (c *ResourceQuotaMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes GVRs this check needs to operate.
func (c *ResourceQuotaMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NamespaceGVR, ResourceQuotaGVR}
}

// Run executes the check against cached resources and returns any findings.
func (c *ResourceQuotaMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("resource-quota-missing check: %w", err)
	}

	namespaces := resources.List(NamespaceGVR)
	var findings []checker.Finding

	for i := range namespaces {
		ns := &namespaces[i]
		name := ns.GetName()
		if isSystemNamespace(name) {
			continue
		}

		rqs := resources.ListNamespaced(ResourceQuotaGVR, name)
		if len(rqs) == 0 {
			findings = append(findings, checker.Finding{
				Checker:   "resource-quota-missing",
				Severity:  checker.SeverityLow,
				Resource:  name,
				Namespace: name,
				Kind:      "Namespace",
				Message:   fmt.Sprintf("Namespace %q has no ResourceQuota defined.", name),
				Remediation: "## Why This Matters\n\n" +
					"Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. " +
					"This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.\n\n" +
					"## How to Fix\n\n" +
					"Create a ResourceQuota to cap the namespace's total resource consumption:\n\n" +
					"```yaml\napiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: compute-quota\n  namespace: my-app\nspec:\n  hard:\n    requests.cpu: \"10\"\n    requests.memory: 20Gi\n    limits.cpu: \"20\"\n    limits.memory: 40Gi\n    pods: \"50\"\n    services: \"10\"\n```\n\n" +
					"Tune quota values based on the namespace's actual workload requirements and cluster capacity.\n\n" +
					"## Learn More\n\n" +
					"CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. " +
					"See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.",
			})
		}
	}

	return findings, nil
}
