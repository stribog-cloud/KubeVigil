package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// NamespaceDefaultUsageChecker detects workloads deployed in the default namespace.
type NamespaceDefaultUsageChecker struct{}

// Name returns the kebab-case identifier for this check.
func (c *NamespaceDefaultUsageChecker) Name() string { return "namespace-default-usage" }

// Description returns a human-readable summary of what this check detects.
func (c *NamespaceDefaultUsageChecker) Description() string {
	return "Detects workloads deployed in the default namespace, which lacks isolation policies."
}

// Categories returns the security categories this check belongs to.
func (c *NamespaceDefaultUsageChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns the scan modes (manifest, live, or both) that support this check.
func (c *NamespaceDefaultUsageChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes GVRs this check needs to operate.
func (c *NamespaceDefaultUsageChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the check against cached resources and returns any findings.
func (c *NamespaceDefaultUsageChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("namespace-default-usage check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		if info.Namespace == "default" {
			findings = append(findings, checker.Finding{
				Checker:   "namespace-default-usage",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: "default",
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q is deployed in the default namespace.", info.Kind, info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"The default namespace is a shared, unsecured space that lacks resource quotas, network policies, and RBAC boundaries. " +
					"Workloads deployed here are exposed to cross-tenant access and resource contention, making it trivial for a compromised pod to interact with other services.\n\n" +
					"## How to Fix\n\n" +
					"Create a dedicated namespace for your workload and apply security labels:\n\n" +
					"```yaml\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: my-app\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n---\n# Then update your workload:\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  namespace: my-app    # Move out of default\n```\n\n" +
					"Apply NetworkPolicies and ResourceQuotas to the new namespace for full isolation.\n\n" +
					"## Learn More\n\n" +
					"The CIS Kubernetes Benchmark (5.7.4) recommends against using the default namespace. " +
					"See https://kubernetes.io/docs/concepts/security/multi-tenancy/ for namespace isolation patterns.",
				FieldPath: ".metadata.namespace",
			})
		}
	}

	return findings, nil
}
