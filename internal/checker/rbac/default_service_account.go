package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// DefaultServiceAccountChecker detects workloads using the default ServiceAccount.
// The default ServiceAccount may have unintended permissions via role bindings,
// and every workload should use a dedicated ServiceAccount with only the required permissions.
type DefaultServiceAccountChecker struct{}

// Name returns the kebab-case check ID.
func (c *DefaultServiceAccountChecker) Name() string { return "default-service-account" }

// Description returns a human-readable description.
func (c *DefaultServiceAccountChecker) Description() string {
	return "Detects workloads using the default ServiceAccount, which may have unintended permissions."
}

// Categories returns the check categories.
func (c *DefaultServiceAccountChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *DefaultServiceAccountChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *DefaultServiceAccountChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the default-service-account check against all workload resources in the cache.
func (c *DefaultServiceAccountChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("default-service-account check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		sa := info.Spec.ServiceAccountName
		if sa == "" || sa == "default" {
			findings = append(findings, checker.Finding{
				Checker:   "default-service-account",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q uses the default ServiceAccount, which may have unintended permissions.", info.Kind, info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, " +
					"the attacker inherits whatever permissions have been granted to the default account via role bindings, " +
					"enabling lateral movement across all workloads sharing it.\n\n" +
					"## How to Fix\n\n" +
					"Create a dedicated ServiceAccount for each workload and reference it in the pod spec:\n\n" +
					"```yaml\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: my-app\n  namespace: production\nautomountServiceAccountToken: false\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app\nspec:\n  template:\n    spec:\n      serviceAccountName: my-app\n```\n\n" +
					"Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 " +
					"for guidance on ensuring default service accounts are not actively used.",
				FieldPath: ".spec.serviceAccountName",
			})
		}
	}

	return findings, nil
}
