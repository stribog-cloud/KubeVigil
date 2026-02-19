package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ClusterAdminChecker detects RoleBindings or ClusterRoleBindings that grant
// the cluster-admin ClusterRole, which provides unrestricted access to all
// resources in all namespaces.
type ClusterAdminChecker struct{}

// Name returns the kebab-case check ID.
func (c *ClusterAdminChecker) Name() string { return "rbac-cluster-admin" }

// Description returns a human-readable description.
func (c *ClusterAdminChecker) Description() string {
	return "Detects RoleBindings or ClusterRoleBindings to the cluster-admin ClusterRole."
}

// Categories returns the check categories.
func (c *ClusterAdminChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *ClusterAdminChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ClusterAdminChecker) RequiredResources() []schema.GroupVersionResource {
	return BindingGVRs()
}

// Run executes the cluster-admin binding check against all bindings in the cache.
func (c *ClusterAdminChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-cluster-admin check: %w", err)
	}

	bindings := ExtractBindings(resources)
	var findings []checker.Finding

	for i := range bindings {
		b := &bindings[i]
		if b.RoleRef.Name == "cluster-admin" && b.RoleRef.Kind == "ClusterRole" {
			findings = append(findings, checker.Finding{
				Checker:   "rbac-cluster-admin",
				Severity:  checker.SeverityCritical,
				Resource:  b.Name,
				Namespace: b.Namespace,
				Kind:      b.Kind,
				Message:   fmt.Sprintf("%s %q grants cluster-admin privileges. Every cluster-admin binding should be justified and documented.", b.Kind, b.Name),
				Remediation: "## Why This Matters\n\n" +
					"The `cluster-admin` ClusterRole grants unrestricted access to every resource in every namespace, " +
					"including the ability to create and modify RBAC rules themselves. A compromised identity with " +
					"cluster-admin privileges has full control of the entire cluster, making this the highest-value " +
					"target for attackers.\n\n" +
					"## How to Fix\n\n" +
					"Replace cluster-admin bindings with purpose-built ClusterRoles scoped to actual needs:\n\n" +
					"```yaml\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: my-admin\nroleRef:\n  kind: ClusterRole\n  name: my-limited-admin-role    # Scoped permissions\n  apiGroup: rbac.authorization.k8s.io\nsubjects:\n  - kind: User\n    name: admin@example.com\n    apiGroup: rbac.authorization.k8s.io\n```\n\n" +
					"Conduct periodic access reviews to ensure cluster-admin bindings remain justified and documented.\n\n" +
					"## Learn More\n\n" +
					"See CIS Kubernetes Benchmark 5.1.1 on limiting cluster-admin usage and the NSA/CISA " +
					"Kubernetes Hardening Guide on minimizing administrative privileges.",
				FieldPath: ".roleRef",
			})
		}
	}

	return findings, nil
}
