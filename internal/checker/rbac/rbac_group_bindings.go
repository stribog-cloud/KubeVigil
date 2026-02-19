package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// broadGroups is the set of system groups that are overly broad.
// Granting RBAC permissions to these groups is dangerous because they encompass
// all authenticated users, all unauthenticated users, or anonymous access.
var broadGroups = map[string]bool{
	"system:authenticated":   true,
	"system:unauthenticated": true,
	"system:anonymous":       true,
}

// GroupBindingsChecker detects RoleBindings or ClusterRoleBindings that grant
// permissions to overly broad system groups like system:authenticated,
// system:unauthenticated, or system:anonymous.
type GroupBindingsChecker struct{}

// Name returns the kebab-case check ID.
func (c *GroupBindingsChecker) Name() string { return "rbac-group-bindings" }

// Description returns a human-readable description.
func (c *GroupBindingsChecker) Description() string {
	return "Detects bindings to overly broad groups (system:authenticated, system:unauthenticated, system:anonymous)."
}

// Categories returns the check categories.
func (c *GroupBindingsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *GroupBindingsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *GroupBindingsChecker) RequiredResources() []schema.GroupVersionResource {
	return BindingGVRs()
}

// Run executes the broad group binding check against all bindings in the cache.
func (c *GroupBindingsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-group-bindings check: %w", err)
	}

	bindings := ExtractBindings(resources)
	var findings []checker.Finding

	for i := range bindings {
		b := &bindings[i]
		for _, sub := range b.Subjects {
			if sub.Kind == "Group" && broadGroups[sub.Name] {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-group-bindings",
					Severity:  checker.SeverityHigh,
					Resource:  b.Name,
					Namespace: b.Namespace,
					Kind:      b.Kind,
					Message:   fmt.Sprintf("%s %q binds to overly broad group %q, potentially granting permissions to all users.", b.Kind, b.Name, sub.Name),
					Remediation: "## Why This Matters\n\n" +
						"Groups like `system:authenticated` include every authenticated identity in the cluster, " +
						"including all service accounts across all namespaces. Binding permissions to these groups " +
						"effectively grants those permissions to every pod, user, and controller in the cluster. " +
						"`system:unauthenticated` and `system:anonymous` are even more dangerous as they grant access " +
						"without any authentication.\n\n" +
						"## How to Fix\n\n" +
						"Replace broad group bindings with specific subjects:\n\n" +
						"```yaml\nsubjects:\n  - kind: Group\n    name: dev-team                    # Specific group\n    apiGroup: rbac.authorization.k8s.io\n  - kind: ServiceAccount\n    name: my-app\n    namespace: production             # Specific service account\n```\n\n" +
						"Never bind roles to `system:authenticated`, `system:unauthenticated`, or `system:anonymous` " +
						"unless you explicitly intend to grant permissions cluster-wide.\n\n" +
						"## Learn More\n\n" +
						"See CIS Kubernetes Benchmark 5.1.5 and the NSA/CISA Kubernetes Hardening Guide on " +
						"restricting broad group-based access.",
					FieldPath: ".subjects",
				})
				break // one finding per binding is enough
			}
		}
	}

	return findings, nil
}
