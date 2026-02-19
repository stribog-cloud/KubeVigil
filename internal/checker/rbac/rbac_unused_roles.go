package rbac

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// UnusedRolesChecker detects Roles and ClusterRoles that have no matching
// RoleBinding or ClusterRoleBinding, indicating they may be stale or unnecessary.
type UnusedRolesChecker struct{}

// Name returns the kebab-case check ID.
func (c *UnusedRolesChecker) Name() string { return "rbac-unused-roles" }

// Description returns a human-readable description.
func (c *UnusedRolesChecker) Description() string {
	return "Detects Roles and ClusterRoles that have no bindings and may be unused."
}

// Categories returns the check categories.
func (c *UnusedRolesChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *UnusedRolesChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
// Needs both roles AND bindings to cross-reference.
func (c *UnusedRolesChecker) RequiredResources() []schema.GroupVersionResource {
	return AllGVRs()
}

// Run executes the unused roles check by comparing all roles against all bindings.
func (c *UnusedRolesChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-unused-roles check: %w", err)
	}

	roles := ExtractRoles(resources)
	bindings := ExtractBindings(resources)

	// Build set of referenced role keys.
	referenced := make(map[string]bool)
	for i := range bindings {
		b := &bindings[i]
		switch b.RoleRef.Kind {
		case "Role":
			// Namespaced: key includes namespace.
			key := b.Namespace + "/" + b.RoleRef.Name
			referenced[key] = true
		case "ClusterRole":
			// Cluster-scoped.
			key := "/" + b.RoleRef.Name
			referenced[key] = true
		}
	}

	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]

		// Skip system roles — these are built-in and always exist.
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		var key string
		if role.Kind == "Role" {
			key = role.Namespace + "/" + role.Name
		} else {
			key = "/" + role.Name
		}

		if !referenced[key] {
			findings = append(findings, checker.Finding{
				Checker:   "rbac-unused-roles",
				Severity:  checker.SeverityInfo,
				Resource:  role.Name,
				Namespace: role.Namespace,
				Kind:      role.Kind,
				Message:   fmt.Sprintf("%s %q has no bindings and may be unused.", role.Kind, role.Name),
				Remediation: "## Why This Matters\n\n" +
					"Unused Roles and ClusterRoles are dormant permissions waiting to be activated. An attacker " +
					"who can create or modify RoleBindings could bind these unused roles to gain additional privileges. " +
					"They also create confusion during audits and make it harder to understand the actual RBAC posture.\n\n" +
					"## How to Fix\n\n" +
					"Verify the role is truly unused, then remove it:\n\n" +
					"```bash\n# Check for any bindings referencing this role\nkubectl get rolebindings,clusterrolebindings -A \\\n  -o json | jq '.items[] | select(.roleRef.name==\"unused-role\")'\n\n# Remove the unused role\nkubectl delete clusterrole unused-role\nkubectl delete role unused-role -n my-namespace\n```\n\n" +
					"Implement a regular RBAC hygiene process to review and clean up unused roles quarterly.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes RBAC best practices documentation and CIS Kubernetes Benchmark section 5.1 " +
					"for guidance on maintaining a clean RBAC configuration.",
			})
		}
	}

	return findings, nil
}
