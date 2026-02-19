package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// WildcardResourcesChecker detects Roles and ClusterRoles that grant access to wildcard (*)
// resources, which allows operations on all resource types and violates least privilege.
type WildcardResourcesChecker struct{}

// Name returns the kebab-case check ID.
func (c *WildcardResourcesChecker) Name() string { return "rbac-wildcard-resources" }

// Description returns a human-readable description.
func (c *WildcardResourcesChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant access to wildcard (*) resources."
}

// Categories returns the check categories.
func (c *WildcardResourcesChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *WildcardResourcesChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *WildcardResourcesChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the wildcard resources check against all Roles and ClusterRoles in the cache.
func (c *WildcardResourcesChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-wildcard-resources check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsString(rule.Resources, "*") {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-wildcard-resources",
					Severity:  checker.SeverityCritical,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants access to wildcard (*) resources, allowing operations on all resource types.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"A wildcard resource (`*`) grants access to every resource type in the specified API group, " +
						"including Secrets, ConfigMaps, and any future resource types added to the cluster. " +
						"This far exceeds what any single workload needs and creates a significant blast radius if compromised.\n\n" +
						"## How to Fix\n\n" +
						"Enumerate the specific resources your application accesses and restrict the rule:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\", \"services\", \"configmaps\"]\n    verbs: [\"get\", \"list\", \"watch\"]\n```\n\n" +
						"Use `kubectl auth can-i --list --as=system:serviceaccount:ns:sa` to audit the effective permissions " +
						"of each service account before and after changes.\n\n" +
						"## Learn More\n\n" +
						"See CIS Kubernetes Benchmark 5.1.3 on least-privilege RBAC and the Kubernetes RBAC " +
						"documentation on role aggregation for managing permissions at scale.",
					FieldPath: fmt.Sprintf(".rules[%d].resources", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
