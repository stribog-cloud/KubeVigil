package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// WildcardAPIGroupsChecker detects Roles and ClusterRoles that grant access to wildcard (*)
// API groups, which allows operations across all API groups and violates least privilege.
// Note: an empty string ("") in apiGroups means the core API group — that is NOT a wildcard.
type WildcardAPIGroupsChecker struct{}

// Name returns the kebab-case check ID.
func (c *WildcardAPIGroupsChecker) Name() string { return "rbac-wildcard-apigroups" }

// Description returns a human-readable description.
func (c *WildcardAPIGroupsChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant access to wildcard (*) API groups."
}

// Categories returns the check categories.
func (c *WildcardAPIGroupsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *WildcardAPIGroupsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *WildcardAPIGroupsChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the wildcard API groups check against all Roles and ClusterRoles in the cache.
func (c *WildcardAPIGroupsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-wildcard-apigroups check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsString(rule.APIGroups, "*") {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-wildcard-apigroups",
					Severity:  checker.SeverityCritical,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants access to wildcard (*) API groups, allowing operations across all API groups.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"A wildcard API group (`*`) grants access across every API group in the cluster, " +
						"including custom resource definitions and any API groups added in the future. " +
						"This means an attacker inheriting this role can operate on resources the original author never anticipated.\n\n" +
						"## How to Fix\n\n" +
						"Replace the wildcard with the specific API groups your workload requires:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]            # Core API (pods, services, secrets)\n    resources: [\"pods\"]\n    verbs: [\"get\", \"list\"]\n  - apiGroups: [\"apps\"]         # Apps API (deployments, statefulsets)\n    resources: [\"deployments\"]\n    verbs: [\"get\", \"list\"]\n```\n\n" +
						"Common API groups: `\"\"` (core), `\"apps\"`, `\"batch\"`, `\"networking.k8s.io\"`, `\"rbac.authorization.k8s.io\"`.\n\n" +
						"## Learn More\n\n" +
						"See CIS Kubernetes Benchmark 5.1.3 and the Kubernetes API groups documentation for a " +
						"complete list of built-in API groups and their resources.",
					FieldPath: fmt.Sprintf(".rules[%d].apiGroups", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
