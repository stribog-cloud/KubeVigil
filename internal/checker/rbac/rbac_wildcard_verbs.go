package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// WildcardVerbsChecker detects Roles and ClusterRoles that grant wildcard (*) verbs,
// which allows all actions on the specified resources and violates the principle of least privilege.
type WildcardVerbsChecker struct{}

// Name returns the kebab-case check ID.
func (c *WildcardVerbsChecker) Name() string { return "rbac-wildcard-verbs" }

// Description returns a human-readable description.
func (c *WildcardVerbsChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant wildcard (*) verbs, violating least-privilege."
}

// Categories returns the check categories.
func (c *WildcardVerbsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *WildcardVerbsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *WildcardVerbsChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the wildcard verbs check against all Roles and ClusterRoles in the cache.
func (c *WildcardVerbsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-wildcard-verbs check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsString(rule.Verbs, "*") {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-wildcard-verbs",
					Severity:  checker.SeverityCritical,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants wildcard (*) verbs, violating least-privilege principle.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"A wildcard verb (`*`) grants every possible action on the specified resources, including delete, " +
						"patch, and create. An attacker who assumes this role can modify or destroy resources, " +
						"exfiltrate data, or escalate privileges far beyond what the workload actually requires.\n\n" +
						"## How to Fix\n\n" +
						"Replace the wildcard with the specific verbs your application needs:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\", \"list\", \"watch\"]  # Only read access\n  - apiGroups: [\"apps\"]\n    resources: [\"deployments\"]\n    verbs: [\"get\", \"update\"]          # Read + update only\n```\n\n" +
						"Enable Kubernetes audit logging and review the audit trail to identify which verbs are actually used " +
						"before tightening permissions.\n\n" +
						"## Learn More\n\n" +
						"Refer to CIS Kubernetes Benchmark 5.1.3 and the Kubernetes RBAC documentation for " +
						"guidance on applying the principle of least privilege to role definitions.",
					FieldPath: fmt.Sprintf(".rules[%d].verbs", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
