package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// escalationVerbs are RBAC verbs that allow privilege escalation by bypassing normal RBAC restrictions.
var escalationVerbs = []string{"bind", "escalate", "impersonate"}

// EscalationVerbsChecker detects Roles and ClusterRoles that grant escalation-capable verbs
// (bind, escalate, impersonate), which can be used to bypass RBAC restrictions.
type EscalationVerbsChecker struct{}

// Name returns the kebab-case check ID.
func (c *EscalationVerbsChecker) Name() string { return "rbac-escalation-verbs" }

// Description returns a human-readable description.
func (c *EscalationVerbsChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant escalation verbs (bind, escalate, impersonate)."
}

// Categories returns the check categories.
func (c *EscalationVerbsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *EscalationVerbsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EscalationVerbsChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the escalation verbs check against all Roles and ClusterRoles in the cache.
func (c *EscalationVerbsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-escalation-verbs check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			for _, verb := range escalationVerbs {
				if containsString(rule.Verbs, verb) {
					findings = append(findings, checker.Finding{
						Checker:   "rbac-escalation-verbs",
						Severity:  checker.SeverityCritical,
						Resource:  role.Name,
						Namespace: role.Namespace,
						Kind:      role.Kind,
						Message:   fmt.Sprintf("%s %q grants escalation verb %q, allowing RBAC privilege escalation.", role.Kind, role.Name, verb),
						Remediation: "## Why This Matters\n\n" +
							"The `bind`, `escalate`, and `impersonate` verbs are special RBAC verbs that allow bypassing " +
							"normal privilege restrictions. `bind` lets a user assign roles they do not hold, `escalate` " +
							"lets a user grant permissions beyond their own, and `impersonate` lets a user act as another identity. " +
							"Any of these can lead to full cluster compromise.\n\n" +
							"## How to Fix\n\n" +
							"Remove escalation verbs and replace with specific non-escalating verbs:\n\n" +
							"```yaml\nrules:\n  - apiGroups: [\"rbac.authorization.k8s.io\"]\n    resources: [\"roles\", \"rolebindings\"]\n    verbs: [\"get\", \"list\", \"watch\"]  # Read-only, no bind/escalate\n```\n\n" +
							"Only cluster administrators and RBAC management controllers (e.g., the Kubernetes controller manager) " +
							"should hold these verbs.\n\n" +
							"## Learn More\n\n" +
							"See CIS Kubernetes Benchmark 5.1.8 on privilege escalation prevention and the Kubernetes " +
							"RBAC documentation section on escalation prevention restrictions.",
						FieldPath: fmt.Sprintf(".rules[%d].verbs", ruleIdx),
					})
					break // one finding per role, stop checking verbs for this rule
				}
			}
			if len(findings) > 0 && findings[len(findings)-1].Resource == role.Name {
				break // already found a finding for this role, stop checking rules
			}
		}
	}

	return findings, nil
}
