package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// tokenRequestVerbs are verbs that allow minting a ServiceAccount token via the TokenRequest API.
var tokenRequestVerbs = []string{"create", "*"}

// TokenRequestChecker detects Roles and ClusterRoles that grant unrestricted create access to
// serviceaccounts/token, letting a subject mint a fresh, valid token for any ServiceAccount via
// the TokenRequest API — a direct impersonation/escalation path distinct from automount-token.
type TokenRequestChecker struct{}

// Name returns the kebab-case check ID.
func (c *TokenRequestChecker) Name() string { return "rbac-token-request" }

// Description returns a human-readable description.
func (c *TokenRequestChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant unrestricted create access to serviceaccounts/token, allowing impersonation via the TokenRequest API."
}

// Categories returns the check categories.
func (c *TokenRequestChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *TokenRequestChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TokenRequestChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the token request check against all Roles and ClusterRoles in the cache.
func (c *TokenRequestChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-token-request check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsString(rule.Resources, "serviceaccounts/token") &&
				containsAny(rule.Verbs, tokenRequestVerbs...) &&
				len(rule.ResourceNames) == 0 {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-token-request",
					Severity:  checker.SeverityCritical,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants unrestricted create access to serviceaccounts/token, allowing minting of tokens for any ServiceAccount.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"The TokenRequest API (`serviceaccounts/token`) mints a fresh, valid, bound token for a named " +
						"ServiceAccount on demand. A subject with unrestricted `create` access to this subresource can " +
						"impersonate any ServiceAccount in the namespace — including highly privileged ones — without " +
						"ever needing direct access to that ServiceAccount's Secret or RBAC bindings.\n\n" +
						"## How to Fix\n\n" +
						"Restrict TokenRequest access to specific, named ServiceAccounts the subject already owns:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"serviceaccounts/token\"]\n    resourceNames: [\"my-app-sa\"]     # Pin to one owned ServiceAccount\n    verbs: [\"create\"]\n```\n\n" +
						"Avoid granting this permission cluster-wide or namespace-wide; treat it with the same care as " +
						"granting direct access to Secrets.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK technique T1078 (Valid Accounts) and the NSA/CISA Kubernetes Hardening Guide " +
						"section 3.1 on restrictive RBAC policies.",
					FieldPath: fmt.Sprintf(".rules[%d].resources", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
