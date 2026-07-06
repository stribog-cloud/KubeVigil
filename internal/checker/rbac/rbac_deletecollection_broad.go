package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// deleteCollectionBroadResources are resources considered high-blast-radius for deletecollection.
var deleteCollectionBroadResources = []string{"pods", "secrets", "persistentvolumeclaims", "namespaces"}

// DeleteCollectionBroadChecker detects Roles and ClusterRoles that grant the deletecollection
// verb on broad resources (pods, secrets, *, or no resourceNames restriction), allowing a single
// API call to mass-delete every matching object in a namespace or cluster.
type DeleteCollectionBroadChecker struct{}

// Name returns the kebab-case check ID.
func (c *DeleteCollectionBroadChecker) Name() string { return "rbac-deletecollection-broad" }

// Description returns a human-readable description.
func (c *DeleteCollectionBroadChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant unrestricted deletecollection on broad or wildcard resources."
}

// Categories returns the check categories.
func (c *DeleteCollectionBroadChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *DeleteCollectionBroadChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *DeleteCollectionBroadChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the deletecollection breadth check against all Roles and ClusterRoles in the cache.
func (c *DeleteCollectionBroadChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-deletecollection-broad check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			broad := containsString(rule.Resources, "*") || containsAny(rule.Resources, deleteCollectionBroadResources...)
			if broad && containsString(rule.Verbs, "deletecollection") && len(rule.ResourceNames) == 0 {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-deletecollection-broad",
					Severity:  checker.SeverityHigh,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants unrestricted deletecollection on broad resources, allowing mass deletion in a single API call.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"The `deletecollection` verb deletes every object matching a list call in a single request. " +
						"Granted on broad resources like `pods`, `secrets`, or `*` with no `resourceNames` restriction, " +
						"a single API call can destroy every matching object in a namespace or cluster — a " +
						"denial-of-service and data-destruction primitive far beyond what most workloads need.\n\n" +
						"## How to Fix\n\n" +
						"Remove `deletecollection` or restrict it to single-object `delete` plus a narrow " +
						"`resourceNames` list:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\", \"list\", \"delete\"]  # Single-object delete only\n  # Do NOT include:\n  # verbs: [\"deletecollection\"]\n```\n\n" +
						"If bulk cleanup is genuinely required, scope it to a narrow set of `resourceNames` or a " +
						"dedicated, audited maintenance ServiceAccount.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK technique T1485 (Data Destruction) and the NSA/CISA Kubernetes Hardening " +
						"Guide section 3.1 on restrictive RBAC policies.",
					FieldPath: fmt.Sprintf(".rules[%d].verbs", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
