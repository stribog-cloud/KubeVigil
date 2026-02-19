package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// execResources are sub-resources that grant interactive access to pods.
var execResources = []string{"pods/exec", "pods/attach"}

// execVerbs are verbs that grant the ability to exec/attach.
var execVerbs = []string{"create", "*"}

// ExecAccessChecker detects Roles and ClusterRoles that grant exec or attach access to pods,
// which is equivalent to SSH access and allows full control of running containers.
type ExecAccessChecker struct{}

// Name returns the kebab-case check ID.
func (c *ExecAccessChecker) Name() string { return "rbac-exec-access" }

// Description returns a human-readable description.
func (c *ExecAccessChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant exec/attach access to pods."
}

// Categories returns the check categories.
func (c *ExecAccessChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *ExecAccessChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ExecAccessChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the exec access check against all Roles and ClusterRoles in the cache.
func (c *ExecAccessChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-exec-access check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsAny(rule.Resources, execResources...) && containsAny(rule.Verbs, execVerbs...) {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-exec-access",
					Severity:  checker.SeverityHigh,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants exec/attach access to pods, equivalent to SSH access.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"The `pods/exec` and `pods/attach` sub-resources grant the ability to run arbitrary commands " +
						"inside running containers, which is functionally equivalent to SSH access. An attacker with " +
						"exec access can read environment variables, access mounted secrets, install tools, and pivot " +
						"to other systems on the network.\n\n" +
						"## How to Fix\n\n" +
						"Remove exec and attach sub-resources from the role rules:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]              # pods only, no sub-resources\n    verbs: [\"get\", \"list\", \"watch\"]\n  # Do NOT include:\n  # resources: [\"pods/exec\", \"pods/attach\"]\n```\n\n" +
						"If exec access is required for debugging, restrict it to specific namespaces and enable " +
						"Kubernetes audit logging to monitor all exec sessions in production.\n\n" +
						"## Learn More\n\n" +
						"See CIS Kubernetes Benchmark 5.1.3 and MITRE ATT&CK technique T1609 (Container Administration Command) " +
						"for the exec-based attack vector.",
					FieldPath: fmt.Sprintf(".rules[%d].resources", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
