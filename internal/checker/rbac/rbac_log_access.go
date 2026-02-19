package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// logReadVerbs are verbs that grant the ability to read pod logs.
var logReadVerbs = []string{"get", "*"}

// LogAccessChecker detects Roles and ClusterRoles that grant access to pod logs,
// which may contain sensitive application data such as credentials or PII.
type LogAccessChecker struct{}

// Name returns the kebab-case check ID.
func (c *LogAccessChecker) Name() string { return "rbac-log-access" }

// Description returns a human-readable description.
func (c *LogAccessChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant access to pod logs."
}

// Categories returns the check categories.
func (c *LogAccessChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *LogAccessChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *LogAccessChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the log access check against all Roles and ClusterRoles in the cache.
func (c *LogAccessChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-log-access check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsString(rule.Resources, "pods/log") && containsAny(rule.Verbs, logReadVerbs...) {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-log-access",
					Severity:  checker.SeverityMedium,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants access to pod logs, which may contain sensitive application data.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"The `pods/log` sub-resource provides access to container stdout/stderr output. Applications " +
						"frequently log sensitive data inadvertently, including authentication tokens, database " +
						"connection strings, API keys, and personally identifiable information (PII). An attacker with " +
						"log access can harvest these credentials without needing exec access.\n\n" +
						"## How to Fix\n\n" +
						"Remove the `pods/log` sub-resource and grant log access only to dedicated monitoring roles:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]              # pods only, no sub-resources\n    verbs: [\"get\", \"list\", \"watch\"]\n  # Grant pods/log only to monitoring-specific roles\n```\n\n" +
						"Additionally, configure applications to avoid logging sensitive data. Use structured logging " +
						"libraries that support field redaction.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK technique T1530 (Data from Cloud Storage) and the Kubernetes RBAC " +
						"documentation on sub-resource access control.",
					FieldPath: fmt.Sprintf(".rules[%d].resources", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
