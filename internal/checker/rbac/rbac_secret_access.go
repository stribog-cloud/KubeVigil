package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// secretReadVerbs are verbs that allow reading secret data.
var secretReadVerbs = []string{"get", "list", "watch", "*"}

// SecretAccessChecker detects Roles and ClusterRoles that grant read access to Secrets,
// which may contain credentials, TLS keys, and other sensitive data.
type SecretAccessChecker struct{}

// Name returns the kebab-case check ID.
func (c *SecretAccessChecker) Name() string { return "rbac-secret-access" }

// Description returns a human-readable description.
func (c *SecretAccessChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant read access to Secrets."
}

// Categories returns the check categories.
func (c *SecretAccessChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *SecretAccessChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *SecretAccessChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the secret access check against all Roles and ClusterRoles in the cache.
func (c *SecretAccessChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-secret-access check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsString(rule.Resources, "secrets") && containsAny(rule.Verbs, secretReadVerbs...) {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-secret-access",
					Severity:  checker.SeverityHigh,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants read access to Secrets, which may contain credentials and TLS keys.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"Roles granting read access to Secrets expose every credential in the namespace, including " +
						"database passwords, TLS private keys, API tokens, and third-party credentials. A compromised " +
						"workload with this access can exfiltrate all secrets and pivot to external systems.\n\n" +
						"## How to Fix\n\n" +
						"Restrict access to only the specific secrets your workload needs using `resourceNames`:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    resourceNames: [\"my-app-tls\", \"my-app-db-creds\"]\n    verbs: [\"get\"]\n```\n\n" +
						"For sensitive credentials, consider using an external secrets manager (HashiCorp Vault, " +
						"AWS Secrets Manager, or GCP Secret Manager) with the External Secrets Operator.\n\n" +
						"## Learn More\n\n" +
						"See CIS Kubernetes Benchmark 5.1.2 on minimizing access to secrets and MITRE ATT&CK " +
						"technique T1552 (Unsecured Credentials) for the threat model.",
					FieldPath: fmt.Sprintf(".rules[%d].resources", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
