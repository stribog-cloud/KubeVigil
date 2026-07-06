package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// nodeProxyResources are resource strings that grant access to the kubelet's proxy subresource.
// "nodes/*" is included because a wildcard subresource entry implicitly matches nodes/proxy too.
var nodeProxyResources = []string{"nodes/proxy", "nodes/*"}

// nodeProxyVerbs are verbs that allow reaching the kubelet API through the nodes/proxy subresource.
var nodeProxyVerbs = []string{"get", "create", "*"}

// NodeProxyAccessChecker detects Roles and ClusterRoles that grant get/create access to the
// nodes/proxy subresource, which lets a subject reach the kubelet API directly.
type NodeProxyAccessChecker struct{}

// Name returns the kebab-case check ID.
func (c *NodeProxyAccessChecker) Name() string { return "rbac-node-proxy-access" }

// Description returns a human-readable description.
func (c *NodeProxyAccessChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant get/create access to the nodes/proxy subresource, exposing the kubelet API."
}

// Categories returns the check categories.
func (c *NodeProxyAccessChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *NodeProxyAccessChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *NodeProxyAccessChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the node-proxy access check against all Roles and ClusterRoles in the cache.
func (c *NodeProxyAccessChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-node-proxy-access check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsAny(rule.Resources, nodeProxyResources...) && containsAny(rule.Verbs, nodeProxyVerbs...) {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-node-proxy-access",
					Severity:  checker.SeverityCritical,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants access to the nodes/proxy subresource, exposing the kubelet API directly.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"The `nodes/proxy` subresource lets a subject send requests directly to a node's kubelet API. " +
						"The kubelet API can execute arbitrary commands in any pod on that node, retrieve logs and metrics, " +
						"and read container filesystem contents — effectively giving remote code execution across every " +
						"workload scheduled on the node, not just the caller's own pods.\n\n" +
						"## How to Fix\n\n" +
						"Remove the `nodes/proxy` subresource from the role rules:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"nodes\"]              # nodes only, no proxy subresource\n    verbs: [\"get\", \"list\"]\n  # Do NOT include:\n  # resources: [\"nodes/proxy\"]\n```\n\n" +
						"If node diagnostics are required, use the Kubernetes metrics API or a dedicated monitoring " +
						"ServiceAccount with tightly scoped, audited access instead of granting nodes/proxy broadly.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK technique T1611 (Escape to Host) and the NSA/CISA Kubernetes Hardening Guide " +
						"section 3.1 on restrictive RBAC policies.",
					FieldPath: fmt.Sprintf(".rules[%d].resources", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
