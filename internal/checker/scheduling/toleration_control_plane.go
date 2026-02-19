package scheduling

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TolerationControlPlaneChecker detects workloads that tolerate control-plane/master
// taints without justification. Only system components should schedule on control-plane nodes.
type TolerationControlPlaneChecker struct{}

// Name returns the kebab-case check ID.
func (c *TolerationControlPlaneChecker) Name() string { return "toleration-control-plane" }

// Description returns a human-readable description.
func (c *TolerationControlPlaneChecker) Description() string {
	return "Detects workloads tolerating control-plane/master taints, which should be reserved for system components."
}

// Categories returns the check categories.
func (c *TolerationControlPlaneChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *TolerationControlPlaneChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TolerationControlPlaneChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the toleration-control-plane check.
func (c *TolerationControlPlaneChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("toleration-control-plane check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		for j, tol := range info.Spec.Tolerations {
			if controlPlaneTaintKeys[tol.Key] {
				findings = append(findings, checker.Finding{
					Checker:   "toleration-control-plane",
					Severity:  checker.SeverityHigh,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Message:   fmt.Sprintf("%s %q tolerates control-plane taint key %q; only system components should run on control-plane nodes.", info.Kind, info.ResourceName, tol.Key),
					Remediation: "## Why This Matters\n\n" +
						"Control-plane nodes run critical cluster components like the API server, etcd, and scheduler. " +
						"If a compromised workload runs on a control-plane node, an attacker can access these components directly, " +
						"potentially gaining full cluster control or corrupting cluster state.\n\n" +
						"## How to Fix\n\n" +
						"Remove the control-plane toleration from your workload spec:\n\n" +
						"```yaml\nspec:\n  tolerations:\n    # Remove these entries:\n    # - key: node-role.kubernetes.io/control-plane\n    #   effect: NoSchedule\n    # - key: node-role.kubernetes.io/master\n    #   effect: NoSchedule\n    - key: dedicated\n      operator: Equal\n      value: my-team\n      effect: NoSchedule\n```\n\n" +
						"If the workload genuinely needs to run on control-plane nodes, deploy it in the kube-system namespace with minimal privileges.\n\n" +
						"## Learn More\n\n" +
						"The CIS Kubernetes Benchmark recommends isolating control-plane nodes from tenant workloads. " +
						"See the Kubernetes documentation on taints and tolerations for scheduling best practices.",
					FieldPath: fmt.Sprintf(".spec.tolerations[%d]", j),
				})
			}
		}
	}

	return findings, nil
}
