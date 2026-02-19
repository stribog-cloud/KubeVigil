package scheduling

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TolerationAllChecker detects workloads with operator: Exists tolerations that
// tolerate all taints, allowing scheduling on any node including tainted ones.
type TolerationAllChecker struct{}

// Name returns the kebab-case check ID.
func (c *TolerationAllChecker) Name() string { return "toleration-all" }

// Description returns a human-readable description.
func (c *TolerationAllChecker) Description() string {
	return "Detects workloads with operator: Exists tolerations that tolerate all taints, allowing scheduling on any node."
}

// Categories returns the check categories.
func (c *TolerationAllChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *TolerationAllChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TolerationAllChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the toleration-all check.
func (c *TolerationAllChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("toleration-all check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		for j, tol := range info.Spec.Tolerations {
			// A toleration with Exists operator and empty key matches ALL taints.
			if tol.Operator == corev1.TolerationOpExists && tol.Key == "" {
				findings = append(findings, checker.Finding{
					Checker:   "toleration-all",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Message:   fmt.Sprintf("%s %q has a catch-all toleration (operator: Exists, empty key) that matches all taints.", info.Kind, info.ResourceName),
					Remediation: "## Why This Matters\n\n" +
						"A catch-all toleration (operator: Exists with an empty key) allows the pod to schedule on any node, " +
						"including control-plane nodes, GPU nodes, and nodes tainted for isolation. This bypasses scheduling " +
						"boundaries and can place workloads on nodes where they should not run, creating security and stability risks.\n\n" +
						"## How to Fix\n\n" +
						"Replace the catch-all toleration with specific tolerations for the taints your workload actually needs:\n\n" +
						"```yaml\nspec:\n  tolerations:\n    - key: dedicated\n      operator: Equal\n      value: monitoring\n      effect: NoSchedule\n    # Remove this catch-all:\n    # - operator: Exists\n```\n\n" +
						"Catch-all tolerations are only appropriate for DaemonSets that must run on every node (e.g., log collectors, node monitors).\n\n" +
						"## Learn More\n\n" +
						"Review the Kubernetes taints and tolerations documentation for guidance on scoping tolerations. " +
						"The CIS Benchmark recommends explicit toleration keys to maintain scheduling boundaries.",
					FieldPath: fmt.Sprintf(".spec.tolerations[%d]", j),
				})
			}
		}
	}

	return findings, nil
}
