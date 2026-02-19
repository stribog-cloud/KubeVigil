package scheduling

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// PriorityClassSystemChecker detects non-system workloads using system-cluster-critical
// or system-node-critical PriorityClasses, which can preempt legitimate system pods.
type PriorityClassSystemChecker struct{}

// Name returns the kebab-case check ID.
func (c *PriorityClassSystemChecker) Name() string { return "priority-class-system" }

// Description returns a human-readable description.
func (c *PriorityClassSystemChecker) Description() string {
	return "Detects non-system workloads using system-cluster-critical or system-node-critical PriorityClasses."
}

// Categories returns the check categories.
func (c *PriorityClassSystemChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *PriorityClassSystemChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PriorityClassSystemChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// systemNamespaces that are allowed to use system priority classes.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

// Run executes the priority-class-system check.
func (c *PriorityClassSystemChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("priority-class-system check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		pcName := info.Spec.PriorityClassName

		if !systemPriorityClasses[pcName] {
			continue
		}

		// System namespaces are allowed to use system priority classes.
		if systemNamespaces[info.Namespace] {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "priority-class-system",
			Severity:  checker.SeverityHigh,
			Resource:  info.ResourceName,
			Namespace: info.Namespace,
			Kind:      info.Kind,
			Message:   fmt.Sprintf("%s %q uses system PriorityClass %q which can preempt legitimate system pods.", info.Kind, info.ResourceName, pcName),
			Remediation: "## Why This Matters\n\n" +
				"The system-cluster-critical and system-node-critical PriorityClasses are reserved for essential cluster " +
				"infrastructure like CoreDNS, kube-proxy, and CNI plugins. When application workloads use these classes, " +
				"they can preempt real system components, causing DNS failures, networking outages, or even cluster instability.\n\n" +
				"## How to Fix\n\n" +
				"Create and use a custom PriorityClass with a value below system-critical thresholds:\n\n" +
				"```yaml\napiVersion: scheduling.k8s.io/v1\nkind: PriorityClass\nmetadata:\n  name: app-high-priority\nvalue: 1000000\npreemptionPolicy: PreemptLowerPriority\nglobalDefault: false\n---\n# Then reference it in your workload:\nspec:\n  priorityClassName: app-high-priority\n```\n\n" +
				"System priority values start at 2000000000. Keep application priorities well below this threshold.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes Pod Priority and Preemption documentation for guidance on defining PriorityClasses. " +
				"The CIS Benchmark recommends restricting system priority classes to kube-system namespace only.",
			FieldPath: ".spec.priorityClassName",
		})
	}

	return findings, nil
}
