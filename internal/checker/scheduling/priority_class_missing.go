package scheduling

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// PriorityClassMissingChecker detects workloads without a PriorityClass set.
// Without priority, pods are evicted first during resource pressure.
type PriorityClassMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *PriorityClassMissingChecker) Name() string { return "priority-class-missing" }

// Description returns a human-readable description.
func (c *PriorityClassMissingChecker) Description() string {
	return "Detects workloads without a PriorityClass, which are evicted first during resource pressure."
}

// Categories returns the check categories.
func (c *PriorityClassMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *PriorityClassMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PriorityClassMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the priority-class-missing check.
func (c *PriorityClassMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("priority-class-missing check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		if info.Spec.PriorityClassName == "" {
			findings = append(findings, checker.Finding{
				Checker:   "priority-class-missing",
				Severity:  checker.SeverityLow,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q has no PriorityClass set; it will be evicted first during resource pressure.", info.Kind, info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted " +
					"during resource pressure or node maintenance. This means important application workloads may be killed " +
					"before less critical ones, leading to unpredictable outages.\n\n" +
					"## How to Fix\n\n" +
					"Define PriorityClasses for your workloads and assign them appropriately:\n\n" +
					"```yaml\napiVersion: scheduling.k8s.io/v1\nkind: PriorityClass\nmetadata:\n  name: app-medium\nvalue: 100000\n---\n# Reference in your workload:\nspec:\n  priorityClassName: app-medium\n```\n\n" +
					"Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.\n\n" +
					"## Learn More\n\n" +
					"Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme " +
					"across namespaces ensures predictable eviction behavior during resource contention.",
				FieldPath: ".spec.priorityClassName",
			})
		}
	}

	return findings, nil
}
