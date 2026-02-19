package scheduling

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TopologySpreadChecker detects workloads without topology spread constraints.
// Without these constraints, all replicas may land on the same node, negating high availability.
type TopologySpreadChecker struct{}

// Name returns the kebab-case check ID.
func (c *TopologySpreadChecker) Name() string { return "topology-spread" }

// Description returns a human-readable description.
func (c *TopologySpreadChecker) Description() string {
	return "Detects workloads without topology spread constraints; all replicas may land on the same node."
}

// Categories returns the check categories.
func (c *TopologySpreadChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *TopologySpreadChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TopologySpreadChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the topology-spread check.
func (c *TopologySpreadChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("topology-spread check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		if len(info.Spec.TopologySpreadConstraints) == 0 {
			findings = append(findings, checker.Finding{
				Checker:   "topology-spread",
				Severity:  checker.SeverityLow,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q has no topology spread constraints; all replicas may be scheduled on the same node.", info.Kind, info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"Without topology spread constraints, the scheduler may place all replicas on the same node or in the same " +
					"availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. " +
					"This negates the high-availability benefits of running multiple pods.\n\n" +
					"## How to Fix\n\n" +
					"Add topology spread constraints to distribute replicas across failure domains:\n\n" +
					"```yaml\nspec:\n  topologySpreadConstraints:\n    - maxSkew: 1\n      topologyKey: kubernetes.io/hostname\n      whenUnsatisfiable: DoNotSchedule\n      labelSelector:\n        matchLabels:\n          app: my-app\n    - maxSkew: 1\n      topologyKey: topology.kubernetes.io/zone\n      whenUnsatisfiable: ScheduleAnyway\n```\n\n" +
					"Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints " +
					"provides both node-level and zone-level fault tolerance.",
				FieldPath: ".spec.topologySpreadConstraints",
			})
		}
	}

	return findings, nil
}
