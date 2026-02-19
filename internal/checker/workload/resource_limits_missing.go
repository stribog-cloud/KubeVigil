package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ResourceLimitsMissingChecker detects containers missing CPU or memory limits.
// Without resource limits, a container can consume unbounded node resources,
// leading to denial-of-service conditions for other workloads.
type ResourceLimitsMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *ResourceLimitsMissingChecker) Name() string { return "resource-limits-missing" }

// Description returns a human-readable description.
func (c *ResourceLimitsMissingChecker) Description() string {
	return "Detects containers missing CPU or memory limits, which can lead to unbounded resource consumption."
}

// Categories returns the check categories.
func (c *ResourceLimitsMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *ResourceLimitsMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ResourceLimitsMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the resource-limits-missing check against all workload resources in the cache.
func (c *ResourceLimitsMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("resource-limits-missing check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			missingCPU := !hasResourceLimit(&container, corev1.ResourceCPU)
			missingMemory := !hasResourceLimit(&container, corev1.ResourceMemory)

			if !missingCPU && !missingMemory {
				return
			}

			var msg string
			switch {
			case missingCPU && missingMemory:
				msg = fmt.Sprintf("Container %q is missing both CPU and memory limits.", container.Name)
			case missingCPU:
				msg = fmt.Sprintf("Container %q is missing CPU limits.", container.Name)
			default:
				msg = fmt.Sprintf("Container %q is missing memory limits.", container.Name)
			}

			fieldPath := containerFieldPath(ct, idx, "resources.limits")

			findings = append(findings, checker.Finding{
				Checker:   "resource-limits-missing",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   msg,
				Remediation: "## Why This Matters\n\n" +
					"Without resource limits, a single container can consume all available CPU and memory on a node, " +
					"starving other workloads and triggering cascading failures. An attacker who compromises an unlimited " +
					"container can mount a denial-of-service attack against the entire node with a simple fork bomb or " +
					"memory allocation loop.\n\n" +
					"## How to Fix\n\n" +
					"Set both CPU and memory limits based on your application's actual resource usage:\n\n" +
					"```yaml\nresources:\n  limits:\n    cpu: 500m\n    memory: 256Mi\n  requests:\n    cpu: 100m\n    memory: 128Mi\n```\n\n" +
					"Profile your application under load to determine appropriate values. Set limits to handle peak usage " +
					"and requests to match steady-state consumption.\n\n" +
					"## Learn More\n\n" +
					"Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine " +
					"the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.",
				FieldPath:    fieldPath,
				CurrentValue: nil,
				DesiredValue: map[string]string{"cpu": "500m", "memory": "256Mi"},
				FixHint: &checker.FixHint{
					Safety:      checker.FixPotentiallyBreaking,
					Description: "Adds default resource limits.",
					Impact:      "Applications exceeding limits will be throttled or OOMKilled.",
					Operation:   checker.FixOpSet,
				},
			})
		})
	}

	return findings, nil
}

// hasResourceLimit checks whether a container has a specific resource limit set.
func hasResourceLimit(container *corev1.Container, name corev1.ResourceName) bool {
	if container.Resources.Limits == nil {
		return false
	}
	_, ok := container.Resources.Limits[name]
	return ok
}
