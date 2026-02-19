package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ResourceRequestsMissingChecker detects containers missing CPU or memory requests.
// Without resource requests, the scheduler cannot make informed placement decisions,
// leading to overcommitted nodes and unpredictable performance.
type ResourceRequestsMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *ResourceRequestsMissingChecker) Name() string { return "resource-requests-missing" }

// Description returns a human-readable description.
func (c *ResourceRequestsMissingChecker) Description() string {
	return "Detects containers missing CPU or memory requests, which prevents proper scheduling."
}

// Categories returns the check categories.
func (c *ResourceRequestsMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *ResourceRequestsMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ResourceRequestsMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the resource-requests-missing check against all workload resources in the cache.
func (c *ResourceRequestsMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("resource-requests-missing check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			missingCPU := !hasResourceRequest(&container, corev1.ResourceCPU)
			missingMemory := !hasResourceRequest(&container, corev1.ResourceMemory)

			if !missingCPU && !missingMemory {
				return
			}

			var msg string
			switch {
			case missingCPU && missingMemory:
				msg = fmt.Sprintf("Container %q is missing both CPU and memory requests.", container.Name)
			case missingCPU:
				msg = fmt.Sprintf("Container %q is missing CPU requests.", container.Name)
			default:
				msg = fmt.Sprintf("Container %q is missing memory requests.", container.Name)
			}

			fieldPath := containerFieldPath(ct, idx, "resources.requests")

			findings = append(findings, checker.Finding{
				Checker:   "resource-requests-missing",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   msg,
				Remediation: "## Why This Matters\n\n" +
					"Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without " +
					"requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single " +
					"node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.\n\n" +
					"## How to Fix\n\n" +
					"Set resource requests based on your application's steady-state usage:\n\n" +
					"```yaml\nresources:\n  requests:\n    cpu: 100m\n    memory: 128Mi\n  limits:\n    cpu: 500m\n    memory: 256Mi\n```\n\n" +
					"Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set " +
					"requests to match the typical steady-state usage.\n\n" +
					"## Learn More\n\n" +
					"Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits " +
					"receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}

// hasResourceRequest checks whether a container has a specific resource request set.
func hasResourceRequest(container *corev1.Container, name corev1.ResourceName) bool {
	if container.Resources.Requests == nil {
		return false
	}
	_, ok := container.Resources.Requests[name]
	return ok
}
