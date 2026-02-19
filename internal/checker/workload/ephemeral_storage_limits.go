package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// EphemeralStorageLimitsChecker detects containers missing ephemeral-storage limits.
// Without ephemeral-storage limits, containers can fill up the node's disk,
// causing eviction of all pods on the node.
type EphemeralStorageLimitsChecker struct{}

// Name returns the kebab-case check ID.
func (c *EphemeralStorageLimitsChecker) Name() string { return "ephemeral-storage-limits" }

// Description returns a human-readable description.
func (c *EphemeralStorageLimitsChecker) Description() string {
	return "Detects containers missing ephemeral-storage limits, which can lead to unbounded disk usage."
}

// Categories returns the check categories.
func (c *EphemeralStorageLimitsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *EphemeralStorageLimitsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EphemeralStorageLimitsChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the ephemeral-storage-limits check against all workload resources in the cache.
func (c *EphemeralStorageLimitsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ephemeral-storage-limits check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if hasResourceLimit(&container, corev1.ResourceEphemeralStorage) {
				return
			}

			fieldPath := containerFieldPath(ct, idx, "resources.limits.ephemeral-storage")

			findings = append(findings, checker.Finding{
				Checker:   "ephemeral-storage-limits",
				Severity:  checker.SeverityLow,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q is missing ephemeral-storage limits.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, " +
					"a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially " +
					"causing a cascading failure across your cluster. This is a common denial-of-service vector.\n\n" +
					"## How to Fix\n\n" +
					"Set ephemeral-storage limits alongside your CPU and memory limits:\n\n" +
					"```yaml\nresources:\n  limits:\n    ephemeral-storage: 1Gi\n  requests:\n    ephemeral-storage: 500Mi\n```\n\n" +
					"Estimate your application's disk usage from logs, temporary files, and cache data. " +
					"If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.\n\n" +
					"## Learn More\n\n" +
					"The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default " +
					"ephemeral-storage limits at the namespace level to catch containers that omit this setting.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}
