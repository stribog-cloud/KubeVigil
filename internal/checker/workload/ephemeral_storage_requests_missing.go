package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// EphemeralStorageRequestsMissingChecker detects containers missing an
// ephemeral-storage request. This complements EphemeralStorageLimitsChecker
// (which only checks for a limit), mirroring the established
// resource-limits-missing/resource-requests-missing split already applied to
// CPU and memory.
type EphemeralStorageRequestsMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *EphemeralStorageRequestsMissingChecker) Name() string {
	return "ephemeral-storage-requests-missing"
}

// Description returns a human-readable description.
func (c *EphemeralStorageRequestsMissingChecker) Description() string {
	return "Detects containers missing an ephemeral-storage request, which prevents proper scheduling."
}

// Categories returns the check categories.
func (c *EphemeralStorageRequestsMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *EphemeralStorageRequestsMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EphemeralStorageRequestsMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the ephemeral-storage-requests-missing check against all workload resources in the cache.
func (c *EphemeralStorageRequestsMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ephemeral-storage-requests-missing check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if hasResourceRequest(&container, corev1.ResourceEphemeralStorage) {
				return
			}

			fieldPath := containerFieldPath(ct, idx, "resources.requests.ephemeral-storage")

			findings = append(findings, checker.Finding{
				Checker:   "ephemeral-storage-requests-missing",
				Severity:  checker.SeverityLow,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q is missing an ephemeral-storage request.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"Resource requests tell the Kubernetes scheduler how much ephemeral storage (container logs, emptyDir " +
					"volumes, and the writable container layer) your container needs. Without a request, the scheduler treats " +
					"the pod as needing zero ephemeral storage and may pack too many pods onto a single node, leading to disk " +
					"pressure and unpredictable eviction behavior even when a limit is set.\n\n" +
					"## How to Fix\n\n" +
					"Set an ephemeral-storage request alongside your limit:\n\n" +
					"```yaml\nresources:\n  requests:\n    ephemeral-storage: 500Mi\n  limits:\n    ephemeral-storage: 1Gi\n```\n\n" +
					"Estimate the request from your application's steady-state disk usage (logs, temp files, cache data).\n\n" +
					"## Learn More\n\n" +
					"This mirrors the CPU/memory resource-requests-missing check applied to ephemeral storage. See the " +
					"Kubernetes documentation on local ephemeral storage for scheduling and eviction behavior.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}
