package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ReadOnlyRootfsChecker detects containers without readOnlyRootFilesystem: true.
// A writable root filesystem allows attackers to modify binaries, install tools,
// or persist malware inside the container.
type ReadOnlyRootfsChecker struct{}

// Name returns the kebab-case check ID.
func (c *ReadOnlyRootfsChecker) Name() string { return "read-only-rootfs" }

// Description returns a human-readable description.
func (c *ReadOnlyRootfsChecker) Description() string {
	return "Detects containers without readOnlyRootFilesystem: true, which allows modification of container filesystem."
}

// Categories returns the check categories.
func (c *ReadOnlyRootfsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *ReadOnlyRootfsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ReadOnlyRootfsChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the read-only-rootfs check against all workload resources in the cache.
func (c *ReadOnlyRootfsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("read-only-rootfs check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if container.SecurityContext == nil ||
				container.SecurityContext.ReadOnlyRootFilesystem == nil ||
				!*container.SecurityContext.ReadOnlyRootFilesystem {

				fieldPath := containerFieldPath(ct, idx, "securityContext.readOnlyRootFilesystem")

				findings = append(findings, checker.Finding{
					Checker:     "read-only-rootfs",
					Severity:    checker.SeverityMedium,
					Resource:    info.ResourceName,
					Namespace:   info.Namespace,
					Kind:        info.Kind,
					Container:   container.Name,
					Message:     fmt.Sprintf("Container %q does not have a read-only root filesystem.", container.Name),
					Remediation: "Set securityContext.readOnlyRootFilesystem to true. Use emptyDir or tmpfs for writable paths.",
					FieldPath:   fieldPath,
				})
			}
		})
	}

	return findings, nil
}
