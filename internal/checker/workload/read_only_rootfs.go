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
					Checker:   "read-only-rootfs",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("Container %q does not have a read-only root filesystem.", container.Name),
					Remediation: "## Why This Matters\n\n" +
						"A writable root filesystem allows an attacker who gains code execution in your container to modify application " +
						"binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the " +
						"filesystem read-only eliminates an entire class of post-exploitation techniques.\n\n" +
						"## How to Fix\n\n" +
						"Enable a read-only root filesystem and mount writable volumes only where needed:\n\n" +
						"```yaml\nsecurityContext:\n  readOnlyRootFilesystem: true\nvolumeMounts:\n  - name: tmp\n    mountPath: /tmp\nvolumes:\n  - name: tmp\n    emptyDir: {}\n```\n\n" +
						"Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir " +
						"or tmpfs volume rather than making the entire filesystem writable.\n\n" +
						"## Learn More\n\n" +
						"This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities " +
						"and running as non-root, a read-only filesystem forms a strong container hardening baseline.",
					FieldPath: fieldPath,
				})
			}
		})
	}

	return findings, nil
}
