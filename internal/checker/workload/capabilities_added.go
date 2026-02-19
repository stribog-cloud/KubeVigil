package workload

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// dangerousCapabilities lists Linux capabilities that grant elevated access
// and represent a significant security risk when added to containers.
var dangerousCapabilities = map[corev1.Capability]bool{
	"SYS_ADMIN":        true,
	"NET_RAW":          true,
	"SYS_PTRACE":       true,
	"DAC_OVERRIDE":     true,
	"SETUID":           true,
	"SETGID":           true,
	"NET_ADMIN":        true,
	"SYS_RAWIO":        true,
	"MKNOD":            true,
	"SYS_MODULE":       true,
	"DAC_READ_SEARCH":  true,
	"FOWNER":           true,
	"LINUX_IMMUTABLE":  true,
	"SYS_CHROOT":       true,
	"SYS_BOOT":         true,
	"KILL":             true,
	"NET_BIND_SERVICE": true,
}

// CapabilitiesAddedChecker detects containers that add dangerous Linux capabilities.
// Adding capabilities like SYS_ADMIN or NET_RAW significantly expands the container's
// attack surface and can be leveraged for container escapes or network attacks.
type CapabilitiesAddedChecker struct{}

// Name returns the kebab-case check ID.
func (c *CapabilitiesAddedChecker) Name() string { return "capabilities-added" }

// Description returns a human-readable description.
func (c *CapabilitiesAddedChecker) Description() string {
	return "Detects containers with dangerous Linux capabilities added via securityContext.capabilities.add."
}

// Categories returns the check categories.
func (c *CapabilitiesAddedChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *CapabilitiesAddedChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CapabilitiesAddedChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the capabilities-added check against all workload resources in the cache.
func (c *CapabilitiesAddedChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("capabilities-added check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
				return
			}

			var dangerous []string
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if dangerousCapabilities[cap] {
					dangerous = append(dangerous, string(cap))
				}
			}

			if len(dangerous) == 0 {
				return
			}

			fieldPath := containerFieldPath(ct, idx, "securityContext.capabilities.add")

			findings = append(findings, checker.Finding{
				Checker:   "capabilities-added",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q adds dangerous capabilities: %s.", container.Name, strings.Join(dangerous, ", ")),
				Remediation: "## Why This Matters\n\n" +
					"Linux capabilities like SYS_ADMIN, NET_RAW, and SYS_PTRACE grant kernel-level powers that dramatically expand " +
					"a container's attack surface. SYS_ADMIN alone enables filesystem mounts and namespace manipulation that can lead " +
					"to container escape. NET_RAW allows ARP spoofing and network sniffing attacks within the cluster.\n\n" +
					"## How to Fix\n\n" +
					"Drop all capabilities and only add back the specific ones your application truly requires:\n\n" +
					"```yaml\nsecurityContext:\n  capabilities:\n    drop: [\"ALL\"]\n    add: []  # Only add specific caps after careful review\n```\n\n" +
					"If your application needs to bind to ports below 1024, consider using a Kubernetes Service instead of " +
					"granting NET_BIND_SERVICE. If setup tasks need elevated permissions, use an init container.\n\n" +
					"## Learn More\n\n" +
					"The Pod Security Standards \"Restricted\" profile only allows NET_BIND_SERVICE. Refer to the Linux capabilities " +
					"man page (capabilities(7)) and CIS Benchmark 5.2.7-5.2.9 for guidance on acceptable capabilities.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}
