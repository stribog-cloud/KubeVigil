package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// CapabilitiesNotDroppedChecker detects containers that do not drop ALL capabilities.
// Containers inherit a default set of Linux capabilities that are rarely needed.
// Best practice is to drop ALL and add back only what is required.
type CapabilitiesNotDroppedChecker struct{}

// Name returns the kebab-case check ID.
func (c *CapabilitiesNotDroppedChecker) Name() string { return "capabilities-not-dropped" }

// Description returns a human-readable description.
func (c *CapabilitiesNotDroppedChecker) Description() string {
	return "Detects containers that do not drop ALL capabilities, leaving unnecessary privileges."
}

// Categories returns the check categories.
func (c *CapabilitiesNotDroppedChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *CapabilitiesNotDroppedChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CapabilitiesNotDroppedChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the capabilities-not-dropped check against all workload resources in the cache.
func (c *CapabilitiesNotDroppedChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("capabilities-not-dropped check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if dropsAll(&container) {
				return
			}

			fieldPath := containerFieldPath(ct, idx, "securityContext.capabilities.drop")

			findings = append(findings, checker.Finding{
				Checker:   "capabilities-not-dropped",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q does not drop ALL capabilities, leaving it with unnecessary default privileges.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. " +
					"These defaults are rarely needed by application code and significantly increase the potential damage " +
					"from a container compromise. Dropping all capabilities follows the principle of least privilege.\n\n" +
					"## How to Fix\n\n" +
					"Explicitly drop all capabilities and selectively add back only what your application needs:\n\n" +
					"```yaml\nsecurityContext:\n  capabilities:\n    drop: [\"ALL\"]\n    add: [\"NET_BIND_SERVICE\"]  # Only if needed\n```\n\n" +
					"Most web applications, API servers, and background workers run perfectly with all capabilities dropped. " +
					"Test your application after making this change to confirm no functionality is lost.\n\n" +
					"## Learn More\n\n" +
					"This is required by the Pod Security Standards \"Restricted\" profile and aligns with CIS Benchmark 5.2.7. " +
					"Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}

// dropsAll returns true if the container's capabilities.drop list includes "ALL".
func dropsAll(container *corev1.Container) bool {
	if container.SecurityContext == nil {
		return false
	}
	if container.SecurityContext.Capabilities == nil {
		return false
	}
	for _, cap := range container.SecurityContext.Capabilities.Drop {
		if cap == "ALL" {
			return true
		}
	}
	return false
}
