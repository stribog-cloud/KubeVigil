package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HostPortsChecker detects containers that bind to host ports.
// Binding to host ports ties a pod to a specific node and exposes services
// directly on the node's network interface, bypassing Kubernetes Service
// abstractions and limiting scheduling flexibility.
type HostPortsChecker struct{}

// Name returns the kebab-case check ID.
func (c *HostPortsChecker) Name() string { return "host-ports" }

// Description returns a human-readable description.
func (c *HostPortsChecker) Description() string {
	return "Detects containers that bind to host ports, which exposes services directly on the node."
}

// Categories returns the check categories.
func (c *HostPortsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *HostPortsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HostPortsChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the host-ports check against all workload resources in the cache.
func (c *HostPortsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("host-ports check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			for _, port := range container.Ports {
				if port.HostPort > 0 {
					findings = append(findings, checker.Finding{
						Checker:     "host-ports",
						Severity:    checker.SeverityHigh,
						Resource:    info.ResourceName,
						Namespace:   info.Namespace,
						Kind:        info.Kind,
						Container:   container.Name,
						Message:     fmt.Sprintf("Container %q binds to host port %d, exposing the service directly on the node.", container.Name, port.HostPort),
						Remediation: "Remove hostPort bindings. Use Services to expose pods instead.",
						FieldPath:   containerFieldPath(ct, idx, "ports"),
					})
				}
			}
		})
	}

	return findings, nil
}
