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
						Checker:   "host-ports",
						Severity:  checker.SeverityHigh,
						Resource:  info.ResourceName,
						Namespace: info.Namespace,
						Kind:      info.Kind,
						Container: container.Name,
						Message:   fmt.Sprintf("Container %q binds to host port %d, exposing the service directly on the node.", container.Name, port.HostPort),
						Remediation: "## Why This Matters\n\n" +
							"Binding to a host port exposes your service directly on the node's network interface, bypassing Kubernetes " +
							"Service abstractions and NetworkPolicies. It also ties each pod replica to a unique node (since two pods " +
							"cannot share the same host port), severely limiting scheduling flexibility, rolling updates, and scaling.\n\n" +
							"## How to Fix\n\n" +
							"Remove the hostPort and use Kubernetes Services to expose your application:\n\n" +
							"```yaml\nports:\n  - containerPort: 8080\n    protocol: TCP\n    # Remove hostPort entirely\n```\n\n" +
							"Use a ClusterIP Service for internal traffic, NodePort or LoadBalancer for external access, " +
							"or an Ingress controller for HTTP routing.\n\n" +
							"## Learn More\n\n" +
							"Host ports are prohibited by the Pod Security Standards \"Baseline\" profile. The only common " +
							"legitimate use is for DaemonSets that must bind to a well-known port on every node (e.g., log collectors).",
						FieldPath:    containerFieldPath(ct, idx, "ports"),
						CurrentValue: port.HostPort,
						DesiredValue: nil,
						FixHint: &checker.FixHint{
							Safety:      checker.FixPotentiallyBreaking,
							Description: "Removes hostPort from container ports.",
							Impact:      "External traffic routing via host ports will stop working.",
							Operation:   checker.FixOpRemove,
						},
					})
				}
			}
		})
	}

	return findings, nil
}
