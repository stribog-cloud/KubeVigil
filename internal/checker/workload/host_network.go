package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HostNetworkChecker detects pods with hostNetwork: true enabled.
// When hostNetwork is true, containers share the host's network namespace,
// bypassing Kubernetes network policies and gaining access to all host network
// interfaces and ports.
type HostNetworkChecker struct{}

// Name returns the kebab-case check ID.
func (c *HostNetworkChecker) Name() string { return "host-network" }

// Description returns a human-readable description.
func (c *HostNetworkChecker) Description() string {
	return "Detects pods with hostNetwork: true, which bypasses network policies and exposes the host network."
}

// Categories returns the check categories.
func (c *HostNetworkChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *HostNetworkChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HostNetworkChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the host-network check against all workload resources in the cache.
func (c *HostNetworkChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("host-network check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		if !info.Spec.HostNetwork {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:     "host-network",
			Severity:    checker.SeverityCritical,
			Resource:    info.ResourceName,
			Namespace:   info.Namespace,
			Kind:        info.Kind,
			Container:   "",
			Message:     fmt.Sprintf("%s %q has hostNetwork enabled, bypassing network policies and exposing the host network.", info.Kind, info.ResourceName),
			Remediation: "Set spec.hostNetwork to false. Host network namespace bypasses network policies.",
			FieldPath:   ".spec.hostNetwork",
		})
	}

	return findings, nil
}
