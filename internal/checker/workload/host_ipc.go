package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HostIPCChecker detects pods with hostIPC: true enabled.
// When hostIPC is true, containers share the host's IPC namespace, allowing
// access to host shared memory segments and inter-process communication.
type HostIPCChecker struct{}

// Name returns the kebab-case check ID.
func (c *HostIPCChecker) Name() string { return "host-ipc" }

// Description returns a human-readable description.
func (c *HostIPCChecker) Description() string {
	return "Detects pods with hostIPC: true, which shares the host IPC namespace with containers."
}

// Categories returns the check categories.
func (c *HostIPCChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *HostIPCChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HostIPCChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the host-ipc check against all workload resources in the cache.
func (c *HostIPCChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("host-ipc check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		if !info.Spec.HostIPC {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:     "host-ipc",
			Severity:    checker.SeverityCritical,
			Resource:    info.ResourceName,
			Namespace:   info.Namespace,
			Kind:        info.Kind,
			Container:   "",
			Message:     fmt.Sprintf("%s %q has hostIPC enabled, allowing containers to access host shared memory.", info.Kind, info.ResourceName),
			Remediation: "Set spec.hostIPC to false. Host IPC namespace allows accessing host shared memory.",
			FieldPath:   ".spec.hostIPC",
		})
	}

	return findings, nil
}
