package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HostPIDChecker detects pods with hostPID: true enabled.
// When hostPID is true, containers share the host's PID namespace, allowing
// them to see and signal all processes running on the node.
type HostPIDChecker struct{}

// Name returns the kebab-case check ID.
func (c *HostPIDChecker) Name() string { return "host-pid" }

// Description returns a human-readable description.
func (c *HostPIDChecker) Description() string {
	return "Detects pods with hostPID: true, which shares the host PID namespace with containers."
}

// Categories returns the check categories.
func (c *HostPIDChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *HostPIDChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HostPIDChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the host-pid check against all workload resources in the cache.
func (c *HostPIDChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("host-pid check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		if !info.Spec.HostPID {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "host-pid",
			Severity:  checker.SeverityCritical,
			Resource:  info.ResourceName,
			Namespace: info.Namespace,
			Kind:      info.Kind,
			Container: "",
			Message:   fmt.Sprintf("%s %q has hostPID enabled, allowing containers to see all host processes.", info.Kind, info.ResourceName),
			Remediation: "## Why This Matters\n\n" +
				"When hostPID is enabled, containers share the host's process ID namespace and can see every process running " +
				"on the node, including processes from other pods and system daemons. An attacker can use this to inspect " +
				"environment variables containing secrets, send signals to critical processes, or exploit /proc entries to " +
				"escape the container entirely.\n\n" +
				"## How to Fix\n\n" +
				"Disable host PID namespace sharing in the pod spec:\n\n" +
				"```yaml\nspec:\n  hostPID: false\n```\n\n" +
				"If you need process visibility for monitoring or debugging, consider using ephemeral containers " +
				"or a dedicated monitoring DaemonSet with tightly scoped RBAC instead.\n\n" +
				"## Learn More\n\n" +
				"This check aligns with CIS Benchmark 5.2.2 and the Pod Security Standards \"Baseline\" profile, " +
				"which prohibits hostPID. Process namespace isolation is a fundamental container security boundary.",
			FieldPath: ".spec.hostPID",
		})
	}

	return findings, nil
}
