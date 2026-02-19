package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// RuntimeClassChecker detects pods that do not specify a RuntimeClass.
// RuntimeClasses enable sandboxed container runtimes (e.g., gVisor, Kata Containers)
// that provide stronger isolation boundaries than the default runtime.
type RuntimeClassChecker struct{}

// Name returns the kebab-case check ID.
func (c *RuntimeClassChecker) Name() string { return "runtime-class" }

// Description returns a human-readable description.
func (c *RuntimeClassChecker) Description() string {
	return "Detects pods missing a RuntimeClass, which means they use the default (unsandboxed) container runtime."
}

// Categories returns the check categories.
func (c *RuntimeClassChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *RuntimeClassChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *RuntimeClassChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the runtime-class check against all workload resources in the cache.
func (c *RuntimeClassChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("runtime-class check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		if info.Spec.RuntimeClassName != nil && *info.Spec.RuntimeClassName != "" {
			continue // RuntimeClass is set
		}

		findings = append(findings, checker.Finding{
			Checker:   "runtime-class",
			Severity:  checker.SeverityLow,
			Resource:  info.ResourceName,
			Namespace: info.Namespace,
			Kind:      info.Kind,
			Message:   fmt.Sprintf("Pod %q does not specify a RuntimeClass, using the default (unsandboxed) runtime.", info.ResourceName),
			Remediation: "## Why This Matters\n\n" +
				"Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel " +
				"directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like " +
				"gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in " +
				"lightweight VMs.\n\n" +
				"## How to Fix\n\n" +
				"Specify a sandboxed RuntimeClass in the pod spec:\n\n" +
				"```yaml\nspec:\n  runtimeClassName: gvisor\n```\n\n" +
				"Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), " +
				"`kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with " +
				"`kubectl get runtimeclasses`.\n\n" +
				"## Learn More\n\n" +
				"Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. " +
				"They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.",
			FieldPath: ".spec.runtimeClassName",
		})
	}

	return findings, nil
}
