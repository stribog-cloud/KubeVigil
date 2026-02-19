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
			Checker:     "runtime-class",
			Severity:    checker.SeverityLow,
			Resource:    info.ResourceName,
			Namespace:   info.Namespace,
			Kind:        info.Kind,
			Message:     fmt.Sprintf("Pod %q does not specify a RuntimeClass, using the default (unsandboxed) runtime.", info.ResourceName),
			Remediation: "Specify a RuntimeClass for sandboxed container execution (e.g., gVisor, Kata).",
			FieldPath:   ".spec.runtimeClassName",
		})
	}

	return findings, nil
}
