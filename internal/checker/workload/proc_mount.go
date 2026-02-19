package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ProcMountChecker detects containers with procMount set to Unmasked.
// By default, Kubernetes masks certain paths in /proc to prevent containers from
// accessing sensitive host information. Unmasking /proc exposes this information
// and can be used for container escapes.
type ProcMountChecker struct{}

// Name returns the kebab-case check ID.
func (c *ProcMountChecker) Name() string { return "proc-mount" }

// Description returns a human-readable description.
func (c *ProcMountChecker) Description() string {
	return "Detects containers with procMount set to Unmasked, which exposes sensitive host information via /proc."
}

// Categories returns the check categories.
func (c *ProcMountChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *ProcMountChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ProcMountChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the proc-mount check against all workload resources in the cache.
func (c *ProcMountChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("proc-mount check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if container.SecurityContext == nil {
				return
			}
			if container.SecurityContext.ProcMount == nil {
				return
			}
			if *container.SecurityContext.ProcMount != corev1.UnmaskedProcMount {
				return
			}

			fieldPath := containerFieldPath(ct, idx, "securityContext.procMount")

			findings = append(findings, checker.Finding{
				Checker:     "proc-mount",
				Severity:    checker.SeverityHigh,
				Resource:    info.ResourceName,
				Namespace:   info.Namespace,
				Kind:        info.Kind,
				Container:   container.Name,
				Message:     fmt.Sprintf("Container %q has procMount set to Unmasked, exposing sensitive host information via /proc.", container.Name),
				Remediation: "Set procMount to Default or remove it. Unmasked /proc exposes sensitive host information.",
				FieldPath:   fieldPath,
			})
		})
	}

	return findings, nil
}
