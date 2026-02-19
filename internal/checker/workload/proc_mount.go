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
				Checker:   "proc-mount",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q has procMount set to Unmasked, exposing sensitive host information via /proc.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"Kubernetes masks certain paths in /proc by default to prevent containers from reading sensitive kernel " +
					"information such as hardware details, other process data, and kernel parameters. An unmasked /proc filesystem " +
					"exposes these paths and can be used as a stepping stone for container escape attacks by manipulating cgroup " +
					"files or accessing kernel interfaces.\n\n" +
					"## How to Fix\n\n" +
					"Use the default masked proc mount or remove the procMount field entirely:\n\n" +
					"```yaml\nsecurityContext:\n  procMount: Default\n```\n\n" +
					"The Default value masks sensitive paths like /proc/kcore, /proc/keys, and /proc/timer_list. " +
					"If you need raw /proc access for debugging, use ephemeral containers in non-production environments only.\n\n" +
					"## Learn More\n\n" +
					"Unmasked procMount is prohibited by the Pod Security Standards \"Baseline\" profile. The masked paths " +
					"in /proc prevent information disclosure that could aid in kernel exploitation or container escape.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}
