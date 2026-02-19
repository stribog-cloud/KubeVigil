package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// RunAsGroupChecker detects containers that are missing runAsGroup or have
// runAsGroup set to GID 0. Without an explicit group, the container process
// runs as the root group (GID 0), which may grant access to group-owned
// files and resources on the host.
type RunAsGroupChecker struct{}

// Name returns the kebab-case check ID.
func (c *RunAsGroupChecker) Name() string { return "run-as-group" }

// Description returns a human-readable description.
func (c *RunAsGroupChecker) Description() string {
	return "Detects containers missing runAsGroup or running as GID 0."
}

// Categories returns the check categories.
func (c *RunAsGroupChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *RunAsGroupChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *RunAsGroupChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the run-as-group check against all workload resources in the cache.
//
// A finding is produced when:
//   - runAsGroup is not set at either container or pod level (missing)
//   - runAsGroup is explicitly set to 0 at the effective level
//
// Container-level runAsGroup overrides pod-level runAsGroup.
func (c *RunAsGroupChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("run-as-group check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		podSC := info.Spec.SecurityContext

		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			effectiveGID := resolveRunAsGroup(podSC, container.SecurityContext)

			fieldPath := containerFieldPath(ct, idx, "securityContext.runAsGroup")

			if effectiveGID == nil {
				// runAsGroup is not set at any level.
				findings = append(findings, checker.Finding{
					Checker:     "run-as-group",
					Severity:    checker.SeverityMedium,
					Resource:    info.ResourceName,
					Namespace:   info.Namespace,
					Kind:        info.Kind,
					Container:   container.Name,
					Message:     fmt.Sprintf("Container %q does not set runAsGroup; the process will run as GID 0 (root group) by default.", container.Name),
					Remediation: "Set securityContext.runAsGroup to a non-zero GID (e.g., 1000) to avoid running as the root group.",
					FieldPath:   fieldPath,
				})
				return
			}

			if *effectiveGID == 0 {
				// runAsGroup is explicitly set to 0.
				findings = append(findings, checker.Finding{
					Checker:     "run-as-group",
					Severity:    checker.SeverityMedium,
					Resource:    info.ResourceName,
					Namespace:   info.Namespace,
					Kind:        info.Kind,
					Container:   container.Name,
					Message:     fmt.Sprintf("Container %q is explicitly configured to run as the root group (GID 0).", container.Name),
					Remediation: "Set securityContext.runAsGroup to a non-zero GID (e.g., 1000) to avoid running as the root group.",
					FieldPath:   fieldPath,
				})
			}
		})
	}

	return findings, nil
}

// resolveRunAsGroup returns the effective runAsGroup for a container,
// applying the container-overrides-pod inheritance rule.
func resolveRunAsGroup(podSC *corev1.PodSecurityContext, containerSC *corev1.SecurityContext) *int64 {
	// Container-level takes precedence.
	if containerSC != nil && containerSC.RunAsGroup != nil {
		return containerSC.RunAsGroup
	}
	// Fall back to pod-level.
	if podSC != nil && podSC.RunAsGroup != nil {
		return podSC.RunAsGroup
	}
	return nil
}
