package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// RunAsRootChecker detects containers running as root (UID 0) or missing
// runAsNonRoot: true. Running as root gives processes full privileges inside
// the container, increasing the blast radius of a container breakout.
type RunAsRootChecker struct{}

// Name returns the kebab-case check ID.
func (c *RunAsRootChecker) Name() string { return "run-as-root" }

// Description returns a human-readable description.
func (c *RunAsRootChecker) Description() string {
	return "Detects containers running as root (UID 0) or missing runAsNonRoot: true."
}

// Categories returns the check categories.
func (c *RunAsRootChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *RunAsRootChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *RunAsRootChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the run-as-root check against all workload resources in the cache.
//
// The check evaluates container-level and pod-level securityContext with proper
// inheritance: container-level settings override pod-level settings. A container
// is considered safe if any of the following are true:
//   - Container-level runAsNonRoot is true (and runAsUser is not explicitly 0)
//   - Pod-level runAsNonRoot is true AND container does not override it AND
//     container-level runAsUser is not explicitly 0
//   - Container-level runAsUser is set to a non-zero value
//   - Pod-level runAsUser is set to a non-zero value AND container does not override it
func (c *RunAsRootChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("run-as-root check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		podSC := info.Spec.SecurityContext

		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if finding, ok := checkRunAsRoot(info, &container, ct, idx, podSC); ok {
				findings = append(findings, finding)
			}
		})
	}

	return findings, nil
}

// checkRunAsRoot evaluates whether a single container may run as root.
// Returns a finding and true if the container is not adequately protected.
func checkRunAsRoot(info *PodSpecInfo, container *corev1.Container, ct ContainerType, idx int, podSC *corev1.PodSecurityContext) (checker.Finding, bool) {
	containerSC := container.SecurityContext

	// Resolve effective runAsUser: container overrides pod.
	effectiveRunAsUser := resolveRunAsUser(podSC, containerSC)

	// If runAsUser is explicitly 0, always flag regardless of runAsNonRoot.
	if effectiveRunAsUser != nil && *effectiveRunAsUser == 0 {
		return checker.Finding{
			Checker:     "run-as-root",
			Severity:    checker.SeverityHigh,
			Resource:    info.ResourceName,
			Namespace:   info.Namespace,
			Kind:        info.Kind,
			Container:   container.Name,
			Message:     fmt.Sprintf("Container %q is explicitly configured to run as root (UID 0).", container.Name),
			Remediation: "Set securityContext.runAsUser to a non-zero UID (e.g., 1000) and set runAsNonRoot: true.",
			FieldPath:   containerFieldPath(ct, idx, "securityContext.runAsUser"),
		}, true
	}

	// If runAsUser is set to a non-zero value, the container is safe.
	if effectiveRunAsUser != nil && *effectiveRunAsUser != 0 {
		return checker.Finding{}, false
	}

	// No explicit runAsUser set. Check runAsNonRoot.
	effectiveRunAsNonRoot := resolveRunAsNonRoot(podSC, containerSC)

	// If runAsNonRoot is true, the container is safe (Kubernetes will enforce it).
	if effectiveRunAsNonRoot != nil && *effectiveRunAsNonRoot {
		return checker.Finding{}, false
	}

	// Neither runAsUser (non-zero) nor runAsNonRoot: true is set.
	// The container may run as root by default.
	return checker.Finding{
		Checker:     "run-as-root",
		Severity:    checker.SeverityHigh,
		Resource:    info.ResourceName,
		Namespace:   info.Namespace,
		Kind:        info.Kind,
		Container:   container.Name,
		Message:     fmt.Sprintf("Container %q does not set runAsNonRoot: true and may run as root.", container.Name),
		Remediation: "Set securityContext.runAsNonRoot to true and optionally set runAsUser to a non-zero UID.",
		FieldPath:   containerFieldPath(ct, idx, "securityContext.runAsNonRoot"),
	}, true
}

// resolveRunAsUser returns the effective runAsUser for a container,
// applying the container-overrides-pod inheritance rule.
func resolveRunAsUser(podSC *corev1.PodSecurityContext, containerSC *corev1.SecurityContext) *int64 {
	// Container-level takes precedence.
	if containerSC != nil && containerSC.RunAsUser != nil {
		return containerSC.RunAsUser
	}
	// Fall back to pod-level.
	if podSC != nil && podSC.RunAsUser != nil {
		return podSC.RunAsUser
	}
	return nil
}

// resolveRunAsNonRoot returns the effective runAsNonRoot for a container,
// applying the container-overrides-pod inheritance rule.
func resolveRunAsNonRoot(podSC *corev1.PodSecurityContext, containerSC *corev1.SecurityContext) *bool {
	// Container-level takes precedence.
	if containerSC != nil && containerSC.RunAsNonRoot != nil {
		return containerSC.RunAsNonRoot
	}
	// Fall back to pod-level.
	if podSC != nil && podSC.RunAsNonRoot != nil {
		return podSC.RunAsNonRoot
	}
	return nil
}
