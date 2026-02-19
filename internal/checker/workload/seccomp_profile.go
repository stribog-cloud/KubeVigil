package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// SeccompProfileChecker detects containers and pods missing a Seccomp profile.
// Seccomp restricts the system calls a container can make, reducing the kernel
// attack surface. Containers should use RuntimeDefault or a custom Localhost profile.
type SeccompProfileChecker struct{}

// Name returns the kebab-case check ID.
func (c *SeccompProfileChecker) Name() string { return "seccomp-profile" }

// Description returns a human-readable description.
func (c *SeccompProfileChecker) Description() string {
	return "Detects containers and pods missing a Seccomp profile, which leaves the full set of system calls available."
}

// Categories returns the check categories.
func (c *SeccompProfileChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *SeccompProfileChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *SeccompProfileChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the seccomp-profile check against all workload resources in the cache.
func (c *SeccompProfileChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("seccomp-profile check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if hasSeccompProfile(&container, info) {
				return
			}

			fieldPath := containerFieldPath(ct, idx, "securityContext.seccompProfile")

			findings = append(findings, checker.Finding{
				Checker:   "seccomp-profile",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q does not have a Seccomp profile set at either the container or pod level.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire " +
					"kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container " +
					"escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.\n\n" +
					"## How to Fix\n\n" +
					"Apply a Seccomp profile at the container or pod level:\n\n" +
					"```yaml\nsecurityContext:\n  seccompProfile:\n    type: RuntimeDefault\n```\n\n" +
					"The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application " +
					"behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. " +
					"Set the profile at the pod level to apply it to all containers.\n\n" +
					"## Learn More\n\n" +
					"Seccomp profiles are required by the Pod Security Standards \"Restricted\" profile and CIS Benchmark 5.7.2. " +
					"Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}

// hasSeccompProfile returns true if the container has a seccomp profile set,
// either at the container level or inherited from the pod level.
func hasSeccompProfile(container *corev1.Container, info *PodSpecInfo) bool {
	// Check container-level seccomp profile first.
	if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
		profileType := container.SecurityContext.SeccompProfile.Type
		if profileType == corev1.SeccompProfileTypeRuntimeDefault ||
			profileType == corev1.SeccompProfileTypeLocalhost {
			return true
		}
	}

	// Fall back to pod-level seccomp profile.
	if info.Spec.SecurityContext != nil && info.Spec.SecurityContext.SeccompProfile != nil {
		profileType := info.Spec.SecurityContext.SeccompProfile.Type
		if profileType == corev1.SeccompProfileTypeRuntimeDefault ||
			profileType == corev1.SeccompProfileTypeLocalhost {
			return true
		}
	}

	return false
}
