package psa

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// RestrictedViolationsChecker detects workloads that violate the Pod Security
// Standards (PSS) Restricted profile additions. The Restricted profile is the
// most hardened profile, requiring running as non-root, disabling privilege
// escalation, and dropping all capabilities. This checker focuses on the
// Restricted-specific additions beyond Baseline (runAsNonRoot,
// allowPrivilegeEscalation, capabilities drop ALL).
type RestrictedViolationsChecker struct{}

// Name returns the kebab-case check ID.
func (c *RestrictedViolationsChecker) Name() string { return "psa-restricted-violations" }

// Description returns a human-readable description.
func (c *RestrictedViolationsChecker) Description() string {
	return "Detects workloads violating the PSS Restricted profile (runAsNonRoot, allowPrivilegeEscalation, capabilities drop ALL)."
}

// Categories returns the check categories.
func (c *RestrictedViolationsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryPSS}
}

// SupportedModes returns which scan modes this check supports.
func (c *RestrictedViolationsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *RestrictedViolationsChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the PSS Restricted violations check against all workloads in the cache.
func (c *RestrictedViolationsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("psa-restricted-violations check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		// Determine pod-level runAsNonRoot setting.
		podRunAsNonRoot := false
		if info.Spec.SecurityContext != nil && info.Spec.SecurityContext.RunAsNonRoot != nil {
			podRunAsNonRoot = *info.Spec.SecurityContext.RunAsNonRoot
		}

		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			sc := container.SecurityContext

			// Check runAsNonRoot: must be explicitly true at container or pod level.
			containerRunAsNonRoot := podRunAsNonRoot
			if sc != nil && sc.RunAsNonRoot != nil {
				containerRunAsNonRoot = *sc.RunAsNonRoot
			}
			if !containerRunAsNonRoot {
				findings = append(findings, checker.Finding{
					Checker:   "psa-restricted-violations",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("%s %q container %q violates PSS Restricted: runAsNonRoot is not true.", info.Kind, info.ResourceName, container.Name),
					Remediation: "## Why This Matters\n\n" +
						"Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. " +
						"Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.\n\n" +
						"## How to Fix\n\n" +
						"Set `runAsNonRoot: true` and specify a non-root user ID in the security context:\n\n" +
						"```yaml\nsecurityContext:\n  runAsNonRoot: true\n  runAsUser: 1000\n  runAsGroup: 1000\n```\n\n" +
						"Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).\n\n" +
						"## Learn More\n\n" +
						"See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. " +
						"Running as non-root is a fundamental container security best practice.",
					FieldPath: containerFieldPath(ct, idx, "securityContext.runAsNonRoot"),
				})
			}

			// Check allowPrivilegeEscalation: must be explicitly false.
			if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				findings = append(findings, checker.Finding{
					Checker:   "psa-restricted-violations",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("%s %q container %q violates PSS Restricted: allowPrivilegeEscalation is not false.", info.Kind, info.ResourceName, container.Name),
					Remediation: "## Why This Matters\n\n" +
						"When `allowPrivilegeEscalation` is true (the default), processes inside the container can gain more privileges than their parent process. " +
						"This enables attacks via setuid/setgid binaries, kernel exploits, and other escalation vectors that can lead to container escape.\n\n" +
						"## How to Fix\n\n" +
						"Explicitly set `allowPrivilegeEscalation` to false in the container's security context:\n\n" +
						"```yaml\nsecurityContext:\n  allowPrivilegeEscalation: false\n  runAsNonRoot: true\n  capabilities:\n    drop: [ALL]\n```\n\n" +
						"This prevents setuid binaries and other privilege escalation vectors from working inside the container.\n\n" +
						"## Learn More\n\n" +
						"See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.5. " +
						"Disabling privilege escalation is required for PSS Restricted compliance.",
					FieldPath: containerFieldPath(ct, idx, "securityContext.allowPrivilegeEscalation"),
				})
			}

			// Check capabilities.drop includes ALL.
			dropsAll := false
			if sc != nil && sc.Capabilities != nil {
				for _, cap := range sc.Capabilities.Drop {
					if cap == "ALL" {
						dropsAll = true
						break
					}
				}
			}
			if !dropsAll {
				findings = append(findings, checker.Finding{
					Checker:   "psa-restricted-violations",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("%s %q container %q violates PSS Restricted: capabilities.drop does not include ALL.", info.Kind, info.ResourceName, container.Name),
					Remediation: "## Why This Matters\n\n" +
						"By default, containers receive a set of Linux capabilities that may be exploited for privilege escalation. " +
						"Without explicitly dropping ALL capabilities, containers retain permissions like NET_RAW (enabling packet spoofing) and FOWNER (bypassing file permission checks).\n\n" +
						"## How to Fix\n\n" +
						"Drop all capabilities and add back only the specific ones your application requires:\n\n" +
						"```yaml\nsecurityContext:\n  capabilities:\n    drop: [ALL]\n    add: [NET_BIND_SERVICE]  # Only if binding to ports below 1024\n```\n\n" +
						"Most applications work correctly with all capabilities dropped. Test your workload first and add back only capabilities that cause failures.\n\n" +
						"## Learn More\n\n" +
						"See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.7. " +
						"Dropping ALL capabilities is required for PSS Restricted compliance.",
					FieldPath: containerFieldPath(ct, idx, "securityContext.capabilities.drop"),
				})
			}
		})
	}

	return findings, nil
}
