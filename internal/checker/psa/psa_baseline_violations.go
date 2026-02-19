package psa

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// BaselineViolationsChecker detects workloads that violate the Pod Security
// Standards (PSS) Baseline profile. The Baseline profile targets ease of
// adoption for common containerized workloads while preventing known privilege
// escalations. Violations include hostNetwork, hostPID, hostIPC, privileged
// containers, and dangerous capability additions (ALL, SYS_ADMIN).
type BaselineViolationsChecker struct{}

// Name returns the kebab-case check ID.
func (c *BaselineViolationsChecker) Name() string { return "psa-baseline-violations" }

// Description returns a human-readable description.
func (c *BaselineViolationsChecker) Description() string {
	return "Detects workloads violating the PSS Baseline profile (hostNetwork, hostPID, hostIPC, privileged, dangerous capabilities)."
}

// Categories returns the check categories.
func (c *BaselineViolationsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryPSS}
}

// SupportedModes returns which scan modes this check supports.
func (c *BaselineViolationsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *BaselineViolationsChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// dangerousBaselineCaps are capabilities that violate the PSS Baseline profile.
var dangerousBaselineCaps = map[corev1.Capability]bool{
	"ALL":       true,
	"SYS_ADMIN": true,
}

// Run executes the PSS Baseline violations check against all workloads in the cache.
func (c *BaselineViolationsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("psa-baseline-violations check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		// Check pod-level security context fields.
		if info.Spec.HostNetwork {
			findings = append(findings, checker.Finding{
				Checker:   "psa-baseline-violations",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q violates PSS Baseline: hostNetwork is true.", info.Kind, info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"hostNetwork gives the pod direct access to the node's network interfaces, allowing it to sniff traffic, bind to any port, and bypass NetworkPolicies entirely. " +
					"This is one of the most dangerous pod security violations as it breaks network isolation.\n\n" +
					"## How to Fix\n\n" +
					"Remove or set `hostNetwork` to false in the pod spec:\n\n" +
					"```yaml\nspec:\n  hostNetwork: false\n```\n\n" +
					"If specific ports must be accessible on the node, use `hostPort` on individual containers with restricted port ranges instead of full host network access.\n\n" +
					"## Learn More\n\n" +
					"See the Pod Security Standards Baseline profile documentation. " +
					"CIS Kubernetes Benchmark 5.2.4 requires that hostNetwork is not allowed in pod security policies.",
				FieldPath: ".spec.hostNetwork",
			})
		}

		if info.Spec.HostPID {
			findings = append(findings, checker.Finding{
				Checker:   "psa-baseline-violations",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q violates PSS Baseline: hostPID is true.", info.Kind, info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"hostPID shares the host's process ID namespace with the pod, allowing containers to see and send signals to all host processes. " +
					"An attacker can use this to inspect process environments (which may contain secrets), kill critical system processes, or escalate privileges via /proc.\n\n" +
					"## How to Fix\n\n" +
					"Remove or set `hostPID` to false in the pod spec:\n\n" +
					"```yaml\nspec:\n  hostPID: false\n```\n\n" +
					"Most workloads have no legitimate need for host PID namespace access. If process visibility is needed, consider using dedicated monitoring tools with minimal privileges.\n\n" +
					"## Learn More\n\n" +
					"See the Pod Security Standards Baseline profile and CIS Kubernetes Benchmark 5.2.2. " +
					"Host PID namespace sharing is a well-known container escape vector.",
				FieldPath: ".spec.hostPID",
			})
		}

		if info.Spec.HostIPC {
			findings = append(findings, checker.Finding{
				Checker:   "psa-baseline-violations",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q violates PSS Baseline: hostIPC is true.", info.Kind, info.ResourceName),
				Remediation: "## Why This Matters\n\n" +
					"hostIPC shares the host's IPC namespace with the pod, allowing containers to access shared memory segments, semaphores, and message queues used by host processes. " +
					"An attacker can read sensitive data from shared memory or interfere with host process communication.\n\n" +
					"## How to Fix\n\n" +
					"Remove or set `hostIPC` to false in the pod spec:\n\n" +
					"```yaml\nspec:\n  hostIPC: false\n```\n\n" +
					"Most workloads have no legitimate need for host IPC namespace access. If inter-process communication is required, use Kubernetes-native mechanisms like shared volumes.\n\n" +
					"## Learn More\n\n" +
					"See the Pod Security Standards Baseline profile and CIS Kubernetes Benchmark 5.2.3. " +
					"Host IPC namespace sharing can expose sensitive data in shared memory segments.",
				FieldPath: ".spec.hostIPC",
			})
		}

		// Check container-level fields.
		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			sc := container.SecurityContext

			// Check privileged.
			if sc != nil && sc.Privileged != nil && *sc.Privileged {
				findings = append(findings, checker.Finding{
					Checker:   "psa-baseline-violations",
					Severity:  checker.SeverityHigh,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("%s %q container %q violates PSS Baseline: privileged is true.", info.Kind, info.ResourceName, container.Name),
					Remediation: "## Why This Matters\n\n" +
						"Privileged containers run with all Linux capabilities, have access to all host devices, and can modify kernel parameters. " +
						"This is equivalent to root access on the node and trivially allows container escape, making it the most severe pod security violation.\n\n" +
						"## How to Fix\n\n" +
						"Disable privileged mode and grant only the specific capabilities the container needs:\n\n" +
						"```yaml\nsecurityContext:\n  privileged: false\n  capabilities:\n    drop: [ALL]\n    add: [NET_BIND_SERVICE]  # Only specific required caps\n```\n\n" +
						"Audit which capabilities are actually needed by testing the application with all capabilities dropped, then adding back only those that are required.\n\n" +
						"## Learn More\n\n" +
						"See the Pod Security Standards Baseline profile and CIS Kubernetes Benchmark 5.2.1. " +
						"Privileged containers should never be used in production workloads.",
					FieldPath: containerFieldPath(ct, idx, "securityContext.privileged"),
				})
			}

			// Check dangerous capabilities.
			if sc != nil && sc.Capabilities != nil {
				for _, cap := range sc.Capabilities.Add {
					if dangerousBaselineCaps[cap] {
						findings = append(findings, checker.Finding{
							Checker:   "psa-baseline-violations",
							Severity:  checker.SeverityHigh,
							Resource:  info.ResourceName,
							Namespace: info.Namespace,
							Kind:      info.Kind,
							Container: container.Name,
							Message:   fmt.Sprintf("%s %q container %q violates PSS Baseline: adds dangerous capability %q.", info.Kind, info.ResourceName, container.Name, cap),
							Remediation: "## Why This Matters\n\n" +
								"Adding ALL or SYS_ADMIN capabilities grants the container near-root privileges on the host. " +
								"SYS_ADMIN alone enables mounting filesystems, loading kernel modules, and other operations that can lead to full container escape.\n\n" +
								"## How to Fix\n\n" +
								"Drop all capabilities and add back only the specific ones your application requires:\n\n" +
								"```yaml\nsecurityContext:\n  capabilities:\n    drop: [ALL]\n    add: [NET_BIND_SERVICE]  # Only what is truly needed\n```\n\n" +
								"Test your application with all capabilities dropped first, then add back only those that cause failures.\n\n" +
								"## Learn More\n\n" +
								"See the Pod Security Standards Baseline profile and the capabilities(7) man page for the full list of Linux capabilities. " +
								"CIS Kubernetes Benchmark 5.2.7 recommends minimizing the set of added capabilities.",
							FieldPath: containerFieldPath(ct, idx, "securityContext.capabilities.add"),
						})
						break // one finding per container for capabilities
					}
				}
			}
		})
	}

	return findings, nil
}
