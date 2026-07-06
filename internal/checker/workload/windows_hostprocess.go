package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// WindowsHostProcessChecker detects containers or pods with
// securityContext.windowsOptions.hostProcess: true. This is the Windows-node
// analog of Linux privileged: true — the container runs with full access to
// the Windows host's filesystem, registry, and other processes.
type WindowsHostProcessChecker struct{}

// Name returns the kebab-case check ID.
func (c *WindowsHostProcessChecker) Name() string { return "windows-hostprocess" }

// Description returns a human-readable description.
func (c *WindowsHostProcessChecker) Description() string {
	return "Detects containers running as Windows HostProcess containers, granting full access to the Windows host."
}

// Categories returns the check categories.
func (c *WindowsHostProcessChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *WindowsHostProcessChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *WindowsHostProcessChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the windows-hostprocess check against all workload resources in the cache.
func (c *WindowsHostProcessChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("windows-hostprocess check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		podLevelHostProcess := false
		if info.Spec.SecurityContext != nil &&
			info.Spec.SecurityContext.WindowsOptions != nil &&
			info.Spec.SecurityContext.WindowsOptions.HostProcess != nil {
			podLevelHostProcess = *info.Spec.SecurityContext.WindowsOptions.HostProcess
		}

		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			effective := podLevelHostProcess
			fieldPath := ".spec.securityContext.windowsOptions.hostProcess"

			if container.SecurityContext != nil &&
				container.SecurityContext.WindowsOptions != nil &&
				container.SecurityContext.WindowsOptions.HostProcess != nil {
				effective = *container.SecurityContext.WindowsOptions.HostProcess
				fieldPath = containerFieldPath(ct, idx, "securityContext.windowsOptions.hostProcess")
			}

			if !effective {
				return
			}

			findings = append(findings, checker.Finding{
				Checker:   "windows-hostprocess",
				Severity:  checker.SeverityCritical,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q runs as a Windows HostProcess container, granting full access to the host.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"A HostProcess container runs directly on the Windows host rather than inside an isolated container boundary. " +
					"It has full access to the host's filesystem, registry, and can interact with other processes on the node — " +
					"the Windows-node equivalent of a Linux privileged container. An attacker who compromises a HostProcess " +
					"container immediately has host-level access.\n\n" +
					"## How to Fix\n\n" +
					"Set hostProcess to false in the container's (or pod's) securityContext.windowsOptions:\n\n" +
					"```yaml\nsecurityContext:\n  windowsOptions:\n    hostProcess: false\n```\n\n" +
					"HostProcess containers should only be used for known, audited Windows system components (e.g., CNI plugins, " +
					"node-level agents) that genuinely require host access, and should run in a dedicated, tightly scoped namespace.\n\n" +
					"## Learn More\n\n" +
					"This check aligns with MITRE ATT&CK T1611 (Escape to Host) and NSA/CISA Kubernetes Hardening Guidance 1.1 " +
					"(minimize container host access). See the Kubernetes documentation on Windows HostProcess Pods.",
				FieldPath:    fieldPath,
				CurrentValue: true,
				DesiredValue: false,
				FixHint: &checker.FixHint{
					Safety:      checker.FixSafe,
					Description: "Disables Windows HostProcess mode.",
					Impact:      "None — containers should never run as HostProcess unless they are known Windows system components.",
					Operation:   checker.FixOpSet,
				},
			})
		})
	}

	return findings, nil
}
