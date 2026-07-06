package supply_chain

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// LifecycleHooksChecker detects containers with preStop hooks that make external
// network calls, which could be used for data exfiltration on termination.
type LifecycleHooksChecker struct{}

// Name returns the check ID.
func (c *LifecycleHooksChecker) Name() string { return "lifecycle-hooks" }

// Description returns a human-readable description.
func (c *LifecycleHooksChecker) Description() string {
	return "Detects containers with preStop hooks making external network calls, which could enable data exfiltration on pod termination."
}

// Categories returns the check categories.
func (c *LifecycleHooksChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySupplyChain}
}

// SupportedModes returns which scan modes this check supports.
func (c *LifecycleHooksChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *LifecycleHooksChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// networkIndicators are substrings that suggest a network call in a hook
// command. This is a best-effort heuristic, NOT a security boundary: substring
// matching cannot catch every exfiltration technique (a determined author can
// quote-split `c'u'rl`, use a different tool, or open a raw socket), and it is
// meant to surface the common, honest cases — a postStart hook phoning home —
// for review, not to prove their absence. The list is deliberately broad.
var networkIndicators = []string{
	// Common HTTP clients and URL schemes.
	"curl", "wget", "http://", "https://", "ftp://",
	// Netcat and friends.
	"nc ", "ncat", "netcat",
	// Other network-capable tools and shell primitives.
	"socat", "openssl s_client", "/dev/tcp/", "/dev/udp/",
	"telnet", "ssh ", "scp ", "python -m http", "wget2",
}

// Run executes the lifecycle hooks check.
func (c *LifecycleHooksChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("lifecycle-hooks check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)

	for i := range specs {
		info := &specs[i]
		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			if container.Lifecycle == nil || container.Lifecycle.PreStop == nil {
				return
			}

			hook := container.Lifecycle.PreStop

			// Check exec commands for network indicators.
			if hook.Exec != nil {
				cmd := strings.Join(hook.Exec.Command, " ")
				cmdLower := strings.ToLower(cmd)
				for _, indicator := range networkIndicators {
					if strings.Contains(cmdLower, indicator) {
						findings = append(findings, checker.Finding{
							Checker:   "lifecycle-hooks",
							Severity:  checker.SeverityLow,
							Resource:  info.ResourceName,
							Namespace: info.Namespace,
							Kind:      info.Kind,
							Container: container.Name,
							Message:   fmt.Sprintf("Container %q has a preStop hook with potential network call: %q.", container.Name, cmd),
							Remediation: "## Why This Matters\n\n" +
								"PreStop hooks that make network calls (curl, wget, HTTP requests) can be exploited for data exfiltration " +
								"during pod termination. An attacker who modifies a deployment can add a preStop hook that sends sensitive " +
								"data to an external server every time a pod is terminated, scaled down, or restarted.\n\n" +
								"## How to Fix\n\n" +
								"Replace network-calling preStop hooks with local-only cleanup operations:\n\n" +
								"```yaml\nlifecycle:\n  preStop:\n    exec:\n      command:\n        - /bin/sh\n        - -c\n        - \"kill -SIGTERM 1 && sleep 5\"  # Graceful local shutdown\n```\n\n" +
								"If external notification is truly required, use a sidecar or controller pattern with egress network policies restricting the destination.\n\n" +
								"## Learn More\n\n" +
								"See MITRE ATT&CK T1020 (Automated Exfiltration) for data exfiltration techniques. " +
								"Network policies should restrict egress for pods that do not need external access.",
							FieldPath: containerFieldPath(ct, idx, "lifecycle.preStop.exec"),
						})
						break
					}
				}
			}

			// HTTPGet hooks always make network calls.
			if hook.HTTPGet != nil {
				findings = append(findings, checker.Finding{
					Checker:   "lifecycle-hooks",
					Severity:  checker.SeverityLow,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("Container %q has a preStop hook making an HTTP request.", container.Name),
					Remediation: "## Why This Matters\n\n" +
						"PreStop HTTP hooks send HTTP requests every time a pod terminates. A malicious actor can configure these " +
						"hooks to exfiltrate data to external endpoints during normal cluster operations like rolling updates, " +
						"scaling events, or node drains, making the exfiltration difficult to distinguish from normal activity.\n\n" +
						"## How to Fix\n\n" +
						"Replace the HTTP preStop hook with a local exec-based cleanup:\n\n" +
						"```yaml\nlifecycle:\n  preStop:\n    exec:\n      command:\n        - /bin/sh\n        - -c\n        - \"kill -SIGTERM 1 && sleep 5\"  # Graceful local shutdown\n```\n\n" +
						"If HTTP notification is necessary, ensure the endpoint is a cluster-internal service and enforce egress network policies.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK T1020 (Automated Exfiltration) and the Kubernetes Pod Lifecycle documentation. " +
						"Egress network policies are essential for controlling what destinations pods can reach during termination.",
					FieldPath: containerFieldPath(ct, idx, "lifecycle.preStop.httpGet"),
				})
			}
		})
	}

	return findings, nil
}
