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

// PostStartHookNetworkCallChecker detects containers with a postStart
// lifecycle hook making a network call. Unlike [LifecycleHooksChecker] (which
// only inspects preStop), a postStart network call fires on every container
// start — including every restart or reschedule — making it a natural place
// to establish beacon/callback behavior at high frequency.
type PostStartHookNetworkCallChecker struct{}

// Name returns the kebab-case check ID.
func (c *PostStartHookNetworkCallChecker) Name() string { return "poststart-hook-network-call" }

// Description returns a human-readable description.
func (c *PostStartHookNetworkCallChecker) Description() string {
	return "Detects containers with a postStart lifecycle hook making a network call (curl/wget/HTTP/nc), a high-frequency beaconing/callback point."
}

// Categories returns the check categories.
func (c *PostStartHookNetworkCallChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySupplyChain}
}

// SupportedModes returns which scan modes this check supports.
func (c *PostStartHookNetworkCallChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PostStartHookNetworkCallChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the poststart-hook-network-call check.
func (c *PostStartHookNetworkCallChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("poststart-hook-network-call check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)

	for i := range specs {
		info := &specs[i]
		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			if container.Lifecycle == nil || container.Lifecycle.PostStart == nil {
				return
			}

			hook := container.Lifecycle.PostStart

			// Check exec commands for network indicators. Reuses the
			// networkIndicators list defined by lifecycle_hooks.go.
			if hook.Exec != nil {
				cmd := strings.Join(hook.Exec.Command, " ")
				cmdLower := strings.ToLower(cmd)
				for _, indicator := range networkIndicators {
					if strings.Contains(cmdLower, indicator) {
						findings = append(findings, checker.Finding{
							Checker:   "poststart-hook-network-call",
							Severity:  checker.SeverityLow,
							Resource:  info.ResourceName,
							Namespace: info.Namespace,
							Kind:      info.Kind,
							Container: container.Name,
							Message:   fmt.Sprintf("Container %q has a postStart hook with potential network call: %q.", container.Name, cmd),
							Remediation: "## Why This Matters\n\n" +
								"PostStart hooks run on **every** container start, including every restart, " +
								"reschedule, or rolling update — far more frequently than a preStop hook. A " +
								"network call here (curl, wget, HTTP request) is a natural place to establish " +
								"beacon or callback (C2) behavior that blends into normal cluster churn.\n\n" +
								"## How to Fix\n\n" +
								"Replace network-calling postStart hooks with local-only initialization:\n\n" +
								"```yaml\nlifecycle:\n  postStart:\n    exec:\n      command:\n        - /bin/sh\n        - -c\n        - \"echo started > /tmp/ready\"  # Local-only signal\n```\n\n" +
								"If external notification is genuinely required, use an init container or sidecar " +
								"pattern with egress network policies restricting the destination.\n\n" +
								"## Learn More\n\n" +
								"See MITRE ATT&CK T1071 (Application Layer Protocol) for command-and-control " +
								"beaconing techniques. Network policies should restrict egress for pods that do " +
								"not need external access.",
							FieldPath: containerFieldPath(ct, idx, "lifecycle.postStart.exec"),
						})
						break
					}
				}
			}

			// HTTPGet hooks always make network calls.
			if hook.HTTPGet != nil {
				findings = append(findings, checker.Finding{
					Checker:   "poststart-hook-network-call",
					Severity:  checker.SeverityLow,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("Container %q has a postStart hook making an HTTP request.", container.Name),
					Remediation: "## Why This Matters\n\n" +
						"PostStart HTTP hooks send a request every time a container starts — including every " +
						"restart, reschedule, or rolling update. An attacker who can influence the deployment " +
						"spec can use this as a high-frequency beacon to an external endpoint, blending into " +
						"normal cluster operations.\n\n" +
						"## How to Fix\n\n" +
						"Replace the HTTP postStart hook with a local exec-based initialization:\n\n" +
						"```yaml\nlifecycle:\n  postStart:\n    exec:\n      command:\n        - /bin/sh\n        - -c\n        - \"echo started > /tmp/ready\"  # Local-only signal\n```\n\n" +
						"If HTTP notification is necessary, ensure the endpoint is a cluster-internal service " +
						"and enforce egress network policies.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK T1071 (Application Layer Protocol) and the Kubernetes Pod Lifecycle " +
						"documentation. Egress network policies are essential for controlling what " +
						"destinations pods can reach on every start.",
					FieldPath: containerFieldPath(ct, idx, "lifecycle.postStart.httpGet"),
				})
			}
		})
	}

	return findings, nil
}
