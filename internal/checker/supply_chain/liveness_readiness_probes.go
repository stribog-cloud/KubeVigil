package supply_chain

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// LivenessReadinessProbesChecker detects containers missing liveness or readiness probes.
type LivenessReadinessProbesChecker struct{}

// Name returns the check ID.
func (c *LivenessReadinessProbesChecker) Name() string { return "liveness-readiness-probes" }

// Description returns a human-readable description.
func (c *LivenessReadinessProbesChecker) Description() string {
	return "Detects containers missing liveness or readiness probes, which are needed for health monitoring and traffic routing."
}

// Categories returns the check categories.
func (c *LivenessReadinessProbesChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySupplyChain}
}

// SupportedModes returns which scan modes this check supports.
func (c *LivenessReadinessProbesChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *LivenessReadinessProbesChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the probes check.
func (c *LivenessReadinessProbesChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("liveness-readiness-probes check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)

	for i := range specs {
		info := &specs[i]
		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			// Skip init containers — probes don't apply to them.
			if ct == workload.ContainerTypeInit {
				return
			}

			if container.LivenessProbe == nil {
				findings = append(findings, checker.Finding{
					Checker:   "liveness-readiness-probes",
					Severity:  checker.SeverityLow,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("Container %q has no liveness probe configured.", container.Name),
					Remediation: "## Why This Matters\n\n" +
						"Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. " +
						"The container continues running and consuming resources while failing to serve traffic. Users experience " +
						"timeouts and errors until someone manually intervenes.\n\n" +
						"## How to Fix\n\n" +
						"Add a liveness probe that checks the container's health:\n\n" +
						"```yaml\ncontainers:\n  - name: app\n    livenessProbe:\n      httpGet:\n        path: /healthz\n        port: 8080\n      initialDelaySeconds: 15\n      periodSeconds: 10\n      failureThreshold: 3\n```\n\n" +
						"Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.\n\n" +
						"## Learn More\n\n" +
						"See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your " +
						"application to start, and consider adding a startupProbe for slow-starting containers.",
					FieldPath: containerFieldPath(ct, idx, "livenessProbe"),
				})
			}

			if container.ReadinessProbe == nil {
				findings = append(findings, checker.Finding{
					Checker:   "liveness-readiness-probes",
					Severity:  checker.SeverityLow,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("Container %q has no readiness probe configured.", container.Name),
					Remediation: "## Why This Matters\n\n" +
						"Without a readiness probe, Kubernetes adds the pod to Service endpoints immediately, routing live traffic " +
						"to containers that may still be initializing or temporarily unable to serve requests. This causes " +
						"user-facing errors, increased latency, and failed requests during deployments and restarts.\n\n" +
						"## How to Fix\n\n" +
						"Add a readiness probe that validates the container can serve traffic:\n\n" +
						"```yaml\ncontainers:\n  - name: app\n    readinessProbe:\n      httpGet:\n        path: /ready\n        port: 8080\n      initialDelaySeconds: 5\n      periodSeconds: 10\n      failureThreshold: 3\n```\n\n" +
						"The readiness endpoint should check downstream dependencies (database, cache) to confirm the container is truly ready.\n\n" +
						"## Learn More\n\n" +
						"See the Kubernetes documentation on container probes. Readiness probes control Service endpoint membership, " +
						"so failing probes remove the pod from load balancing without restarting it.",
					FieldPath: containerFieldPath(ct, idx, "readinessProbe"),
				})
			}
		})
	}

	return findings, nil
}
