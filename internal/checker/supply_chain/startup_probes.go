package supply_chain

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// StartupProbesChecker detects containers with liveness probes but no startup probe.
// Without a startup probe, slow-starting containers may be killed by the liveness probe
// before they finish initializing.
type StartupProbesChecker struct{}

// Name returns the check ID.
func (c *StartupProbesChecker) Name() string { return "startup-probes" }

// Description returns a human-readable description.
func (c *StartupProbesChecker) Description() string {
	return "Detects containers with liveness probes but no startup probe, which can cause restart loops during slow initialization."
}

// Categories returns the check categories.
func (c *StartupProbesChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySupplyChain}
}

// SupportedModes returns which scan modes this check supports.
func (c *StartupProbesChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *StartupProbesChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the startup probes check.
func (c *StartupProbesChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("startup-probes check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)

	for i := range specs {
		info := &specs[i]
		workload.IterateContainers(info, func(container corev1.Container, ct workload.ContainerType, idx int) {
			// Skip init containers.
			if ct == workload.ContainerTypeInit {
				return
			}

			// Only flag if there's a liveness probe but no startup probe.
			if container.LivenessProbe != nil && container.StartupProbe == nil {
				findings = append(findings, checker.Finding{
					Checker:   "startup-probes",
					Severity:  checker.SeverityInfo,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Container: container.Name,
					Message:   fmt.Sprintf("Container %q has a liveness probe but no startup probe, which can cause restart loops during slow startup.", container.Name),
					Remediation: "## Why This Matters\n\n" +
						"When a container has a liveness probe but no startup probe, the liveness probe starts checking immediately " +
						"after the container starts. If the application takes longer to initialize than the liveness probe's " +
						"initialDelaySeconds + failureThreshold allows, Kubernetes kills and restarts the container, creating " +
						"an infinite restart loop (CrashLoopBackOff).\n\n" +
						"## How to Fix\n\n" +
						"Add a startup probe that gives the container enough time to initialize:\n\n" +
						"```yaml\ncontainers:\n  - name: app\n    startupProbe:\n      httpGet:\n        path: /healthz\n        port: 8080\n      failureThreshold: 30     # 30 x 10s = 5 minutes to start\n      periodSeconds: 10\n```\n\n" +
						"The liveness probe is disabled until the startup probe succeeds, giving slow-starting applications the time they need.\n\n" +
						"## Learn More\n\n" +
						"See the Kubernetes startup probe documentation. This is especially important for Java/JVM applications, " +
						"containers loading large ML models, or services that run database migrations on startup.",
					FieldPath: containerFieldPath(ct, idx, "startupProbe"),
				})
			}
		})
	}

	return findings, nil
}
