package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// PrivilegedChecker detects containers running with privileged: true.
// Privileged containers have full access to the host, effectively running
// as root on the node. This is a direct path to cluster compromise.
type PrivilegedChecker struct{}

// Name returns the kebab-case check ID.
func (c *PrivilegedChecker) Name() string { return "privileged" }

// Description returns a human-readable description.
func (c *PrivilegedChecker) Description() string {
	return "Detects containers running with privileged: true, which grants full host access."
}

// Categories returns the check categories.
func (c *PrivilegedChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *PrivilegedChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PrivilegedChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the privileged check against all workload resources in the cache.
func (c *PrivilegedChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("privileged check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if container.SecurityContext == nil {
				return
			}
			if container.SecurityContext.Privileged == nil || !*container.SecurityContext.Privileged {
				return
			}

			fieldPath := containerFieldPath(ct, idx, "securityContext.privileged")

			findings = append(findings, checker.Finding{
				Checker:   "privileged",
				Severity:  checker.SeverityCritical,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q is running in privileged mode, granting full host access.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"A privileged container runs with all Linux capabilities and has direct access to the host's devices, " +
					"filesystems, and kernel. An attacker who compromises a privileged container can immediately escape to the " +
					"host node, access secrets from other pods, and pivot across the entire cluster. This is the single most " +
					"dangerous workload misconfiguration.\n\n" +
					"## How to Fix\n\n" +
					"Set `privileged` to `false` in the container's securityContext:\n\n" +
					"```yaml\nsecurityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop: [\"ALL\"]\n```\n\n" +
					"If your container requires specific host access (e.g., network configuration), grant only the individual " +
					"capabilities it needs via `capabilities.add` instead of enabling full privileged mode.\n\n" +
					"## Learn More\n\n" +
					"This check aligns with CIS Kubernetes Benchmark 5.2.1 and the Pod Security Standards \"Baseline\" profile, " +
					"which both prohibit privileged containers. See the Kubernetes documentation on Pod Security Standards for details.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}

// containerFieldPath builds a JSON-style field path for a container field.
func containerFieldPath(ct ContainerType, idx int, field string) string {
	switch ct {
	case ContainerTypeInit, ContainerTypeSidecar:
		return fmt.Sprintf(".spec.initContainers[%d].%s", idx, field)
	default:
		return fmt.Sprintf(".spec.containers[%d].%s", idx, field)
	}
}
