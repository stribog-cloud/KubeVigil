package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// PrivilegeEscalationChecker detects containers that do not explicitly disable
// privilege escalation. By default, allowPrivilegeEscalation is true in Kubernetes,
// which permits a process to gain more privileges than its parent.
type PrivilegeEscalationChecker struct{}

// Name returns the kebab-case check ID.
func (c *PrivilegeEscalationChecker) Name() string { return "privilege-escalation" }

// Description returns a human-readable description.
func (c *PrivilegeEscalationChecker) Description() string {
	return "Detects containers missing allowPrivilegeEscalation: false, which permits processes to gain elevated privileges."
}

// Categories returns the check categories.
func (c *PrivilegeEscalationChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *PrivilegeEscalationChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PrivilegeEscalationChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the privilege-escalation check against all workload resources in the cache.
func (c *PrivilegeEscalationChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("privilege-escalation check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if container.SecurityContext != nil &&
				container.SecurityContext.AllowPrivilegeEscalation != nil &&
				!*container.SecurityContext.AllowPrivilegeEscalation {
				return // explicitly set to false — good
			}

			fieldPath := containerFieldPath(ct, idx, "securityContext.allowPrivilegeEscalation")

			findings = append(findings, checker.Finding{
				Checker:   "privilege-escalation",
				Severity:  checker.SeverityHigh,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q does not set allowPrivilegeEscalation to false, permitting privilege escalation.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a " +
					"process gain more permissions than its parent. An attacker can exploit this using setuid binaries already " +
					"present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.\n\n" +
					"## How to Fix\n\n" +
					"Explicitly disable privilege escalation in the container's securityContext:\n\n" +
					"```yaml\nsecurityContext:\n  allowPrivilegeEscalation: false\n  runAsNonRoot: true\n  capabilities:\n    drop: [\"ALL\"]\n```\n\n" +
					"This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. " +
					"The vast majority of application containers do not need privilege escalation.\n\n" +
					"## Learn More\n\n" +
					"This is required by the Pod Security Standards \"Restricted\" profile and CIS Benchmark 5.2.5. " +
					"Disabling privilege escalation is one of the most impactful single-line security improvements you can make.",
				FieldPath:    fieldPath,
				CurrentValue: nil,
				DesiredValue: false,
				FixHint: &checker.FixHint{
					Safety:      checker.FixSafe,
					Description: "Disables privilege escalation.",
					Impact:      "None for standard workloads.",
					Operation:   checker.FixOpSet,
				},
			})
		})
	}

	return findings, nil
}
