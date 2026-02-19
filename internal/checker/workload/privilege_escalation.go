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
				Checker:     "privilege-escalation",
				Severity:    checker.SeverityHigh,
				Resource:    info.ResourceName,
				Namespace:   info.Namespace,
				Kind:        info.Kind,
				Container:   container.Name,
				Message:     fmt.Sprintf("Container %q does not set allowPrivilegeEscalation to false, permitting privilege escalation.", container.Name),
				Remediation: "Set securityContext.allowPrivilegeEscalation to false.",
				FieldPath:   fieldPath,
			})
		})
	}

	return findings, nil
}
