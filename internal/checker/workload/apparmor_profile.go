package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// AppArmorProfileChecker detects containers missing an AppArmor profile.
// AppArmor provides mandatory access control that restricts programs' capabilities
// beyond standard Linux permissions. Containers should have an AppArmor profile set.
type AppArmorProfileChecker struct{}

// Name returns the kebab-case check ID.
func (c *AppArmorProfileChecker) Name() string { return "apparmor-profile" }

// Description returns a human-readable description.
func (c *AppArmorProfileChecker) Description() string {
	return "Detects containers missing an AppArmor profile, which leaves them without mandatory access control restrictions."
}

// Categories returns the check categories.
func (c *AppArmorProfileChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *AppArmorProfileChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *AppArmorProfileChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the apparmor-profile check against all workload resources in the cache.
func (c *AppArmorProfileChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("apparmor-profile check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			// Check container-level AppArmorProfile field (K8s 1.30+).
			if container.SecurityContext != nil && container.SecurityContext.AppArmorProfile != nil {
				return // profile is set
			}

			fieldPath := containerFieldPath(ct, idx, "securityContext.appArmorProfile")

			findings = append(findings, checker.Finding{
				Checker:   "apparmor-profile",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q does not have an AppArmor profile set.", container.Name),
				Remediation: "## Why This Matters\n\n" +
					"AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities " +
					"a container process can access. Without an AppArmor profile, the container operates without these restrictions, " +
					"allowing an attacker with code execution to access any file the container user can read and make unrestricted " +
					"network connections.\n\n" +
					"## How to Fix\n\n" +
					"Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):\n\n" +
					"```yaml\nsecurityContext:\n  appArmorProfile:\n    type: RuntimeDefault\n```\n\n" +
					"The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, " +
					"create a custom Localhost profile that only allows the specific file and network access your application needs.\n\n" +
					"## Learn More\n\n" +
					"AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. " +
					"Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}
