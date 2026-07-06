package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// dangerousSELinuxTypes lists SELinux types that disable confinement.
var dangerousSELinuxTypes = map[string]bool{
	"spc_t":        true,
	"unconfined_t": true,
}

// SELinuxOptionsChecker detects containers with dangerous SELinux type configurations.
// Running with spc_t or unconfined_t disables SELinux confinement, removing a
// critical layer of mandatory access control.
type SELinuxOptionsChecker struct{}

// Name returns the kebab-case check ID.
func (c *SELinuxOptionsChecker) Name() string { return "selinux-options" }

// Description returns a human-readable description.
func (c *SELinuxOptionsChecker) Description() string {
	return "Detects containers with dangerous SELinux type configurations that disable confinement."
}

// Categories returns the check categories.
func (c *SELinuxOptionsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *SELinuxOptionsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *SELinuxOptionsChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the selinux-options check against all workload resources in the cache.
func (c *SELinuxOptionsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("selinux-options check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			if container.SecurityContext == nil || container.SecurityContext.SELinuxOptions == nil {
				return // no SELinux options — not flagged
			}

			seType := container.SecurityContext.SELinuxOptions.Type
			if !dangerousSELinuxTypes[seType] {
				return // safe or empty type
			}

			fieldPath := containerFieldPath(ct, idx, "securityContext.seLinuxOptions.type")

			findings = append(findings, checker.Finding{
				Checker:   "selinux-options",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: container.Name,
				Message:   fmt.Sprintf("Container %q has dangerous SELinux type %q, which disables SELinux confinement.", container.Name, seType),
				Remediation: "## Why This Matters\n\n" +
					"SELinux types like `spc_t` (super privileged container) and `unconfined_t` completely disable SELinux " +
					"mandatory access control for the container. On RHEL, CentOS, and Fedora nodes where SELinux is enforcing, " +
					"this removes a critical security boundary that prevents containers from accessing host files, devices, and " +
					"other container data even after a compromise.\n\n" +
					"## How to Fix\n\n" +
					"Remove the dangerous SELinux type or use the default confined context:\n\n" +
					"```yaml\nsecurityContext:\n  seLinuxOptions:\n    type: \"\"  # Use default confined context\n  # Or remove seLinuxOptions entirely\n```\n\n" +
					"If your application needs specific SELinux access, create a custom policy rather than disabling confinement " +
					"entirely. Test in a non-production environment first.\n\n" +
					"## Learn More\n\n" +
					"SELinux enforcement is a key defense layer on RHEL-family nodes. The `spc_t` type is equivalent to disabling " +
					"SELinux for that container. Refer to the Kubernetes and OpenShift SELinux documentation.",
				FieldPath: fieldPath,
			})
		})
	}

	return findings, nil
}
