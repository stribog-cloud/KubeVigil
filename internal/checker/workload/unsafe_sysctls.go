package workload

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// safeSysctls lists the sysctls that are allowlisted by the kubelet as safe.
// These are namespaced sysctls that only affect the pod, not the host.
var safeSysctls = map[string]bool{
	"kernel.shm_rmid_forced":              true,
	"net.ipv4.ip_local_port_range":        true,
	"net.ipv4.ip_unprivileged_port_start": true,
	"net.ipv4.tcp_syncookies":             true,
	"net.ipv4.ping_group_range":           true,
	"net.ipv4.ip_local_reserved_ports":    true,
}

// UnsafeSysctlsChecker detects pods that configure sysctls outside the kubelet's
// safe allowlist. Unsafe sysctls can affect the host system or other pods on the
// same node, potentially compromising node stability or security.
type UnsafeSysctlsChecker struct{}

// Name returns the kebab-case check ID.
func (c *UnsafeSysctlsChecker) Name() string { return "unsafe-sysctls" }

// Description returns a human-readable description.
func (c *UnsafeSysctlsChecker) Description() string {
	return "Detects pods that configure sysctls outside the kubelet-allowlisted safe set."
}

// Categories returns the check categories.
func (c *UnsafeSysctlsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *UnsafeSysctlsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *UnsafeSysctlsChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the unsafe-sysctls check against all workload resources in the cache.
func (c *UnsafeSysctlsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("unsafe-sysctls check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		if info.Spec.SecurityContext == nil {
			continue
		}

		var unsafeNames []string
		for _, sysctl := range info.Spec.SecurityContext.Sysctls {
			if !safeSysctls[sysctl.Name] {
				unsafeNames = append(unsafeNames, sysctl.Name)
			}
		}

		if len(unsafeNames) == 0 {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:     "unsafe-sysctls",
			Severity:    checker.SeverityHigh,
			Resource:    info.ResourceName,
			Namespace:   info.Namespace,
			Kind:        info.Kind,
			Message:     fmt.Sprintf("Pod configures unsafe sysctls: %s.", strings.Join(unsafeNames, ", ")),
			Remediation: "Remove unsafe sysctls. Only use kubelet-allowlisted safe sysctls.",
			FieldPath:   ".spec.securityContext.sysctls",
		})
	}

	return findings, nil
}
