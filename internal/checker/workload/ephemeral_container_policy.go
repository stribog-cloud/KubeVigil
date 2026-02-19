package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// EphemeralContainerPolicyChecker detects ephemeral containers without adequate
// security restrictions. Ephemeral containers are added to running pods for
// debugging and should still follow security best practices.
type EphemeralContainerPolicyChecker struct{}

// Name returns the kebab-case check ID.
func (c *EphemeralContainerPolicyChecker) Name() string { return "ephemeral-container-policy" }

// Description returns a human-readable description.
func (c *EphemeralContainerPolicyChecker) Description() string {
	return "Detects ephemeral containers without security restrictions such as runAsNonRoot and allowPrivilegeEscalation."
}

// Categories returns the check categories.
func (c *EphemeralContainerPolicyChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryLifecycle}
}

// SupportedModes returns which scan modes this check supports.
func (c *EphemeralContainerPolicyChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EphemeralContainerPolicyChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the ephemeral-container-policy check against all workload resources in the cache.
func (c *EphemeralContainerPolicyChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ephemeral-container-policy check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		for j := range info.Spec.EphemeralContainers {
			ec := &info.Spec.EphemeralContainers[j]

			if isEphemeralContainerSecure(ec) {
				continue
			}

			fieldPath := fmt.Sprintf(".spec.ephemeralContainers[%d].securityContext", j)

			findings = append(findings, checker.Finding{
				Checker:   "ephemeral-container-policy",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Container: ec.Name,
				Message:   fmt.Sprintf("Ephemeral container %q lacks adequate security restrictions.", ec.Name),
				Remediation: "## Why This Matters\n\n" +
					"Ephemeral containers are added to running pods for debugging via `kubectl debug`. Without security restrictions, " +
					"they can run as root with full capabilities, effectively creating a privileged backdoor into the pod. An attacker " +
					"with `kubectl debug` access could bypass all security controls on the original containers.\n\n" +
					"## How to Fix\n\n" +
					"Apply the same security context standards to ephemeral containers as regular containers:\n\n" +
					"```yaml\nephemeralContainers:\n  - name: debug\n    securityContext:\n      runAsNonRoot: true\n      allowPrivilegeEscalation: false\n      capabilities:\n        drop: [\"ALL\"]\n```\n\n" +
					"Enforce these standards cluster-wide using Pod Security Admission policies at the namespace level, " +
					"which apply equally to ephemeral containers.\n\n" +
					"## Learn More\n\n" +
					"Pod Security Admission enforces the same security profile on ephemeral containers as regular containers. " +
					"Combine RBAC restrictions on `kubectl debug` with security context enforcement for defense in depth.",
				FieldPath: fieldPath,
			})
		}
	}

	return findings, nil
}

// isEphemeralContainerSecure returns true if the ephemeral container has minimum
// security restrictions: securityContext is present, privileged is not true,
// allowPrivilegeEscalation is false, and runAsNonRoot is true.
func isEphemeralContainerSecure(ec *corev1.EphemeralContainer) bool {
	sc := ec.SecurityContext
	if sc == nil {
		return false
	}
	if sc.Privileged != nil && *sc.Privileged {
		return false
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		return false
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		return false
	}
	return true
}
