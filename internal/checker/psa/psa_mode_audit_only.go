package psa

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ModeAuditOnlyChecker detects namespaces with PSA labels set to audit or warn
// mode only, without the enforce label. In this configuration, violations are
// logged or shown as warnings but not blocked — pods with security issues can
// still be admitted.
type ModeAuditOnlyChecker struct{}

// Name returns the kebab-case check ID.
func (c *ModeAuditOnlyChecker) Name() string { return "psa-mode-audit-only" }

// Description returns a human-readable description.
func (c *ModeAuditOnlyChecker) Description() string {
	return "Detects namespaces with PSA in audit/warn mode only, without enforce — violations are logged but not blocked."
}

// Categories returns the check categories.
func (c *ModeAuditOnlyChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryPSS}
}

// SupportedModes returns which scan modes this check supports.
func (c *ModeAuditOnlyChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ModeAuditOnlyChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NamespaceGVR}
}

// Run executes the PSA mode audit-only check against all namespaces in the cache.
func (c *ModeAuditOnlyChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("psa-mode-audit-only check: %w", err)
	}

	namespaces := resources.List(NamespaceGVR)
	var findings []checker.Finding

	for i := range namespaces {
		ns := &namespaces[i]
		name := ns.GetName()

		if isSystemNamespace(name) {
			continue
		}

		labels := ns.GetLabels()

		// Only flag namespaces that have audit or warn labels but NOT enforce.
		_, hasEnforce := labels[psaEnforce]
		_, hasAudit := labels[psaAudit]
		_, hasWarn := labels[psaWarn]

		if !hasEnforce && (hasAudit || hasWarn) {
			findings = append(findings, checker.Finding{
				Checker:   "psa-mode-audit-only",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: name,
				Kind:      "Namespace",
				Message:   fmt.Sprintf("Namespace %q has PSA audit/warn labels but no enforce label; violations are logged but not blocked.", name),
				Remediation: "## Why This Matters\n\n" +
					"Audit and warn modes only log violations or show warnings to users -- they do not actually block non-compliant pods from being created. " +
					"Without the `enforce` label, insecure workloads such as privileged containers or root-running pods can still be admitted to the namespace.\n\n" +
					"## How to Fix\n\n" +
					"Add the `enforce` label alongside the existing audit/warn labels to actively block non-compliant pods:\n\n" +
					"```yaml\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: production\n  labels:\n    pod-security.kubernetes.io/enforce: baseline\n    pod-security.kubernetes.io/audit: restricted\n    pod-security.kubernetes.io/warn: restricted\n```\n\n" +
					"Set `enforce` to `baseline` initially and review audit logs for `restricted` violations before upgrading the enforcement level.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes Pod Security Admission documentation on modes (enforce, audit, warn). " +
					"CIS Kubernetes Benchmark 5.2 recommends active enforcement of Pod Security Standards, not just auditing.",
				FieldPath: ".metadata.labels",
			})
		}
	}

	return findings, nil
}
