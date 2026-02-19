package psa

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// LabelsMissingChecker detects namespaces that lack PSA enforcement labels.
// Without pod-security.kubernetes.io/enforce labels, the namespace has no
// Pod Security Admission enforcement, allowing any pod configuration.
type LabelsMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *LabelsMissingChecker) Name() string { return "psa-labels-missing" }

// Description returns a human-readable description.
func (c *LabelsMissingChecker) Description() string {
	return "Detects namespaces missing PSA enforcement labels, leaving pod security unenforced."
}

// Categories returns the check categories.
func (c *LabelsMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryPSS}
}

// SupportedModes returns which scan modes this check supports.
func (c *LabelsMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *LabelsMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NamespaceGVR}
}

// Run executes the PSA labels missing check against all namespaces in the cache.
func (c *LabelsMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("psa-labels-missing check: %w", err)
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
		if _, ok := labels[psaEnforce]; !ok {
			findings = append(findings, checker.Finding{
				Checker:   "psa-labels-missing",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: name,
				Kind:      "Namespace",
				Message:   fmt.Sprintf("Namespace %q is missing the %s label; pod security is not enforced.", name, psaEnforce),
				Remediation: fmt.Sprintf(
					"## Why This Matters\n\n"+
						"Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. "+
						"This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.\n\n"+
						"## How to Fix\n\n"+
						"Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:\n\n"+
						"```yaml\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n    pod-security.kubernetes.io/enforce: baseline\n    pod-security.kubernetes.io/audit: restricted\n    pod-security.kubernetes.io/warn: restricted\n```\n\n"+
						"Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.\n\n"+
						"## Learn More\n\n"+
						"See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. "+
						"The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.", name),
				FieldPath: ".metadata.labels",
			})
		}
	}

	return findings, nil
}
