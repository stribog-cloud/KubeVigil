package rbac

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// SubjectExternalChecker detects bindings that reference external User subjects,
// which may become stale when users leave the organization or change roles.
type SubjectExternalChecker struct{}

// Name returns the kebab-case check ID.
func (c *SubjectExternalChecker) Name() string { return "rbac-subject-external" }

// Description returns a human-readable description.
func (c *SubjectExternalChecker) Description() string {
	return "Detects bindings referencing external User subjects that may become stale."
}

// Categories returns the check categories.
func (c *SubjectExternalChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *SubjectExternalChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *SubjectExternalChecker) RequiredResources() []schema.GroupVersionResource {
	return BindingGVRs()
}

// Run executes the external subject check against all bindings in the cache.
func (c *SubjectExternalChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-subject-external check: %w", err)
	}

	bindings := ExtractBindings(resources)
	var findings []checker.Finding

	for i := range bindings {
		b := &bindings[i]
		for _, sub := range b.Subjects {
			if sub.Kind == "User" && !strings.HasPrefix(sub.Name, "system:") {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-subject-external",
					Severity:  checker.SeverityLow,
					Resource:  b.Name,
					Namespace: b.Namespace,
					Kind:      b.Kind,
					Message:   fmt.Sprintf("%s %q references external user %q. External user bindings may become stale.", b.Kind, b.Name, sub.Name),
					Remediation: "## Why This Matters\n\n" +
						"Individual User subjects in RBAC bindings reference external identities (e.g., from an OIDC provider " +
						"or client certificates). When users leave the organization or change roles, these bindings become " +
						"orphaned, granting access to identities that should no longer have it. Unlike groups, user bindings " +
						"cannot be centrally managed through an identity provider.\n\n" +
						"## How to Fix\n\n" +
						"Replace individual User subjects with Group subjects managed by your identity provider:\n\n" +
						"```yaml\nsubjects:\n  - kind: Group\n    name: platform-engineers          # Managed by IdP\n    apiGroup: rbac.authorization.k8s.io\n  # Avoid:\n  # - kind: User\n  #   name: jane@example.com\n```\n\n" +
						"If individual user bindings are necessary, implement an automated process to reconcile " +
						"RBAC bindings against your identity provider directory.\n\n" +
						"## Learn More\n\n" +
						"See the Kubernetes authentication documentation on OIDC integration and CIS Kubernetes " +
						"Benchmark section 5.1 for RBAC best practices on subject management.",
					FieldPath: ".subjects",
				})
			}
		}
	}

	return findings, nil
}
