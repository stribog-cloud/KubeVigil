package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// CrossNamespaceServiceAccountChecker detects RoleBindings whose subjects reference a
// ServiceAccount in a different namespace than the RoleBinding itself — an unusual
// cross-namespace trust grant that is frequently accidental, since the subject's namespace
// field silently overrides the binding's own namespace.
type CrossNamespaceServiceAccountChecker struct{}

// Name returns the kebab-case check ID.
func (c *CrossNamespaceServiceAccountChecker) Name() string {
	return "rbac-crossnamespace-serviceaccount"
}

// Description returns a human-readable description.
func (c *CrossNamespaceServiceAccountChecker) Description() string {
	return "Detects RoleBindings whose ServiceAccount subjects reference a different namespace than the binding itself."
}

// Categories returns the check categories.
func (c *CrossNamespaceServiceAccountChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *CrossNamespaceServiceAccountChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CrossNamespaceServiceAccountChecker) RequiredResources() []schema.GroupVersionResource {
	return BindingGVRs()
}

// Run executes the cross-namespace ServiceAccount check against all bindings in the cache.
func (c *CrossNamespaceServiceAccountChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-crossnamespace-serviceaccount check: %w", err)
	}

	bindings := ExtractBindings(resources)
	var findings []checker.Finding

	for i := range bindings {
		b := &bindings[i]
		if b.Kind != "RoleBinding" {
			continue // ClusterRoleBinding has no "own namespace" to compare against
		}
		for _, sub := range b.Subjects {
			if sub.Kind != "ServiceAccount" {
				continue
			}
			if sub.Namespace == "" || sub.Namespace == b.Namespace {
				continue
			}
			findings = append(findings, checker.Finding{
				Checker:   "rbac-crossnamespace-serviceaccount",
				Severity:  checker.SeverityMedium,
				Resource:  b.Name,
				Namespace: b.Namespace,
				Kind:      b.Kind,
				Message:   fmt.Sprintf("RoleBinding %q in namespace %q grants access to ServiceAccount %q in a different namespace %q.", b.Name, b.Namespace, sub.Name, sub.Namespace),
				Remediation: "## Why This Matters\n\n" +
					"A RoleBinding's `subjects[].namespace` field silently overrides the binding's own namespace " +
					"for ServiceAccount subjects. This means a RoleBinding in namespace A can grant its permissions " +
					"to a ServiceAccount that lives in namespace B — an unusual cross-namespace trust grant that is " +
					"frequently accidental (a copy-pasted manifest that forgot to update the subject namespace) but " +
					"can also be used deliberately to extend trust across a namespace boundary without review.\n\n" +
					"## How to Fix\n\n" +
					"Verify the cross-namespace grant is intentional. If not, correct the subject's namespace to " +
					"match the binding:\n\n" +
					"```yaml\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: app-binding\n  namespace: ns-a\nsubjects:\n  - kind: ServiceAccount\n    name: app-sa\n    namespace: ns-a    # Matches the binding's own namespace\n```\n\n" +
					"If cross-namespace access is genuinely required, document it explicitly and review it as part " +
					"of your regular RBAC audit process.\n\n" +
					"## Learn More\n\n" +
					"See the NSA/CISA Kubernetes Hardening Guide section 3.1 on RBAC policies and the Kubernetes " +
					"RBAC documentation on RoleBinding subject namespace semantics.",
				FieldPath: ".subjects",
			})
		}
	}

	return findings, nil
}
