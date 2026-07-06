package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ValidatingAdmissionPolicyAuditOnlyChecker detects ValidatingAdmissionPolicyBinding
// resources whose validationActions only audit or warn on violations, never deny.
type ValidatingAdmissionPolicyAuditOnlyChecker struct{}

// Name returns the kebab-case check ID.
func (c *ValidatingAdmissionPolicyAuditOnlyChecker) Name() string {
	return "validatingadmissionpolicy-audit-only"
}

// Description returns a human-readable description.
func (c *ValidatingAdmissionPolicyAuditOnlyChecker) Description() string {
	return "Detects ValidatingAdmissionPolicyBinding resources whose validationActions only audit/warn, never deny, on policy violations."
}

// Categories returns the check categories.
func (c *ValidatingAdmissionPolicyAuditOnlyChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns which scan modes this check supports.
func (c *ValidatingAdmissionPolicyAuditOnlyChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ValidatingAdmissionPolicyAuditOnlyChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ValidatingAdmissionPolicyBindingGVR, ValidatingAdmissionPolicyGVR}
}

// Run executes the validatingadmissionpolicy-audit-only check.
func (c *ValidatingAdmissionPolicyAuditOnlyChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("validatingadmissionpolicy-audit-only check: %w", err)
	}

	// Build a set of known policy names so the finding message can note
	// whether the referenced policy is actually cached.
	policies := resources.List(ValidatingAdmissionPolicyGVR)
	knownPolicies := make(map[string]bool, len(policies))
	for i := range policies {
		knownPolicies[policies[i].GetName()] = true
	}

	bindings := resources.List(ValidatingAdmissionPolicyBindingGVR)
	var findings []checker.Finding

	for i := range bindings {
		obj := &bindings[i]
		name := obj.GetName()

		actions, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "validationActions")
		if containsAction(actions, "Deny") {
			continue
		}

		policyName, _, _ := unstructured.NestedString(obj.Object, "spec", "policyName")
		policyNote := ""
		switch {
		case policyName != "" && knownPolicies[policyName]:
			policyNote = fmt.Sprintf(" (policy %q)", policyName)
		case policyName != "":
			policyNote = fmt.Sprintf(" (policy %q, not found among scanned resources)", policyName)
		}

		findings = append(findings, checker.Finding{
			Checker:  "validatingadmissionpolicy-audit-only",
			Severity: checker.SeverityMedium,
			Resource: name,
			Kind:     obj.GetKind(),
			Message:  fmt.Sprintf("ValidatingAdmissionPolicyBinding %q%s only audits/warns on violations (validationActions: %v); nothing is denied.", name, policyNote, actions),
			Remediation: "## Why This Matters\n\n" +
				"A ValidatingAdmissionPolicyBinding whose `validationActions` contains only `Audit` and/or `Warn` (no `Deny`) evaluates " +
				"the policy on every matching request and records or displays a warning, but never blocks the non-compliant request. " +
				"Teams often assume the policy is enforced simply because it exists and is evaluated -- this is the native VAP " +
				"equivalent of the `psa-mode-audit-only` gap for Pod Security Admission.\n\n" +
				"## How to Fix\n\n" +
				"Add `Deny` to the binding's `validationActions` once you have reviewed the audit/warn logs and confirmed the policy " +
				"does not have false positives:\n\n" +
				"```yaml\napiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicyBinding\nmetadata:\n  name: replica-limit-binding\nspec:\n  policyName: replica-limit-policy\n  validationActions: [\"Deny\"]\n```\n\n" +
				"## Learn More\n\n" +
				"See https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#validationactions " +
				"for the semantics of Deny, Warn, and Audit validation actions.",
			FieldPath:    ".spec.validationActions",
			CurrentValue: actions,
			DesiredValue: []string{"Deny"},
		})
	}

	return findings, nil
}

// containsAction returns true if actions contains the given value.
func containsAction(actions []string, value string) bool {
	for _, a := range actions {
		if a == value {
			return true
		}
	}
	return false
}
