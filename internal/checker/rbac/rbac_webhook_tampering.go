package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// webhookConfigResources are resources for admission webhook configuration objects.
var webhookConfigResources = []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}

// webhookTamperVerbs are verbs that let a subject disable or weaken an admission webhook.
var webhookTamperVerbs = []string{"update", "patch", "delete", "deletecollection", "*"}

// WebhookTamperingChecker detects Roles and ClusterRoles that grant update/patch/delete access
// to ValidatingWebhookConfiguration or MutatingWebhookConfiguration objects, letting a subject
// disable or weaken cluster-wide security admission control.
type WebhookTamperingChecker struct{}

// Name returns the kebab-case check ID.
func (c *WebhookTamperingChecker) Name() string { return "rbac-webhook-tampering" }

// Description returns a human-readable description.
func (c *WebhookTamperingChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant update/patch/delete access to admission webhook configurations."
}

// Categories returns the check categories.
func (c *WebhookTamperingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *WebhookTamperingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *WebhookTamperingChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the webhook tampering check against all Roles and ClusterRoles in the cache.
func (c *WebhookTamperingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-webhook-tampering check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsAny(rule.Resources, webhookConfigResources...) && containsAny(rule.Verbs, webhookTamperVerbs...) {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-webhook-tampering",
					Severity:  checker.SeverityHigh,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q can modify or delete admission webhook configurations, allowing cluster-wide security controls to be disabled.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"ValidatingWebhookConfiguration and MutatingWebhookConfiguration objects enforce cluster-wide " +
						"admission control (e.g., OPA Gatekeeper, Kyverno, custom policy engines). A subject that can " +
						"update, patch, or delete these objects can silently disable or weaken every security policy " +
						"they enforce, opening the door to otherwise-blocked malicious workloads.\n\n" +
						"## How to Fix\n\n" +
						"Restrict access to read-only for these resources:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"admissionregistration.k8s.io\"]\n    resources: [\"validatingwebhookconfigurations\", \"mutatingwebhookconfigurations\"]\n    verbs: [\"get\", \"list\", \"watch\"]  # Read-only\n```\n\n" +
						"Only cluster administrators and the controllers that own a given webhook should be able to " +
						"modify it. Alert on any change to these objects via audit logging.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK technique T1562 (Impair Defenses) and the NSA/CISA Kubernetes Hardening " +
						"Guide section 2.1 on pod security enforcement.",
					FieldPath: fmt.Sprintf(".rules[%d].resources", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
