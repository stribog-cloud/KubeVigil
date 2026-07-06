package rbac

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// csrApprovalResources are resource strings that grant CSR approval/signing capability.
var csrApprovalResources = []string{"certificatesigningrequests/approval", "signers"}

// csrApprovalVerbs are verbs that allow approving a CertificateSigningRequest.
var csrApprovalVerbs = []string{"update", "approve", "*"}

// CSRApprovalChecker detects Roles and ClusterRoles that grant the ability to approve
// CertificateSigningRequests, letting a subject self-approve a CSR and mint a client
// certificate that authenticates as any identity, including system:masters.
type CSRApprovalChecker struct{}

// Name returns the kebab-case check ID.
func (c *CSRApprovalChecker) Name() string { return "rbac-csr-approval" }

// Description returns a human-readable description.
func (c *CSRApprovalChecker) Description() string {
	return "Detects Roles/ClusterRoles that grant CertificateSigningRequest approval, allowing identity impersonation via minted client certs."
}

// Categories returns the check categories.
func (c *CSRApprovalChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryRBAC}
}

// SupportedModes returns which scan modes this check supports.
func (c *CSRApprovalChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CSRApprovalChecker) RequiredResources() []schema.GroupVersionResource {
	return RoleGVRs()
}

// Run executes the CSR approval check against all Roles and ClusterRoles in the cache.
func (c *CSRApprovalChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("rbac-csr-approval check: %w", err)
	}

	roles := ExtractRoles(resources)
	var findings []checker.Finding

	for i := range roles {
		role := &roles[i]
		for ruleIdx, rule := range role.Rules {
			if containsAny(rule.Resources, csrApprovalResources...) && containsAny(rule.Verbs, csrApprovalVerbs...) {
				findings = append(findings, checker.Finding{
					Checker:   "rbac-csr-approval",
					Severity:  checker.SeverityCritical,
					Resource:  role.Name,
					Namespace: role.Namespace,
					Kind:      role.Kind,
					Message:   fmt.Sprintf("%s %q grants CertificateSigningRequest approval, allowing a subject to self-approve a CSR and mint any identity.", role.Kind, role.Name),
					Remediation: "## Why This Matters\n\n" +
						"Approving a CertificateSigningRequest mints a signed client certificate for whatever identity the " +
						"CSR requests — including `system:masters` or any other cluster identity. A subject that can both " +
						"submit and approve CSRs (or approve any signer) can escalate to full cluster-admin without ever " +
						"holding that privilege directly.\n\n" +
						"## How to Fix\n\n" +
						"Remove approval/signer permissions and restrict CSR access to read-only:\n\n" +
						"```yaml\nrules:\n  - apiGroups: [\"certificates.k8s.io\"]\n    resources: [\"certificatesigningrequests\"]\n    verbs: [\"get\", \"list\", \"watch\"]  # No approval\n  # Do NOT include:\n  # resources: [\"certificatesigningrequests/approval\", \"signers\"]\n  #   verbs: [\"update\", \"approve\"]\n```\n\n" +
						"Restrict CSR approval to a small, audited set of cluster administrators, and require manual " +
						"review of every signer-scoped approval grant.\n\n" +
						"## Learn More\n\n" +
						"See MITRE ATT&CK technique T1078 (Valid Accounts) and the NSA/CISA Kubernetes Hardening Guide " +
						"section 3.1 on restrictive RBAC policies.",
					FieldPath: fmt.Sprintf(".rules[%d].resources", ruleIdx),
				})
				break // one finding per role
			}
		}
	}

	return findings, nil
}
