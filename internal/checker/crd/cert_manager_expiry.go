package crd

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

const (
	// expiryWarningDays is the number of days before expiry to flag a certificate.
	expiryWarningDays = 14
)

// CertManagerExpiryChecker detects cert-manager Certificates nearing expiry
// or in a failed state.
type CertManagerExpiryChecker struct{}

// Name returns the check ID.
func (c *CertManagerExpiryChecker) Name() string { return "cert-manager-expiry" }

// Description returns a human-readable description.
func (c *CertManagerExpiryChecker) Description() string {
	return "Detects cert-manager Certificates nearing expiry (within 14 days) or in a failed renewal state."
}

// Categories returns the check categories.
func (c *CertManagerExpiryChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCRD}
}

// SupportedModes returns which scan modes this check supports.
func (c *CertManagerExpiryChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CertManagerExpiryChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CertificateGVR}
}

// Run executes the cert-manager expiry check.
func (c *CertManagerExpiryChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cert-manager-expiry check: %w", err)
	}

	certs := resources.List(CertificateGVR)
	now := time.Now()
	warningThreshold := now.Add(time.Duration(expiryWarningDays) * 24 * time.Hour)

	for _, cert := range certs {
		name := cert.GetName()
		ns := cert.GetNamespace()

		// Check for failed conditions.
		if isCertFailed(cert) {
			findings = append(findings, checker.Finding{
				Checker:   "cert-manager-expiry",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: ns,
				Kind:      "Certificate",
				Message:   fmt.Sprintf("Certificate %q is in a failed renewal state.", name),
				Remediation: "## Why This Matters\n\n" +
					"A certificate stuck in a failed renewal state will not be renewed automatically. " +
					"When the current certificate expires, all TLS connections to the affected service will fail, causing downtime and broken client trust.\n\n" +
					"## How to Fix\n\n" +
					"Diagnose the renewal failure and resolve the underlying issue:\n\n" +
					"```yaml\n# Check Certificate status and events:\n# kubectl describe certificate <name> -n <namespace>\n# Check cert-manager controller logs:\n# kubectl logs -n cert-manager deploy/cert-manager\n# Check CertificateRequest and Order resources:\n# kubectl get certificaterequest,order -n <namespace>\n```\n\n" +
					"Common causes include issuer misconfiguration, DNS-01 challenge solver failures, rate limits, or insufficient RBAC permissions.\n\n" +
					"## Learn More\n\n" +
					"See https://cert-manager.io/docs/troubleshooting/ for a systematic troubleshooting guide for failed certificate issuance and renewals.",
			})
			continue
		}

		// Check for approaching expiry via status.notAfter.
		notAfterStr, found, _ := unstructured.NestedString(cert.Object, "status", "notAfter")
		if !found || notAfterStr == "" {
			continue
		}

		notAfter, parseErr := time.Parse(time.RFC3339, notAfterStr)
		if parseErr != nil {
			continue
		}

		if notAfter.Before(now) {
			findings = append(findings, checker.Finding{
				Checker:   "cert-manager-expiry",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: ns,
				Kind:      "Certificate",
				Message:   fmt.Sprintf("Certificate %q has expired (notAfter: %s).", name, notAfter.Format(time.RFC3339)),
				Remediation: "## Why This Matters\n\n" +
					"An expired certificate causes immediate TLS handshake failures for all clients connecting to the affected service. " +
					"Browsers and API clients will reject the connection, resulting in service outages until the certificate is renewed.\n\n" +
					"## How to Fix\n\n" +
					"Trigger an immediate manual renewal to restore service:\n\n" +
					"```yaml\n# Force renewal using cert-manager CLI:\n# kubectl cert-manager renew <certificate-name> -n <namespace>\n\n# Or delete the Secret to trigger re-issuance:\n# kubectl delete secret <cert-secret-name> -n <namespace>\n```\n\n" +
					"After restoring service, investigate why auto-renewal failed: check the Issuer status, challenge solver configuration, and cert-manager controller logs.\n\n" +
					"## Learn More\n\n" +
					"See https://cert-manager.io/docs/usage/certificate/#renewal for how cert-manager handles automatic renewal and how to configure `renewBefore` to prevent future expiry.",
			})
		} else if notAfter.Before(warningThreshold) {
			daysLeft := int(time.Until(notAfter).Hours() / 24)
			findings = append(findings, checker.Finding{
				Checker:   "cert-manager-expiry",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: ns,
				Kind:      "Certificate",
				Message:   fmt.Sprintf("Certificate %q expires in %d days (notAfter: %s).", name, daysLeft, notAfter.Format(time.RFC3339)),
				Remediation: "## Why This Matters\n\n" +
					"A certificate expiring within 14 days suggests that auto-renewal is not progressing. " +
					"If left unresolved, the certificate will expire and cause TLS failures, service outages, and broken trust chains for downstream clients.\n\n" +
					"## How to Fix\n\n" +
					"Verify the auto-renewal configuration and ensure renewals are progressing:\n\n" +
					"```yaml\nspec:\n  duration: 2160h               # 90 days\n  renewBefore: 720h             # Renew 30 days before expiry\n  issuerRef:\n    name: letsencrypt-prod\n    kind: ClusterIssuer\n```\n\n" +
					"Check cert-manager logs (`kubectl logs -n cert-manager deploy/cert-manager`) and the Issuer status for errors blocking renewal.\n\n" +
					"## Learn More\n\n" +
					"See https://cert-manager.io/docs/usage/certificate/#renewal for renewal timing configuration and https://cert-manager.io/docs/troubleshooting/ for diagnosing stalled renewals.",
			})
		}
	}

	return findings, nil
}

// isCertFailed checks if a Certificate has a Failed condition.
func isCertFailed(cert unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(cert.Object, "status", "conditions")
	for _, cond := range conditions {
		cm, ok := cond.(map[string]interface{})
		if !ok {
			continue
		}
		condType, _ := cm["type"].(string)
		status, _ := cm["status"].(string)
		reason, _ := cm["reason"].(string)
		if condType == "Ready" && status == "False" && reason == "Failed" {
			return true
		}
	}
	return false
}
