package crd

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// CertManagerInsecureChecker detects cert-manager Certificates using weak key
// algorithms or excessively long durations.
type CertManagerInsecureChecker struct{}

// Name returns the check ID.
func (c *CertManagerInsecureChecker) Name() string { return "cert-manager-insecure" }

// Description returns a human-readable description.
func (c *CertManagerInsecureChecker) Description() string {
	return "Detects cert-manager Certificates using weak key algorithms (RSA < 2048, ECDSA < P256) or excessively long durations."
}

// Categories returns the check categories.
func (c *CertManagerInsecureChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCRD}
}

// SupportedModes returns which scan modes this check supports.
func (c *CertManagerInsecureChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CertManagerInsecureChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CertificateGVR}
}

// Run executes the cert-manager insecure check.
func (c *CertManagerInsecureChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cert-manager-insecure check: %w", err)
	}

	certs := resources.List(CertificateGVR)

	for _, cert := range certs {
		name := cert.GetName()
		ns := cert.GetNamespace()

		findings = append(findings, checkKeyAlgorithm(cert, name, ns)...)
		findings = append(findings, checkDuration(cert, name, ns)...)
	}

	return findings, nil
}

// checkKeyAlgorithm flags weak key configurations.
func checkKeyAlgorithm(cert unstructured.Unstructured, name, ns string) []checker.Finding {
	algo, _, _ := unstructured.NestedString(cert.Object, "spec", "privateKey", "algorithm")
	size, found, _ := unstructured.NestedInt64(cert.Object, "spec", "privateKey", "size")

	// Also check float64 path since JSON numbers may be float.
	if !found {
		sizeF, fFound, _ := unstructured.NestedFloat64(cert.Object, "spec", "privateKey", "size")
		if fFound {
			size = int64(sizeF)
			found = true
		}
	}

	algoUpper := strings.ToUpper(algo)

	var findings []checker.Finding

	if algoUpper == "RSA" && found && size < 2048 {
		findings = append(findings, checker.Finding{
			Checker:   "cert-manager-insecure",
			Severity:  checker.SeverityMedium,
			Resource:  name,
			Namespace: ns,
			Kind:      "Certificate",
			Message:   fmt.Sprintf("Certificate %q uses RSA key with size %d (minimum recommended: 2048).", name, size),
			Remediation: "## Why This Matters\n\n" +
				"RSA keys smaller than 2048 bits are considered cryptographically weak by NIST and industry standards. " +
				"They can be factored with modern hardware, allowing attackers to forge certificates and intercept encrypted traffic.\n\n" +
				"## How to Fix\n\n" +
				"Increase the RSA key size to at least 2048 bits (4096 recommended):\n\n" +
				"```yaml\nspec:\n  privateKey:\n    algorithm: RSA\n    size: 4096                    # Minimum 2048, prefer 4096\n    rotationPolicy: Always        # Rotate key on each renewal\n```\n\n" +
				"For better performance with equivalent security, consider migrating to ECDSA P-256 which uses smaller keys and faster operations.\n\n" +
				"## Learn More\n\n" +
				"NIST SP 800-57 recommends a minimum of 2048-bit RSA keys. " +
				"See https://cert-manager.io/docs/usage/certificate/#creating-certificate-resources for cert-manager key configuration options.",
			FieldPath: ".spec.privateKey.size",
		})
	}

	if algoUpper == "ECDSA" && found && size < 256 {
		findings = append(findings, checker.Finding{
			Checker:   "cert-manager-insecure",
			Severity:  checker.SeverityMedium,
			Resource:  name,
			Namespace: ns,
			Kind:      "Certificate",
			Message:   fmt.Sprintf("Certificate %q uses ECDSA key with size %d (minimum recommended: 256/P-256).", name, size),
			Remediation: "## Why This Matters\n\n" +
				"ECDSA keys smaller than P-256 (256-bit) provide less than 128-bit security equivalent, which falls below the minimum " +
				"recommended by NIST and major browser root programs. Weak elliptic curves are vulnerable to cryptanalytic attacks.\n\n" +
				"## How to Fix\n\n" +
				"Use P-256 (minimum) or P-384 for stronger security:\n\n" +
				"```yaml\nspec:\n  privateKey:\n    algorithm: ECDSA\n    size: 256                     # P-256 (128-bit security)\n    rotationPolicy: Always        # Rotate key on each renewal\n```\n\n" +
				"P-256 is recommended for most use cases. Use P-384 only when required by compliance or government standards.\n\n" +
				"## Learn More\n\n" +
				"NIST SP 800-186 recommends P-256 as the minimum ECDSA curve. " +
				"See https://cert-manager.io/docs/usage/certificate/#creating-certificate-resources for supported key algorithms and sizes.",
			FieldPath: ".spec.privateKey.size",
		})
	}

	return findings
}

// checkDuration flags excessively long certificate durations (> 1 year).
func checkDuration(cert unstructured.Unstructured, name, ns string) []checker.Finding {
	durationStr, found, _ := unstructured.NestedString(cert.Object, "spec", "duration")
	if !found || durationStr == "" {
		return nil
	}

	// cert-manager uses Go duration strings like "8760h" (1 year) or "2160h" (90 days).
	// We flag durations longer than 1 year (8760h).
	hours := parseCertDurationHours(durationStr)
	if hours <= 8760 { // 1 year
		return nil
	}

	return []checker.Finding{{
		Checker:   "cert-manager-insecure",
		Severity:  checker.SeverityMedium,
		Resource:  name,
		Namespace: ns,
		Kind:      "Certificate",
		Message:   fmt.Sprintf("Certificate %q has an excessively long duration (%s, > 1 year).", name, durationStr),
		Remediation: "## Why This Matters\n\n" +
			"Certificate durations longer than one year increase the window of exposure if a private key is compromised. " +
			"An attacker with a stolen key can impersonate the service for the entire remaining certificate lifetime, and revocation mechanisms (CRL/OCSP) are unreliable.\n\n" +
			"## How to Fix\n\n" +
			"Reduce the certificate duration and configure automatic renewal:\n\n" +
			"```yaml\nspec:\n  duration: 2160h               # 90 days\n  renewBefore: 720h             # Renew 30 days before expiry\n  privateKey:\n    rotationPolicy: Always      # New key on each renewal\n```\n\n" +
			"Short-lived certificates (90 days or less) limit blast radius from key compromise and align with industry trends like Let's Encrypt's 90-day default.\n\n" +
			"## Learn More\n\n" +
			"CA/Browser Forum Baseline Requirements cap public TLS certificates at 398 days. " +
			"See https://cert-manager.io/docs/usage/certificate/#renewal for configuring duration and renewal timing.",
		FieldPath: ".spec.duration",
	}}
}

// parseCertDurationHours parses a Go-style duration string and returns the total hours.
// Returns 0 if parsing fails.
func parseCertDurationHours(s string) float64 {
	// Simple parser: cert-manager typically uses "Xh" format.
	var hours float64
	_, err := fmt.Sscanf(s, "%fh", &hours)
	if err != nil {
		return 0
	}
	return hours
}
