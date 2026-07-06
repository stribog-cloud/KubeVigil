package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// Minimum key strength thresholds for TLS certificates, mirroring the
// cert-manager-insecure checker's thresholds applied to raw, statically
// created TLS Secrets.
const (
	minTLSRSAKeyBits    = 2048
	minTLSECDSACurveBit = 256
)

// certManagerCertificateNameAnnotation is set by cert-manager on every
// Secret it manages. Those Secrets are already covered by the
// cert-manager-insecure check (which inspects the Certificate spec directly,
// before any renewal has happened), so this check skips them.
const certManagerCertificateNameAnnotation = "cert-manager.io/certificate-name"

// tlsSecretType is the built-in Kubernetes Secret type for TLS certificate/key pairs.
const tlsSecretType = "kubernetes.io/tls" //nolint:gosec // Not a credential; a Kubernetes Secret type constant.

// TLSWeakKeyChecker detects raw kubernetes.io/tls Secrets — not managed by
// cert-manager — whose certificate uses a weak key: RSA smaller than 2048
// bits, or an ECDSA curve weaker than P-256.
type TLSWeakKeyChecker struct{}

// Name returns the kebab-case check ID.
func (c *TLSWeakKeyChecker) Name() string { return "secrets-tls-weak-key" }

// Description returns a human-readable description.
func (c *TLSWeakKeyChecker) Description() string {
	return "Detects raw kubernetes.io/tls Secrets (not managed by cert-manager) whose certificate uses a weak key (RSA < 2048 bits or ECDSA weaker than P-256)."
}

// Categories returns the check categories.
func (c *TLSWeakKeyChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
func (c *TLSWeakKeyChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TLSWeakKeyChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{SecretGVR}
}

// Run executes the secrets-tls-weak-key check against all TLS Secrets in the cache.
func (c *TLSWeakKeyChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-tls-weak-key check: %w", err)
	}

	secrets := cache.List(SecretGVR)
	var findings []checker.Finding

	for i := range secrets {
		obj := &secrets[i]

		secretType, _, _ := unstructuredString(obj.Object, "type")
		if secretType != tlsSecretType {
			continue
		}

		// cert-manager-managed Secrets are covered by cert-manager-insecure,
		// which inspects the Certificate spec rather than the rendered cert.
		if _, managed := obj.GetAnnotations()[certManagerCertificateNameAnnotation]; managed {
			continue
		}

		cert, ok := parseTLSLeafCertificate(obj)
		if !ok {
			continue
		}

		if finding, weak := evaluateTLSKeyStrength(cert, obj); weak {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// parseTLSLeafCertificate extracts and parses the certificate stored in a TLS
// Secret's data["tls.crt"] value. It returns ok=false — rather than an error
// — for any malformed input (missing key, invalid base64, invalid PEM,
// unparsable certificate), since a checker must never fail a scan over a
// single malformed resource.
func parseTLSLeafCertificate(obj *unstructured.Unstructured) (*x509.Certificate, bool) {
	dataRaw, found := obj.Object["data"]
	if !found {
		return nil, false
	}
	dataMap, ok := dataRaw.(map[string]interface{})
	if !ok {
		return nil, false
	}
	encoded, ok := dataMap["tls.crt"].(string)
	if !ok || encoded == "" {
		return nil, false
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}

	block, _ := pem.Decode(decoded)
	if block == nil {
		return nil, false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}

	return cert, true
}

// evaluateTLSKeyStrength inspects the certificate's public key and returns a
// Finding, plus true, if it uses a weak RSA (< 2048 bits) or ECDSA (weaker
// than P-256) key. Any other key algorithm (Ed25519, DSA, etc.) is not
// covered by this check and returns false.
func evaluateTLSKeyStrength(cert *x509.Certificate, obj *unstructured.Unstructured) (checker.Finding, bool) {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	kind := obj.GetKind()

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		if bits >= minTLSRSAKeyBits {
			return checker.Finding{}, false
		}
		return checker.Finding{
			Checker:   "secrets-tls-weak-key",
			Severity:  checker.SeverityMedium,
			Resource:  name,
			Namespace: namespace,
			Kind:      kind,
			Message: fmt.Sprintf(
				"Secret %q contains a TLS certificate with a weak RSA key (%d bits, minimum recommended: 2048).",
				name, bits,
			),
			Remediation: tlsWeakKeyRemediation,
			FieldPath:   `.data["tls.crt"]`,
		}, true
	case *ecdsa.PublicKey:
		bits := pub.Curve.Params().BitSize
		if bits >= minTLSECDSACurveBit {
			return checker.Finding{}, false
		}
		return checker.Finding{
			Checker:   "secrets-tls-weak-key",
			Severity:  checker.SeverityMedium,
			Resource:  name,
			Namespace: namespace,
			Kind:      kind,
			Message: fmt.Sprintf(
				"Secret %q contains a TLS certificate with a weak ECDSA key (%d-bit curve, minimum recommended: P-256/256-bit).",
				name, bits,
			),
			Remediation: tlsWeakKeyRemediation,
			FieldPath:   `.data["tls.crt"]`,
		}, true
	default:
		return checker.Finding{}, false
	}
}

const tlsWeakKeyRemediation = "## Why This Matters\n\n" +
	"Weak keys can be factored or attacked with modern hardware, allowing an adversary to forge " +
	"certificates and intercept or impersonate encrypted TLS connections. RSA keys under 2048 bits " +
	"and ECDSA curves weaker than P-256 fall below the minimum strength recommended by NIST and " +
	"major browser root programs.\n\n" +
	"## How to Fix\n\n" +
	"Regenerate the certificate and private key with a stronger algorithm, then update the Secret:\n\n" +
	"```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: my-tls-secret\ntype: kubernetes.io/tls\ndata:\n  tls.crt: <base64 cert, RSA >= 2048 or ECDSA P-256+>\n  tls.key: <base64 key>\n```\n\n" +
	"Consider adopting cert-manager to automate issuance and renewal with a compliant key " +
	"configuration going forward.\n\n" +
	"## Learn More\n\n" +
	"NIST SP 800-57 and SP 800-186 recommend a minimum of 2048-bit RSA keys and P-256 for ECDSA. " +
	"See the `cert-manager-insecure` check for the equivalent control applied to cert-manager-issued " +
	"certificates."
