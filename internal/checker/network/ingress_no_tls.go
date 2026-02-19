package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// IngressNoTLSChecker detects Ingress resources without TLS configured,
// meaning traffic is served over unencrypted HTTP.
type IngressNoTLSChecker struct{}

// Name returns the kebab-case check ID.
func (c *IngressNoTLSChecker) Name() string { return "ingress-no-tls" }

// Description returns a human-readable description.
func (c *IngressNoTLSChecker) Description() string {
	return "Detects Ingress resources without TLS configured, serving traffic over unencrypted HTTP."
}

// Categories returns the check categories.
func (c *IngressNoTLSChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *IngressNoTLSChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *IngressNoTLSChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{IngressGVR}
}

// Run executes the ingress-no-tls check against all Ingress resources in the cache.
func (c *IngressNoTLSChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ingress-no-tls check: %w", err)
	}

	ingresses := resources.List(IngressGVR)
	var findings []checker.Finding

	for i := range ingresses {
		ing := &ingresses[i]
		name := ing.GetName()
		namespace := ing.GetNamespace()

		if !hasTLS(ing) {
			findings = append(findings, checker.Finding{
				Checker:   "ingress-no-tls",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: namespace,
				Kind:      "Ingress",
				Message:   fmt.Sprintf("Ingress %q has no TLS configured. Traffic is served over unencrypted HTTP.", name),
				Remediation: "## Why This Matters\n\n" +
					"Without TLS, all traffic between clients and this Ingress is transmitted in plaintext over HTTP. " +
					"Attackers on the network path can intercept credentials, session tokens, API keys, and other sensitive data through man-in-the-middle attacks.\n\n" +
					"## How to Fix\n\n" +
					"Add a `tls` section to the Ingress spec referencing a Secret that contains the TLS certificate and private key:\n\n" +
					"```yaml\nspec:\n  tls:\n    - hosts:\n        - app.example.com\n      secretName: app-tls-cert\n  rules:\n    - host: app.example.com\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend:\n              service:\n                name: app\n                port:\n                  number: 80\n```\n\n" +
					"Use cert-manager to automate certificate provisioning and renewal via Let's Encrypt or your internal CA.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes Ingress TLS documentation and CIS Kubernetes Benchmark 5.4.1. " +
					"HTTPS should be enforced for all externally-facing endpoints to protect data in transit.",
				FieldPath: ".spec.tls",
			})
		}
	}

	return findings, nil
}

// hasTLS returns true if the Ingress has a non-empty TLS section.
func hasTLS(ing *unstructured.Unstructured) bool {
	tls, found, _ := unstructured.NestedSlice(ing.Object, "spec", "tls")
	return found && len(tls) > 0
}
