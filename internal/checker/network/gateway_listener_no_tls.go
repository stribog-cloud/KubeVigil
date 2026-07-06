package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// GatewayListenerNoTLSChecker detects Gateway API Gateway listeners that serve
// traffic unencrypted: listeners using protocol HTTP, or HTTPS/TLS listeners in
// Terminate mode with no certificateRefs configured.
type GatewayListenerNoTLSChecker struct{}

// Name returns the kebab-case check ID.
func (c *GatewayListenerNoTLSChecker) Name() string { return "gateway-listener-no-tls" }

// Description returns a human-readable description.
func (c *GatewayListenerNoTLSChecker) Description() string {
	return "Detects Gateway API listeners serving traffic unencrypted: HTTP listeners, or HTTPS/TLS listeners in Terminate mode with no certificateRefs."
}

// Categories returns the check categories.
func (c *GatewayListenerNoTLSChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *GatewayListenerNoTLSChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *GatewayListenerNoTLSChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{GatewayGVR}
}

// Run executes the gateway-listener-no-tls check against all Gateway resources in the cache.
func (c *GatewayListenerNoTLSChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gateway-listener-no-tls check: %w", err)
	}

	gateways := resources.List(GatewayGVR)
	var findings []checker.Finding

	for i := range gateways {
		gw := &gateways[i]
		name := gw.GetName()
		namespace := gw.GetNamespace()

		for _, idx := range findUnencryptedListeners(gw) {
			findings = append(findings, checker.Finding{
				Checker:   "gateway-listener-no-tls",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: namespace,
				Kind:      "Gateway",
				Message:   fmt.Sprintf("Gateway %q has a listener serving traffic unencrypted (HTTP, or HTTPS/TLS Terminate mode with no certificateRefs).", name),
				Remediation: "## Why This Matters\n\n" +
					"A Gateway listener using the HTTP protocol, or an HTTPS/TLS listener in Terminate mode with no certificate references, serves client traffic without encryption. " +
					"Attackers on the network path can intercept credentials, session tokens, and other sensitive data via man-in-the-middle attacks — the same risk `ingress-no-tls` flags for the classic Ingress API, now on the Gateway API surface.\n\n" +
					"## How to Fix\n\n" +
					"Configure the listener with protocol `HTTPS`, `tls.mode: Terminate`, and a `certificateRefs` entry pointing at a Secret containing the TLS certificate:\n\n" +
					"```yaml\nspec:\n  listeners:\n    - name: https\n      protocol: HTTPS\n      port: 443\n      tls:\n        mode: Terminate\n        certificateRefs:\n          - kind: Secret\n            name: gateway-tls-cert\n```\n\n" +
					"Use cert-manager's Gateway API support to automate certificate provisioning and renewal.\n\n" +
					"## Learn More\n\n" +
					"See the Gateway API documentation on TLS configuration (https://gateway-api.sigs.k8s.io/guides/tls/). " +
					"HTTPS should be enforced for all externally-facing Gateway listeners to protect data in transit.",
				FieldPath: fmt.Sprintf(".spec.listeners[%d].tls", idx),
			})
		}
	}

	return findings, nil
}

// findUnencryptedListeners returns the indices of listeners that serve traffic
// unencrypted: protocol HTTP, or HTTPS/TLS in Terminate mode with no
// certificateRefs configured. Terminate is the Gateway API default TLS mode
// when tls.mode is unset.
func findUnencryptedListeners(gw *unstructured.Unstructured) []int {
	listeners, found, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
	if !found {
		return nil
	}

	var indices []int
	for idx, l := range listeners {
		listenerMap, ok := l.(map[string]interface{})
		if !ok {
			continue
		}

		protocol, _ := listenerMap["protocol"].(string)
		switch protocol {
		case "HTTP":
			indices = append(indices, idx)
		case "HTTPS", "TLS":
			if listenerTerminatesWithoutCert(listenerMap) {
				indices = append(indices, idx)
			}
		}
	}

	return indices
}

// listenerTerminatesWithoutCert returns true if the listener's tls block is in
// (or defaults to) Terminate mode but has no non-empty certificateRefs.
func listenerTerminatesWithoutCert(listenerMap map[string]interface{}) bool {
	tlsMap, _ := listenerMap["tls"].(map[string]interface{})

	mode, _ := tlsMap["mode"].(string)
	if mode == "" {
		mode = "Terminate" // Gateway API default when tls.mode is unset.
	}
	if mode != "Terminate" {
		return false
	}

	refs, hasRefs := tlsMap["certificateRefs"]
	if !hasRefs {
		return true
	}
	refSlice, ok := refs.([]interface{})
	return !ok || len(refSlice) == 0
}
