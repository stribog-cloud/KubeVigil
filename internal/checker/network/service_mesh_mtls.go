package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// PeerAuthenticationGVR is the GroupVersionResource for Istio PeerAuthentication CRD.
var PeerAuthenticationGVR = schema.GroupVersionResource{
	Group: "security.istio.io", Version: "v1beta1", Resource: "peerauthentications",
}

// ServiceMeshMTLSChecker detects Istio PeerAuthentication resources where mTLS is
// not set to STRICT mode. When mTLS is PERMISSIVE or DISABLE, traffic between
// services may be unencrypted, allowing eavesdropping and spoofing.
type ServiceMeshMTLSChecker struct{}

// Name returns the kebab-case check ID.
func (c *ServiceMeshMTLSChecker) Name() string { return "service-mesh-mtls" }

// Description returns a human-readable description.
func (c *ServiceMeshMTLSChecker) Description() string {
	return "Detects Istio PeerAuthentication resources where mTLS is not enforced as STRICT, allowing unencrypted service-to-service traffic."
}

// Categories returns the check categories.
func (c *ServiceMeshMTLSChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *ServiceMeshMTLSChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ServiceMeshMTLSChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{PeerAuthenticationGVR}
}

// Run executes the service-mesh-mtls check against all PeerAuthentication resources in the cache.
func (c *ServiceMeshMTLSChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("service-mesh-mtls check: %w", err)
	}

	peerAuths := resources.List(PeerAuthenticationGVR)
	var findings []checker.Finding

	for i := range peerAuths {
		pa := &peerAuths[i]
		mode := mtlsMode(pa)

		// STRICT is the desired state; skip it.
		if mode == "STRICT" {
			continue
		}

		name := pa.GetName()
		namespace := pa.GetNamespace()
		scope := peerAuthScope(pa, namespace)

		severity := checker.SeverityHigh
		msg := fmt.Sprintf("PeerAuthentication %q in namespace %q has mTLS mode %q%s. Service-to-service traffic may be unencrypted.",
			name, namespace, mode, scope)

		if mode == "DISABLE" {
			msg = fmt.Sprintf("PeerAuthentication %q in namespace %q has mTLS DISABLED%s. All service-to-service traffic is unencrypted.",
				name, namespace, scope)
		}

		if mode == "" {
			msg = fmt.Sprintf("PeerAuthentication %q in namespace %q has no mTLS mode configured%s. mTLS enforcement is undefined.",
				name, namespace, scope)
		}

		findings = append(findings, checker.Finding{
			Checker:   "service-mesh-mtls",
			Severity:  severity,
			Resource:  name,
			Namespace: namespace,
			Kind:      "PeerAuthentication",
			Message:   msg,
			Remediation: "## Why This Matters\n\n" +
				"Without strict mTLS enforcement, service-to-service traffic may be transmitted in plaintext. " +
				"An attacker with access to the pod network can eavesdrop on inter-service communication, steal credentials and tokens, or spoof service identities to intercept requests.\n\n" +
				"## How to Fix\n\n" +
				"Set the mTLS mode to STRICT in the PeerAuthentication resource. For namespace-wide enforcement:\n\n" +
				"```yaml\napiVersion: security.istio.io/v1beta1\nkind: PeerAuthentication\nmetadata:\n  name: default\n  namespace: my-namespace\nspec:\n  mtls:\n    mode: STRICT\n```\n\n" +
				"For mesh-wide enforcement, apply the policy in the `istio-system` namespace with no selector. " +
				"Verify all workloads have Envoy sidecars injected before switching from PERMISSIVE to STRICT.\n\n" +
				"## Learn More\n\n" +
				"See the Istio PeerAuthentication documentation and the NSA/CISA Kubernetes Hardening Guide section on encrypting data in transit. " +
				"Strict mTLS ensures both encryption and mutual identity verification between services.",
			FieldPath: ".spec.mtls.mode",
		})
	}

	return findings, nil
}

// mtlsMode extracts the .spec.mtls.mode field from a PeerAuthentication.
func mtlsMode(pa *unstructured.Unstructured) string {
	mode, found, err := unstructured.NestedString(pa.Object, "spec", "mtls", "mode")
	if err != nil || !found {
		return ""
	}
	return mode
}

// peerAuthScope returns a description of the PeerAuthentication scope.
func peerAuthScope(pa *unstructured.Unstructured, namespace string) string {
	// Check if this is a mesh-wide policy (in istio-system with no selector).
	_, hasSelector, _ := unstructured.NestedMap(pa.Object, "spec", "selector", "matchLabels")
	if namespace == "istio-system" && !hasSelector {
		return " (mesh-wide policy)"
	}
	if hasSelector {
		return " (workload-scoped policy)"
	}
	return " (namespace-wide policy)"
}
