package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// GatewayAllowedRoutesAllNamespacesChecker detects Gateway API Gateway listeners
// with allowedRoutes.namespaces.from set to "All", letting any namespace in the
// cluster attach routes to the Gateway.
type GatewayAllowedRoutesAllNamespacesChecker struct{}

// Name returns the kebab-case check ID.
func (c *GatewayAllowedRoutesAllNamespacesChecker) Name() string {
	return "gateway-allowedroutes-all-namespaces"
}

// Description returns a human-readable description.
func (c *GatewayAllowedRoutesAllNamespacesChecker) Description() string {
	return "Detects Gateway listeners with allowedRoutes.namespaces.from set to All, letting any namespace attach routes to the Gateway."
}

// Categories returns the check categories.
func (c *GatewayAllowedRoutesAllNamespacesChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *GatewayAllowedRoutesAllNamespacesChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *GatewayAllowedRoutesAllNamespacesChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{GatewayGVR}
}

// Run executes the gateway-allowedroutes-all-namespaces check against all Gateway resources in the cache.
func (c *GatewayAllowedRoutesAllNamespacesChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gateway-allowedroutes-all-namespaces check: %w", err)
	}

	gateways := resources.List(GatewayGVR)
	var findings []checker.Finding

	for i := range gateways {
		gw := &gateways[i]
		name := gw.GetName()
		namespace := gw.GetNamespace()

		for _, idx := range findAllNamespacesListeners(gw) {
			findings = append(findings, checker.Finding{
				Checker:   "gateway-allowedroutes-all-namespaces",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: namespace,
				Kind:      "Gateway",
				Message:   fmt.Sprintf("Gateway %q has a listener with allowedRoutes.namespaces.from set to \"All\", letting any namespace attach routes.", name),
				Remediation: "## Why This Matters\n\n" +
					"An `allowedRoutes.namespaces.from: All` listener lets a route (e.g. HTTPRoute) created in **any** namespace in the cluster attach itself to this Gateway. " +
					"This crosses a trust boundary the Gateway's owning team likely did not intend: a compromised or careless namespace elsewhere in the cluster can claim hostnames, paths, or backend references on a shared Gateway it does not own.\n\n" +
					"## How to Fix\n\n" +
					"Scope `allowedRoutes.namespaces.from` to `Same` (only routes in the Gateway's own namespace) or `Selector` with an explicit `matchLabels` selector naming the trusted namespaces:\n\n" +
					"```yaml\nspec:\n  listeners:\n    - name: https\n      allowedRoutes:\n        namespaces:\n          from: Selector\n          selector:\n            matchLabels:\n              gateway-access: my-team\n```\n\n" +
					"Label only the namespaces that should be permitted to attach routes to this Gateway.\n\n" +
					"## Learn More\n\n" +
					"See the Gateway API security model documentation on cross-namespace routing (https://gateway-api.sigs.k8s.io/concepts/security-model/). " +
					"Scoping route attachment prevents unintended trust-boundary crossings between teams sharing a Gateway.",
				FieldPath: fmt.Sprintf(".spec.listeners[%d].allowedRoutes.namespaces.from", idx),
			})
		}
	}

	return findings, nil
}

// findAllNamespacesListeners returns the indices of listeners whose
// allowedRoutes.namespaces.from is set to "All".
func findAllNamespacesListeners(gw *unstructured.Unstructured) []int {
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

		from, found, _ := unstructured.NestedString(listenerMap, "allowedRoutes", "namespaces", "from")
		if found && from == "All" {
			indices = append(indices, idx)
		}
	}

	return indices
}
