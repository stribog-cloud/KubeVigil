package network

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HTTPRouteWildcardHostnameChecker detects HTTPRoute resources with a wildcard
// or empty hostnames list, matching overly broad sets of incoming requests.
type HTTPRouteWildcardHostnameChecker struct{}

// Name returns the kebab-case check ID.
func (c *HTTPRouteWildcardHostnameChecker) Name() string { return "httproute-wildcard-hostname" }

// Description returns a human-readable description.
func (c *HTTPRouteWildcardHostnameChecker) Description() string {
	return "Detects HTTPRoute resources with a wildcard or empty hostnames list, matching overly broad sets of incoming requests."
}

// Categories returns the check categories.
func (c *HTTPRouteWildcardHostnameChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *HTTPRouteWildcardHostnameChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HTTPRouteWildcardHostnameChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{HTTPRouteGVR}
}

// Run executes the httproute-wildcard-hostname check against all HTTPRoute resources in the cache.
func (c *HTTPRouteWildcardHostnameChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("httproute-wildcard-hostname check: %w", err)
	}

	routes := resources.List(HTTPRouteGVR)
	var findings []checker.Finding

	for i := range routes {
		route := &routes[i]
		name := route.GetName()
		namespace := route.GetNamespace()

		if !hasWildcardOrEmptyHostnames(route) {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "httproute-wildcard-hostname",
			Severity:  checker.SeverityMedium,
			Resource:  name,
			Namespace: namespace,
			Kind:      "HTTPRoute",
			Message:   fmt.Sprintf("HTTPRoute %q has a wildcard or empty hostnames list, matching overly broad sets of incoming requests.", name),
			Remediation: "## Why This Matters\n\n" +
				"An HTTPRoute with no `hostnames` (or a wildcard entry like `*.example.com` or `*`) matches requests for any hostname permitted by the parent Gateway listener. " +
				"This can route unintended traffic to backends, make it difficult to reason about which requests a route actually serves, and complicate per-domain security policy enforcement — the Gateway API analog of `ingress-wildcard-host`.\n\n" +
				"## How to Fix\n\n" +
				"Specify explicit, fully-qualified hostnames on the HTTPRoute:\n\n" +
				"```yaml\nspec:\n  hostnames:\n    - app.example.com\n  rules:\n    - matches:\n        - path:\n            type: PathPrefix\n            value: /\n      backendRefs:\n        - name: app\n          port: 80\n```\n\n" +
				"If multiple domains are needed, list each explicit hostname rather than relying on a wildcard.\n\n" +
				"## Learn More\n\n" +
				"See the Gateway API documentation on HTTPRoute hostnames (https://gateway-api.sigs.k8s.io/api-types/httproute/). " +
				"Explicit hostname matching is a security best practice that prevents unintended routing and simplifies audit trails.",
			FieldPath: ".spec.hostnames",
		})
	}

	return findings, nil
}

// hasWildcardOrEmptyHostnames returns true if the HTTPRoute's hostnames list is
// empty/absent, or contains an entry that is exactly "*" or starts with "*.".
func hasWildcardOrEmptyHostnames(route *unstructured.Unstructured) bool {
	hostnames, found, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
	if !found || len(hostnames) == 0 {
		return true
	}

	for _, h := range hostnames {
		if h == "*" || strings.HasPrefix(h, "*.") {
			return true
		}
	}

	return false
}
