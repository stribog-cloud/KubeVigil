package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// IngressWildcardHostChecker detects Ingress resources with wildcard or empty host
// rules, which match all incoming requests regardless of hostname.
type IngressWildcardHostChecker struct{}

// Name returns the kebab-case check ID.
func (c *IngressWildcardHostChecker) Name() string { return "ingress-wildcard-host" }

// Description returns a human-readable description.
func (c *IngressWildcardHostChecker) Description() string {
	return "Detects Ingress resources with wildcard or empty host rules that match all incoming requests."
}

// Categories returns the check categories.
func (c *IngressWildcardHostChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *IngressWildcardHostChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *IngressWildcardHostChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{IngressGVR}
}

// Run executes the ingress-wildcard-host check against all Ingress resources in the cache.
func (c *IngressWildcardHostChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ingress-wildcard-host check: %w", err)
	}

	ingresses := resources.List(IngressGVR)
	var findings []checker.Finding

	for i := range ingresses {
		ing := &ingresses[i]
		name := ing.GetName()
		namespace := ing.GetNamespace()

		wildcardRules := findWildcardRules(ing)
		for _, ruleIdx := range wildcardRules {
			findings = append(findings, checker.Finding{
				Checker:   "ingress-wildcard-host",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: namespace,
				Kind:      "Ingress",
				Message:   fmt.Sprintf("Ingress %q has a rule with wildcard or empty host that matches all incoming requests.", name),
				Remediation: "## Why This Matters\n\n" +
					"A wildcard or empty host in an Ingress rule matches all incoming requests regardless of the Host header. " +
					"This can expose backend services to unintended traffic, enable host header injection attacks, and make it difficult to enforce per-domain security policies like TLS and authentication.\n\n" +
					"## How to Fix\n\n" +
					"Replace the wildcard or empty host with an explicit, fully-qualified domain name:\n\n" +
					"```yaml\nspec:\n  rules:\n    - host: app.example.com\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend:\n              service:\n                name: app\n                port:\n                  number: 80\n```\n\n" +
					"If multiple domains are needed, create separate rules with explicit hosts for each.\n\n" +
					"## Learn More\n\n" +
					"Refer to the Kubernetes Ingress documentation on host-based routing. " +
					"Explicit host matching is a security best practice that prevents unintended routing and simplifies audit trails.",
				FieldPath: fmt.Sprintf(".spec.rules[%d].host", ruleIdx),
			})
		}
	}

	return findings, nil
}

// findWildcardRules returns the indices of rules that have an empty or wildcard host.
func findWildcardRules(ing *unstructured.Unstructured) []int {
	rules, found, _ := unstructured.NestedSlice(ing.Object, "spec", "rules")
	if !found {
		return nil
	}

	var indices []int
	for idx, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		host, _ := ruleMap["host"].(string)
		if host == "" || host == "*" {
			indices = append(indices, idx)
		}
	}

	return indices
}
