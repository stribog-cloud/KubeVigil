package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// OverlyPermissiveChecker detects NetworkPolicies that allow all traffic,
// effectively providing no network segmentation.
type OverlyPermissiveChecker struct{}

// Name returns the kebab-case check ID.
func (c *OverlyPermissiveChecker) Name() string { return "network-policy-overly-permissive" }

// Description returns a human-readable description.
func (c *OverlyPermissiveChecker) Description() string {
	return "Detects NetworkPolicies that allow all traffic, providing no effective network segmentation."
}

// Categories returns the check categories.
func (c *OverlyPermissiveChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *OverlyPermissiveChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *OverlyPermissiveChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NetworkPolicyGVR}
}

// Run executes the overly-permissive check against all NetworkPolicies in the cache.
func (c *OverlyPermissiveChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("network-policy-overly-permissive check: %w", err)
	}

	policies := resources.List(NetworkPolicyGVR)
	var findings []checker.Finding

	for i := range policies {
		pol := &policies[i]
		name := pol.GetName()
		namespace := pol.GetNamespace()

		if hasOverlyPermissiveIngress(pol) {
			findings = append(findings, checker.Finding{
				Checker:   "network-policy-overly-permissive",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: namespace,
				Kind:      "NetworkPolicy",
				Message:   fmt.Sprintf("NetworkPolicy %q allows all ingress traffic, providing no effective ingress segmentation.", name),
				Remediation: "## Why This Matters\n\n" +
					"This NetworkPolicy allows ingress traffic from any source, which is equivalent to having no ingress restriction at all. " +
					"An attacker who compromises any pod in the cluster can reach services protected by this policy, defeating the purpose of network segmentation.\n\n" +
					"## How to Fix\n\n" +
					"Replace the permissive rule with specific source selectors that limit traffic to known, trusted origins:\n\n" +
					"```yaml\nspec:\n  ingress:\n    - from:\n        - podSelector:\n            matchLabels:\n              app: frontend\n        - namespaceSelector:\n            matchLabels:\n              env: production\n      ports:\n        - port: 8080\n          protocol: TCP\n```\n\n" +
					"For external sources, use `ipBlock` with specific CIDRs and `except` ranges to narrow allowed IP ranges.\n\n" +
					"## Learn More\n\n" +
					"Refer to the Kubernetes NetworkPolicy documentation on ingress rules. " +
					"CIS Kubernetes Benchmark 5.3.2 recommends ensuring that all namespaces have appropriately restrictive network policies.",
				FieldPath: ".spec.ingress",
			})
		}

		if hasOverlyPermissiveEgress(pol) {
			findings = append(findings, checker.Finding{
				Checker:   "network-policy-overly-permissive",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: namespace,
				Kind:      "NetworkPolicy",
				Message:   fmt.Sprintf("NetworkPolicy %q allows all egress traffic, providing no effective egress segmentation.", name),
				Remediation: "## Why This Matters\n\n" +
					"This NetworkPolicy allows egress traffic to any destination, which is equivalent to having no egress restriction at all. " +
					"A compromised pod can exfiltrate data to external servers, reach cloud metadata endpoints, or communicate with command-and-control infrastructure.\n\n" +
					"## How to Fix\n\n" +
					"Replace the permissive rule with specific destination selectors that limit traffic to known, required endpoints:\n\n" +
					"```yaml\nspec:\n  egress:\n    - to:\n        - podSelector:\n            matchLabels:\n              app: database\n      ports:\n        - port: 5432\n          protocol: TCP\n    - to:\n        - namespaceSelector: {}\n      ports:\n        - port: 53\n          protocol: UDP\n```\n\n" +
					"Always include a DNS egress rule (port 53) so pods can resolve service names.\n\n" +
					"## Learn More\n\n" +
					"Refer to the Kubernetes NetworkPolicy documentation on egress rules. " +
					"The NSA/CISA Kubernetes Hardening Guide recommends restricting egress to prevent data exfiltration.",
				FieldPath: ".spec.egress",
			})
		}
	}

	return findings, nil
}

// hasOverlyPermissiveIngress returns true if the policy allows all ingress traffic.
// This occurs when:
// - Any ingress rule has an empty "from" list (allows from everywhere)
// - Any ingress rule has an ipBlock with CIDR "0.0.0.0/0" without except
func hasOverlyPermissiveIngress(pol *unstructured.Unstructured) bool {
	ingress, found, _ := unstructured.NestedSlice(pol.Object, "spec", "ingress")
	if !found || len(ingress) == 0 {
		return false
	}

	for _, rule := range ingress {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		if isRuleOverlyPermissive(ruleMap, "from") {
			return true
		}
	}

	return false
}

// hasOverlyPermissiveEgress returns true if the policy allows all egress traffic.
func hasOverlyPermissiveEgress(pol *unstructured.Unstructured) bool {
	egress, found, _ := unstructured.NestedSlice(pol.Object, "spec", "egress")
	if !found || len(egress) == 0 {
		return false
	}

	for _, rule := range egress {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		if isRuleOverlyPermissive(ruleMap, "to") {
			return true
		}
	}

	return false
}

// isRuleOverlyPermissive checks if a single ingress/egress rule allows all traffic.
// The directionKey is "from" for ingress or "to" for egress.
func isRuleOverlyPermissive(ruleMap map[string]interface{}, directionKey string) bool {
	peers, hasPeers := ruleMap[directionKey]
	if !hasPeers {
		// An ingress/egress rule with no "from"/"to" key allows all sources/destinations.
		return true
	}

	peerSlice, ok := peers.([]interface{})
	if !ok {
		return false
	}

	// Empty peer list also allows all.
	if len(peerSlice) == 0 {
		return true
	}

	// Check for 0.0.0.0/0 ipBlock without except.
	for _, peer := range peerSlice {
		peerMap, ok := peer.(map[string]interface{})
		if !ok {
			continue
		}

		ipBlock, ok := peerMap["ipBlock"].(map[string]interface{})
		if !ok {
			continue
		}

		cidr, _ := ipBlock["cidr"].(string)
		if cidr == "0.0.0.0/0" {
			except, hasExcept := ipBlock["except"]
			if !hasExcept {
				return true
			}
			exceptSlice, ok := except.([]interface{})
			if ok && len(exceptSlice) == 0 {
				return true
			}
		}
	}

	return false
}
