package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// EmptyNamespaceSelectorChecker detects NetworkPolicies whose ingress/egress
// peers contain an empty namespaceSelector ({}), a well-known Kubernetes
// footgun: authors often intend "same namespace" but an empty namespaceSelector
// actually matches every namespace in the cluster, silently defeating the
// segmentation the policy was written to enforce.
type EmptyNamespaceSelectorChecker struct{}

// Name returns the kebab-case check ID.
func (c *EmptyNamespaceSelectorChecker) Name() string {
	return "network-policy-empty-namespace-selector"
}

// Description returns a human-readable description.
func (c *EmptyNamespaceSelectorChecker) Description() string {
	return "Detects NetworkPolicies with an empty namespaceSelector ({}) in ingress/egress peers, which matches every namespace in the cluster."
}

// Categories returns the check categories.
func (c *EmptyNamespaceSelectorChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *EmptyNamespaceSelectorChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EmptyNamespaceSelectorChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NetworkPolicyGVR}
}

// Run executes the network-policy-empty-namespace-selector check against all NetworkPolicies in the cache.
func (c *EmptyNamespaceSelectorChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("network-policy-empty-namespace-selector check: %w", err)
	}

	policies := resources.List(NetworkPolicyGVR)
	var findings []checker.Finding

	for i := range policies {
		pol := &policies[i]
		name := pol.GetName()
		namespace := pol.GetNamespace()

		if hasEmptyNamespaceSelectorPeer(pol, "ingress", "from") {
			findings = append(findings, checker.Finding{
				Checker:     "network-policy-empty-namespace-selector",
				Severity:    checker.SeverityMedium,
				Resource:    name,
				Namespace:   namespace,
				Kind:        "NetworkPolicy",
				Message:     fmt.Sprintf("NetworkPolicy %q has an ingress rule with an empty namespaceSelector ({}), which matches every namespace in the cluster.", name),
				Remediation: emptyNamespaceSelectorRemediation("ingress", "from"),
				FieldPath:   ".spec.ingress[].from[].namespaceSelector",
			})
		}

		if hasEmptyNamespaceSelectorPeer(pol, "egress", "to") {
			findings = append(findings, checker.Finding{
				Checker:     "network-policy-empty-namespace-selector",
				Severity:    checker.SeverityMedium,
				Resource:    name,
				Namespace:   namespace,
				Kind:        "NetworkPolicy",
				Message:     fmt.Sprintf("NetworkPolicy %q has an egress rule with an empty namespaceSelector ({}), which matches every namespace in the cluster.", name),
				Remediation: emptyNamespaceSelectorRemediation("egress", "to"),
				FieldPath:   ".spec.egress[].to[].namespaceSelector",
			})
		}
	}

	return findings, nil
}

// emptyNamespaceSelectorRemediation builds the remediation text for a given
// direction ("ingress"/"egress") and its peer key ("from"/"to").
func emptyNamespaceSelectorRemediation(direction, peerKey string) string {
	return "## Why This Matters\n\n" +
		"An empty `namespaceSelector: {}` in a NetworkPolicy peer matches **every** namespace in the cluster, not just the policy's own namespace. " +
		"Authors frequently write this intending to scope traffic to the same namespace, but the empty selector silently defeats that intent and allows traffic from/to workloads in any namespace, including ones the policy author never considered.\n\n" +
		"## How to Fix\n\n" +
		"Scope the `namespaceSelector` with explicit `matchLabels` (or use `podSelector` alone for same-namespace scoping):\n\n" +
		"```yaml\nspec:\n  " + direction + ":\n    - " + peerKey + ":\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: my-namespace\n```\n\n" +
		"If same-namespace traffic is intended, omit `namespaceSelector` entirely and rely on `podSelector`, which implicitly scopes to the policy's own namespace.\n\n" +
		"## Learn More\n\n" +
		"See the Kubernetes NetworkPolicy documentation on namespaceSelector semantics and CIS Kubernetes Benchmark 5.3.2. " +
		"An empty label selector always matches everything — this is documented Kubernetes selector behavior, not a NetworkPolicy-specific quirk."
}

// hasEmptyNamespaceSelectorPeer returns true if any peer in the spec.<ruleKey>
// rule list (ingress or egress) has an empty namespaceSelector ({}) under
// peerKey ("from" or "to").
func hasEmptyNamespaceSelectorPeer(pol *unstructured.Unstructured, ruleKey, peerKey string) bool {
	rules, found, _ := unstructured.NestedSlice(pol.Object, "spec", ruleKey)
	if !found {
		return false
	}

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		peers, ok := ruleMap[peerKey].([]interface{})
		if !ok {
			continue
		}

		for _, peer := range peers {
			peerMap, ok := peer.(map[string]interface{})
			if !ok {
				continue
			}

			nsSelector, hasSelector := peerMap["namespaceSelector"]
			if !hasSelector {
				continue
			}
			selectorMap, ok := nsSelector.(map[string]interface{})
			if ok && len(selectorMap) == 0 {
				return true
			}
		}
	}

	return false
}
