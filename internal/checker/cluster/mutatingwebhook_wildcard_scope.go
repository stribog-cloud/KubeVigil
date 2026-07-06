package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// MutatingWebhookWildcardScopeChecker detects MutatingWebhookConfiguration
// webhooks whose rules match every apiGroup, apiVersion, and resource in the
// cluster with no namespaceSelector narrowing the scope.
type MutatingWebhookWildcardScopeChecker struct{}

// Name returns the kebab-case check ID.
func (c *MutatingWebhookWildcardScopeChecker) Name() string { return "mutatingwebhook-wildcard-scope" }

// Description returns a human-readable description.
func (c *MutatingWebhookWildcardScopeChecker) Description() string {
	return "Detects MutatingWebhookConfiguration webhooks that match every apiGroup/apiVersion/resource cluster-wide with no namespaceSelector."
}

// Categories returns the check categories.
func (c *MutatingWebhookWildcardScopeChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns which scan modes this check supports.
func (c *MutatingWebhookWildcardScopeChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *MutatingWebhookWildcardScopeChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{MutatingWebhookConfigurationGVR}
}

// Run executes the mutatingwebhook-wildcard-scope check.
func (c *MutatingWebhookWildcardScopeChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("mutatingwebhook-wildcard-scope check: %w", err)
	}

	configs := resources.List(MutatingWebhookConfigurationGVR)
	var findings []checker.Finding

	for i := range configs {
		obj := &configs[i]
		name := obj.GetName()

		webhooks, _, _ := unstructured.NestedSlice(obj.Object, "webhooks")
		for whIdx, wh := range webhooks {
			whMap, ok := wh.(map[string]interface{})
			if !ok {
				continue
			}

			if hasScopedNamespaceSelector(whMap) {
				continue
			}

			webhookName, _, _ := unstructured.NestedString(whMap, "name")
			ruleIdx, matched := findWildcardRule(whMap)
			if !matched {
				continue
			}

			findings = append(findings, checker.Finding{
				Checker:  "mutatingwebhook-wildcard-scope",
				Severity: checker.SeverityHigh,
				Resource: name,
				Kind:     obj.GetKind(),
				Message:  fmt.Sprintf("MutatingWebhookConfiguration %q webhook %q matches every apiGroup/apiVersion/resource cluster-wide with no namespaceSelector.", name, webhookName),
				Remediation: "## Why This Matters\n\n" +
					"A mutating webhook whose rule matches `apiGroups: [\"*\"]`, `apiVersions: [\"*\"]`, and `resources: [\"*\"]` with no " +
					"`namespaceSelector` can silently alter ANY resource in the cluster on every write. If the webhook backend is ever " +
					"compromised, misconfigured, or buggy, it becomes a cluster-wide integrity and supply-chain risk -- it can inject " +
					"malicious sidecars, rewrite image references, or corrupt any object cluster-wide.\n\n" +
					"## How to Fix\n\n" +
					"Scope the webhook to only the resources it actually needs to mutate, and add a `namespaceSelector` to exclude " +
					"system namespaces:\n\n" +
					"```yaml\nwebhooks:\n  - name: my-mutator.example.com\n    namespaceSelector:\n      matchExpressions:\n        - key: kubernetes.io/metadata.name\n          operator: NotIn\n          values: [\"kube-system\", \"kube-public\"]\n    rules:\n      - apiGroups: [\"apps\"]\n        apiVersions: [\"v1\"]\n        resources: [\"deployments\"]\n        operations: [\"CREATE\", \"UPDATE\"]\n```\n\n" +
					"## Learn More\n\n" +
					"See https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-namespaceselector " +
					"for scoping admission webhooks with namespaceSelector and rule-level resource restrictions.",
				FieldPath: fmt.Sprintf(".webhooks[%d].rules[%d]", whIdx, ruleIdx),
			})
			break // one finding per webhook configuration
		}
	}

	return findings, nil
}

// hasScopedNamespaceSelector returns true if the webhook's namespaceSelector
// narrows the scope via matchLabels or matchExpressions.
func hasScopedNamespaceSelector(webhook map[string]interface{}) bool {
	sel, found, _ := unstructured.NestedMap(webhook, "namespaceSelector")
	if !found {
		return false
	}
	labels, _, _ := unstructured.NestedStringMap(sel, "matchLabels")
	if len(labels) > 0 {
		return true
	}
	exprs, _, _ := unstructured.NestedSlice(sel, "matchExpressions")
	return len(exprs) > 0
}

// findWildcardRule returns the index of the first rule in the webhook that
// matches every apiGroup, apiVersion, and resource, and whether one was found.
func findWildcardRule(webhook map[string]interface{}) (int, bool) {
	rules, _, _ := unstructured.NestedSlice(webhook, "rules")
	for idx, r := range rules {
		ruleMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		groups, _, _ := unstructured.NestedStringSlice(ruleMap, "apiGroups")
		versions, _, _ := unstructured.NestedStringSlice(ruleMap, "apiVersions")
		res, _, _ := unstructured.NestedStringSlice(ruleMap, "resources")
		if isOnlyWildcard(groups) && isOnlyWildcard(versions) && isOnlyWildcard(res) {
			return idx, true
		}
	}
	return 0, false
}

// isOnlyWildcard returns true if the slice contains exactly one element: "*".
func isOnlyWildcard(vals []string) bool {
	return len(vals) == 1 && vals[0] == "*"
}
