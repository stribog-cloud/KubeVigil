package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ValidatingWebhookFailurePolicyIgnoreChecker detects ValidatingWebhookConfiguration
// webhooks configured with failurePolicy: Ignore, which fail open (admit the
// request) whenever the webhook backend is unreachable.
type ValidatingWebhookFailurePolicyIgnoreChecker struct{}

// Name returns the kebab-case check ID.
func (c *ValidatingWebhookFailurePolicyIgnoreChecker) Name() string {
	return "validatingwebhook-failure-policy-ignore"
}

// Description returns a human-readable description.
func (c *ValidatingWebhookFailurePolicyIgnoreChecker) Description() string {
	return "Detects ValidatingWebhookConfiguration webhooks with failurePolicy: Ignore, which fail open and silently admit requests when the webhook is unreachable."
}

// Categories returns the check categories.
func (c *ValidatingWebhookFailurePolicyIgnoreChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns which scan modes this check supports.
func (c *ValidatingWebhookFailurePolicyIgnoreChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ValidatingWebhookFailurePolicyIgnoreChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ValidatingWebhookConfigurationGVR}
}

// Run executes the validatingwebhook-failure-policy-ignore check.
func (c *ValidatingWebhookFailurePolicyIgnoreChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("validatingwebhook-failure-policy-ignore check: %w", err)
	}

	configs := resources.List(ValidatingWebhookConfigurationGVR)
	var findings []checker.Finding

	for i := range configs {
		obj := &configs[i]
		name := obj.GetName()

		webhooks, _, _ := unstructured.NestedSlice(obj.Object, "webhooks")
		for idx, wh := range webhooks {
			whMap, ok := wh.(map[string]interface{})
			if !ok {
				continue
			}

			failurePolicy, _, _ := unstructured.NestedString(whMap, "failurePolicy")
			if failurePolicy != "Ignore" {
				continue
			}

			webhookName, _, _ := unstructured.NestedString(whMap, "name")

			findings = append(findings, checker.Finding{
				Checker:  "validatingwebhook-failure-policy-ignore",
				Severity: checker.SeverityHigh,
				Resource: name,
				Kind:     obj.GetKind(),
				Message:  fmt.Sprintf("ValidatingWebhookConfiguration %q webhook %q uses failurePolicy: Ignore, admitting requests when the webhook is unreachable.", name, webhookName),
				Remediation: "## Why This Matters\n\n" +
					"With `failurePolicy: Ignore`, if the webhook backend is down, erroring, or unreachable, the API server admits " +
					"the request anyway instead of rejecting it. Any security policy the webhook enforces (OPA Gatekeeper, Kyverno, " +
					"custom admission logic) is silently bypassed the moment the webhook becomes unavailable -- a fail-open design " +
					"that an attacker can exploit by disrupting the webhook service.\n\n" +
					"## How to Fix\n\n" +
					"Set `failurePolicy` to `Fail` so requests are rejected (fail-closed) when the webhook cannot be reached:\n\n" +
					"```yaml\nwebhooks:\n  - name: policy.example.com\n    failurePolicy: Fail\n```\n\n" +
					"Before flipping to `Fail` in production, ensure the webhook deployment has adequate replicas, a PodDisruptionBudget, " +
					"and monitoring so a webhook outage does not become a cluster-wide admission outage.\n\n" +
					"## Learn More\n\n" +
					"See https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy " +
					"for the tradeoffs between fail-open and fail-closed admission webhooks.",
				FieldPath:    fmt.Sprintf(".webhooks[%d].failurePolicy", idx),
				CurrentValue: "Ignore",
				DesiredValue: "Fail",
				FixHint: &checker.FixHint{
					Safety:      checker.FixLikelySafe,
					Description: "Sets failurePolicy to Fail so the webhook fails closed.",
					Impact:      "If the webhook backend is ever down or unreachable, requests it governs will be rejected instead of silently admitted, which can cause outages for webhooks that were intentionally fail-open for availability.",
					Operation:   checker.FixOpSet,
				},
			})
			break // one finding per webhook configuration
		}
	}

	return findings, nil
}
