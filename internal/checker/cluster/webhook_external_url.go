package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// WebhookExternalURLChecker detects ValidatingWebhookConfiguration and
// MutatingWebhookConfiguration webhooks whose clientConfig points to an
// external URL rather than an in-cluster service reference.
type WebhookExternalURLChecker struct{}

// Name returns the kebab-case check ID.
func (c *WebhookExternalURLChecker) Name() string { return "webhook-external-url" }

// Description returns a human-readable description.
func (c *WebhookExternalURLChecker) Description() string {
	return "Detects admission webhooks whose clientConfig.url points to an external endpoint instead of an in-cluster service reference."
}

// Categories returns the check categories.
func (c *WebhookExternalURLChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns which scan modes this check supports.
func (c *WebhookExternalURLChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *WebhookExternalURLChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ValidatingWebhookConfigurationGVR, MutatingWebhookConfigurationGVR}
}

// Run executes the webhook-external-url check.
func (c *WebhookExternalURLChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("webhook-external-url check: %w", err)
	}

	var findings []checker.Finding

	for _, gvr := range []schema.GroupVersionResource{ValidatingWebhookConfigurationGVR, MutatingWebhookConfigurationGVR} {
		objs := resources.List(gvr)
		for i := range objs {
			obj := &objs[i]
			name := obj.GetName()
			kind := obj.GetKind()

			webhooks, _, _ := unstructured.NestedSlice(obj.Object, "webhooks")
			for idx, wh := range webhooks {
				whMap, ok := wh.(map[string]interface{})
				if !ok {
					continue
				}

				url, found, _ := unstructured.NestedString(whMap, "clientConfig", "url")
				if !found || url == "" {
					continue
				}

				webhookName, _, _ := unstructured.NestedString(whMap, "name")

				findings = append(findings, checker.Finding{
					Checker:  "webhook-external-url",
					Severity: checker.SeverityHigh,
					Resource: name,
					Kind:     kind,
					Message:  fmt.Sprintf("%s %q webhook %q calls out to external URL %q instead of an in-cluster service.", kind, name, webhookName, url),
					Remediation: "## Why This Matters\n\n" +
						"An admission webhook whose `clientConfig.url` points outside the cluster sends every admission request " +
						"(potentially including sensitive object contents) over the network to a third party. That traffic is exposed " +
						"to DNS hijacking, man-in-the-middle attacks, and outages of the external endpoint -- any of which can silently " +
						"disable or corrupt cluster-wide admission control.\n\n" +
						"## How to Fix\n\n" +
						"Replace the external URL with an in-cluster service reference and a CA bundle:\n\n" +
						"```yaml\nwebhooks:\n  - name: policy.example.com\n    clientConfig:\n      service:\n        name: policy-webhook\n        namespace: policy-system\n        path: /validate\n      caBundle: <base64-ca-cert>\n```\n\n" +
						"Use cert-manager to manage the webhook's TLS certificate and CA bundle automatically.\n\n" +
						"## Learn More\n\n" +
						"See https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#service-reference " +
						"for service-reference webhook configuration and its security benefits over external URLs.",
					FieldPath:    fmt.Sprintf(".webhooks[%d].clientConfig.url", idx),
					CurrentValue: url,
				})
			}
		}
	}

	return findings, nil
}
