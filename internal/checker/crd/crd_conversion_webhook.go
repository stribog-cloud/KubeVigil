package crd

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ConversionWebhookChecker detects CRDs with conversion webhooks pointing
// to external or potentially untrusted endpoints.
type ConversionWebhookChecker struct{}

// Name returns the check ID.
func (c *ConversionWebhookChecker) Name() string { return "crd-conversion-webhook" }

// Description returns a human-readable description.
func (c *ConversionWebhookChecker) Description() string {
	return "Detects CRDs with conversion webhooks that could be compromised to manipulate data during API version conversion."
}

// Categories returns the check categories.
func (c *ConversionWebhookChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCRD}
}

// SupportedModes returns which scan modes this check supports.
func (c *ConversionWebhookChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ConversionWebhookChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CustomResourceDefinitionGVR}
}

// Run executes the CRD conversion webhook check.
func (c *ConversionWebhookChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("crd-conversion-webhook check: %w", err)
	}

	crds := resources.List(CustomResourceDefinitionGVR)

	for _, crd := range crds {
		name := crd.GetName()

		strategy, _, _ := unstructured.NestedString(crd.Object, "spec", "conversion", "strategy")
		if strategy != "Webhook" {
			continue
		}

		// Check if the webhook uses a URL (external) rather than a service reference.
		url, found, _ := unstructured.NestedString(crd.Object, "spec", "conversion", "webhook", "clientConfig", "url")
		if found && url != "" {
			findings = append(findings, checker.Finding{
				Checker:  "crd-conversion-webhook",
				Severity: checker.SeverityHigh,
				Resource: name,
				Kind:     "CustomResourceDefinition",
				Message:  fmt.Sprintf("CRD %q has a conversion webhook pointing to external URL %q.", name, url),
				Remediation: "## Why This Matters\n\n" +
					"Conversion webhooks using external URLs send API version conversion requests outside the cluster. " +
					"This traffic is vulnerable to DNS hijacking, man-in-the-middle attacks, and external service outages that would break all API operations on this CRD.\n\n" +
					"## How to Fix\n\n" +
					"Replace the external URL with an in-cluster service reference:\n\n" +
					"```yaml\nspec:\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        service:\n          name: my-webhook-svc\n          namespace: my-system\n          path: /convert\n        caBundle: <base64-ca-cert>\n```\n\n" +
					"Use cert-manager to manage the webhook TLS certificates and CA bundle automatically.\n\n" +
					"## Learn More\n\n" +
					"See https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion for webhook conversion setup and security considerations.",
				FieldPath: ".spec.conversion.webhook.clientConfig.url",
			})
			continue
		}

		// Even in-cluster webhooks warrant an informational note.
		svcName, found, _ := unstructured.NestedString(crd.Object, "spec", "conversion", "webhook", "clientConfig", "service", "name")
		if found {
			findings = append(findings, checker.Finding{
				Checker:  "crd-conversion-webhook",
				Severity: checker.SeverityHigh,
				Resource: name,
				Kind:     "CustomResourceDefinition",
				Message:  fmt.Sprintf("CRD %q uses a conversion webhook (service: %q). Ensure the webhook service is trusted and secured.", name, svcName),
				Remediation: "## Why This Matters\n\n" +
					"Conversion webhooks intercept every API version conversion request for this CRD. " +
					"A compromised webhook service can silently modify, inject, or drop data during conversions, affecting all consumers of this custom resource.\n\n" +
					"## How to Fix\n\n" +
					"Ensure the webhook service is properly secured:\n\n" +
					"```yaml\n# 1. Use cert-manager for TLS certificates\n# 2. Apply a NetworkPolicy restricting access:\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: webhook-access\nspec:\n  podSelector:\n    matchLabels:\n      app: my-webhook\n  ingress:\n    - from:\n        - namespaceSelector: {}\n      ports:\n        - port: 443\n```\n\n" +
					"Restrict RBAC permissions for modifying the webhook service and its backing Deployment.\n\n" +
					"## Learn More\n\n" +
					"See https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#service-reference for webhook security patterns and TLS requirements.",
				FieldPath: ".spec.conversion.webhook.clientConfig.service",
			})
		}
	}

	return findings, nil
}
