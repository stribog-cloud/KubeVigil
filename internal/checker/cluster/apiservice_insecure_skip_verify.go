package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// APIServiceInsecureSkipVerifyChecker detects APIService resources that skip
// TLS verification of the extension API server they aggregate.
type APIServiceInsecureSkipVerifyChecker struct{}

// Name returns the kebab-case check ID.
func (c *APIServiceInsecureSkipVerifyChecker) Name() string { return "apiservice-insecure-skip-verify" }

// Description returns a human-readable description.
func (c *APIServiceInsecureSkipVerifyChecker) Description() string {
	return "Detects APIService resources with insecureSkipTLSVerify: true, exposing the aggregation layer to MITM attacks."
}

// Categories returns the check categories.
func (c *APIServiceInsecureSkipVerifyChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns which scan modes this check supports.
func (c *APIServiceInsecureSkipVerifyChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *APIServiceInsecureSkipVerifyChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{APIServiceGVR}
}

// Run executes the apiservice-insecure-skip-verify check.
func (c *APIServiceInsecureSkipVerifyChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("apiservice-insecure-skip-verify check: %w", err)
	}

	apiServices := resources.List(APIServiceGVR)
	var findings []checker.Finding

	for i := range apiServices {
		obj := &apiServices[i]
		name := obj.GetName()

		skip, found, _ := unstructured.NestedBool(obj.Object, "spec", "insecureSkipTLSVerify")
		if !found || !skip {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:  "apiservice-insecure-skip-verify",
			Severity: checker.SeverityHigh,
			Resource: name,
			Kind:     obj.GetKind(),
			Message:  fmt.Sprintf("APIService %q has insecureSkipTLSVerify: true, trusting the extension API server without verifying its TLS certificate.", name),
			Remediation: "## Why This Matters\n\n" +
				"When `insecureSkipTLSVerify` is `true`, the Kubernetes aggregation layer trusts whatever TLS certificate the " +
				"extension API server (e.g. `metrics.k8s.io`, a custom aggregated API) presents without validating it against a CA. " +
				"This is a direct man-in-the-middle exposure for every request routed to that aggregated API -- an attacker who can " +
				"intercept the network path can impersonate the extension API server and read or tamper with every response.\n\n" +
				"## How to Fix\n\n" +
				"Remove `insecureSkipTLSVerify` and provide a valid `caBundle` for the extension API server instead:\n\n" +
				"```yaml\napiVersion: apiregistration.k8s.io/v1\nkind: APIService\nmetadata:\n  name: v1beta1.metrics.k8s.io\nspec:\n  service:\n    name: metrics-server\n    namespace: kube-system\n  group: metrics.k8s.io\n  version: v1beta1\n  caBundle: <base64-ca-cert>\n  groupPriorityMinimum: 100\n  versionPriority: 100\n```\n\n" +
				"Use cert-manager or your cluster's PKI to issue and rotate the extension API server's certificate and populate `caBundle` automatically.\n\n" +
				"## Learn More\n\n" +
				"See https://kubernetes.io/docs/tasks/extend-kubernetes/setup-extension-api-server/ for aggregated API server TLS requirements.",
			FieldPath:    ".spec.insecureSkipTLSVerify",
			CurrentValue: true,
			DesiredValue: false,
		})
	}

	return findings, nil
}
