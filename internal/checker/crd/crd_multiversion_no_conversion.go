package crd

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// MultiversionNoConversionChecker detects CRDs serving two or more versions
// with no conversion webhook configured, risking silent data loss or zeroed
// fields when clients round-trip objects between versions.
type MultiversionNoConversionChecker struct{}

// Name returns the check ID.
func (c *MultiversionNoConversionChecker) Name() string { return "crd-multiversion-no-conversion" }

// Description returns a human-readable description.
func (c *MultiversionNoConversionChecker) Description() string {
	return "Detects CRDs serving 2+ versions with no conversion webhook configured, risking silent data loss between versions."
}

// Categories returns the check categories.
func (c *MultiversionNoConversionChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCRD}
}

// SupportedModes returns which scan modes this check supports.
func (c *MultiversionNoConversionChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *MultiversionNoConversionChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CustomResourceDefinitionGVR}
}

// Run executes the crd-multiversion-no-conversion check.
func (c *MultiversionNoConversionChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("crd-multiversion-no-conversion check: %w", err)
	}

	crds := resources.List(CustomResourceDefinitionGVR)

	for _, crd := range crds {
		name := crd.GetName()

		if countServedVersions(crd) < 2 {
			continue
		}

		strategy, _, _ := unstructured.NestedString(crd.Object, "spec", "conversion", "strategy")
		if strategy == "Webhook" {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:  "crd-multiversion-no-conversion",
			Severity: checker.SeverityMedium,
			Resource: name,
			Kind:     "CustomResourceDefinition",
			Message:  fmt.Sprintf("CRD %q serves 2+ versions with no conversion webhook configured (strategy: %q).", name, orNone(strategy)),
			Remediation: "## Why This Matters\n\n" +
				"When a CRD serves multiple versions without a real conversion webhook, Kubernetes falls back to the trivial " +
				"`None` conversion strategy, which copies fields byte-for-byte between versions with no actual transformation. " +
				"Any field that differs in shape or name between versions silently round-trips as data loss or a zeroed value -- " +
				"clients reading or writing through an older or newer version can lose data without any error being surfaced.\n\n" +
				"## How to Fix\n\n" +
				"Implement and register a conversion webhook so version differences are translated explicitly:\n\n" +
				"```yaml\nspec:\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        service:\n          name: my-crd-converter\n          namespace: my-system\n          path: /convert\n        caBundle: <base64-ca-cert>\n```\n\n" +
				"If only one version needs to remain served long-term, consider deprecating and removing the older served " +
				"version instead of maintaining lossy multi-version support.\n\n" +
				"## Learn More\n\n" +
				"See https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion " +
				"for conversion webhook setup and the risks of the None strategy across multiple served versions.",
			FieldPath: ".spec.conversion.strategy",
		})
	}

	return findings, nil
}

// countServedVersions returns the number of versions in the CRD with served: true.
func countServedVersions(crd unstructured.Unstructured) int {
	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	count := 0
	for _, v := range versions {
		vm, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		served, _, _ := unstructured.NestedBool(vm, "served")
		if served {
			count++
		}
	}
	return count
}

// orNone returns "None" if s is empty, otherwise s.
func orNone(s string) string {
	if s == "" {
		return "None"
	}
	return s
}
