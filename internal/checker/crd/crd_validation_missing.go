package crd

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ValidationMissingChecker detects CustomResourceDefinitions without
// OpenAPI validation schemas. Unvalidated CRDs accept any input.
type ValidationMissingChecker struct{}

// Name returns the check ID.
func (c *ValidationMissingChecker) Name() string { return "crd-validation-missing" }

// Description returns a human-readable description.
func (c *ValidationMissingChecker) Description() string {
	return "Detects CRDs without OpenAPI validation schema, which accept any input including potentially malicious payloads."
}

// Categories returns the check categories.
func (c *ValidationMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCRD}
}

// SupportedModes returns which scan modes this check supports.
func (c *ValidationMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ValidationMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CustomResourceDefinitionGVR}
}

// Run executes the CRD validation check.
func (c *ValidationMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("crd-validation-missing check: %w", err)
	}

	crds := resources.List(CustomResourceDefinitionGVR)

	for _, crd := range crds {
		name := crd.GetName()

		if hasValidationSchema(crd) {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:  "crd-validation-missing",
			Severity: checker.SeverityMedium,
			Resource: name,
			Kind:     "CustomResourceDefinition",
			Message:  fmt.Sprintf("CRD %q has no OpenAPI validation schema defined.", name),
			Remediation: "## Why This Matters\n\n" +
				"CRDs without an OpenAPI validation schema accept any arbitrary input. Attackers or misconfigured automation can " +
				"create custom resources with malicious fields, causing controller crashes, injection attacks, or unexpected behavior in operators that trust the data.\n\n" +
				"## How to Fix\n\n" +
				"Add an OpenAPI v3 validation schema to each version in the CRD spec:\n\n" +
				"```yaml\nspec:\n  versions:\n    - name: v1\n      schema:\n        openAPIV3Schema:\n          type: object\n          properties:\n            spec:\n              type: object\n              required: [replicas]\n              properties:\n                replicas:\n                  type: integer\n                  minimum: 1\n                  maximum: 100\n```\n\n" +
				"Use `x-kubernetes-validations` for CEL-based custom validation rules in Kubernetes 1.25+.\n\n" +
				"## Learn More\n\n" +
				"See https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation for CRD schema validation and structural schema requirements.",
		})
	}

	return findings, nil
}

// hasValidationSchema checks if a CRD has any OpenAPI validation schema.
func hasValidationSchema(crd unstructured.Unstructured) bool {
	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	for _, v := range versions {
		vm, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		_, found, _ := unstructured.NestedMap(vm, "schema", "openAPIV3Schema")
		if found {
			return true
		}
	}
	return false
}
