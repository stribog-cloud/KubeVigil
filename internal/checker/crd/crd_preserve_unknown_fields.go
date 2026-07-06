package crd

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// PreserveUnknownFieldsChecker detects CustomResourceDefinitions with the
// deprecated top-level spec.preserveUnknownFields: true, which disables
// OpenAPI pruning entirely for the CRD.
type PreserveUnknownFieldsChecker struct{}

// Name returns the check ID.
func (c *PreserveUnknownFieldsChecker) Name() string { return "crd-preserve-unknown-fields" }

// Description returns a human-readable description.
func (c *PreserveUnknownFieldsChecker) Description() string {
	return "Detects CRDs with the deprecated spec.preserveUnknownFields: true, which disables OpenAPI pruning for every version."
}

// Categories returns the check categories.
func (c *PreserveUnknownFieldsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCRD}
}

// SupportedModes returns which scan modes this check supports.
func (c *PreserveUnknownFieldsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PreserveUnknownFieldsChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CustomResourceDefinitionGVR}
}

// Run executes the crd-preserve-unknown-fields check.
func (c *PreserveUnknownFieldsChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("crd-preserve-unknown-fields check: %w", err)
	}

	crds := resources.List(CustomResourceDefinitionGVR)

	for _, crd := range crds {
		name := crd.GetName()

		preserve, found, _ := unstructured.NestedBool(crd.Object, "spec", "preserveUnknownFields")
		if !found || !preserve {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:  "crd-preserve-unknown-fields",
			Severity: checker.SeverityMedium,
			Resource: name,
			Kind:     "CustomResourceDefinition",
			Message:  fmt.Sprintf("CRD %q has spec.preserveUnknownFields: true, disabling OpenAPI pruning for every version.", name),
			Remediation: "## Why This Matters\n\n" +
				"The deprecated top-level `preserveUnknownFields: true` disables structural-schema pruning entirely for the CRD. " +
				"Any client can write arbitrary, unvalidated fields into every version of the custom resource, defeating the " +
				"guarantees a structural OpenAPI schema is supposed to provide and enabling injection into fields controllers " +
				"may not expect or sanitize.\n\n" +
				"## How to Fix\n\n" +
				"Remove `preserveUnknownFields` (or set it to `false`) and ensure every version defines a structural " +
				"`openAPIV3Schema`:\n\n" +
				"```yaml\nspec:\n  preserveUnknownFields: false\n  versions:\n    - name: v1\n      served: true\n      storage: true\n      schema:\n        openAPIV3Schema:\n          type: object\n          properties:\n            spec:\n              type: object\n```\n\n" +
				"Test existing custom resources against the new schema before rolling out -- previously-valid resources relying " +
				"on unknown fields may be rejected once pruning is enabled.\n\n" +
				"## Learn More\n\n" +
				"See https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#field-pruning " +
				"for structural schema requirements and field pruning behavior.",
			FieldPath:    ".spec.preserveUnknownFields",
			CurrentValue: true,
			DesiredValue: false,
			FixHint: &checker.FixHint{
				Safety:      checker.FixPotentiallyBreaking,
				Description: "Sets preserveUnknownFields to false so OpenAPI pruning applies.",
				Impact:      "Custom resources with fields not defined in the schema will have those fields pruned (silently dropped) or rejected, which can break clients or controllers that rely on undeclared fields.",
				Operation:   checker.FixOpSet,
			},
		})
	}

	return findings, nil
}
