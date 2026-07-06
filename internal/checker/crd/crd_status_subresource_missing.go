package crd

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// StatusSubresourceMissingChecker detects CRD versions whose schema defines a
// status object but do not enable the status subresource, allowing any
// client with spec write access to also overwrite status directly.
type StatusSubresourceMissingChecker struct{}

// Name returns the check ID.
func (c *StatusSubresourceMissingChecker) Name() string { return "crd-status-subresource-missing" }

// Description returns a human-readable description.
func (c *StatusSubresourceMissingChecker) Description() string {
	return "Detects CRD versions whose schema defines a status object but do not enable subresources.status, letting any writer overwrite status."
}

// Categories returns the check categories.
func (c *StatusSubresourceMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCRD}
}

// SupportedModes returns which scan modes this check supports.
func (c *StatusSubresourceMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *StatusSubresourceMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CustomResourceDefinitionGVR}
}

// Run executes the crd-status-subresource-missing check.
func (c *StatusSubresourceMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("crd-status-subresource-missing check: %w", err)
	}

	crds := resources.List(CustomResourceDefinitionGVR)

	for _, crd := range crds {
		name := crd.GetName()

		versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
		for idx, v := range versions {
			vm, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			if !versionHasStatusProperty(vm) {
				continue
			}
			if versionHasStatusSubresource(vm) {
				continue
			}

			versionName, _, _ := unstructured.NestedString(vm, "name")

			findings = append(findings, checker.Finding{
				Checker:  "crd-status-subresource-missing",
				Severity: checker.SeverityMedium,
				Resource: name,
				Kind:     "CustomResourceDefinition",
				Message:  fmt.Sprintf("CRD %q version %q defines a status schema but does not enable subresources.status.", name, versionName),
				Remediation: "## Why This Matters\n\n" +
					"Without the `status` subresource enabled, there is only one write endpoint for the custom resource -- any " +
					"client with permission to update the resource's `spec` can also arbitrarily overwrite its `status`. Controllers " +
					"frequently treat `status` as authoritative state they alone should write; without the subresource split, " +
					"application clients can corrupt that state (accidentally or maliciously), breaking the spec/status separation " +
					"Kubernetes controllers rely on for correctness and, in some designs, for coarse-grained authorization.\n\n" +
					"## How to Fix\n\n" +
					"Enable the status subresource for the version and define a `status` property in its schema:\n\n" +
					"```yaml\nspec:\n  versions:\n    - name: v1\n      served: true\n      storage: true\n      subresources:\n        status: {}\n      schema:\n        openAPIV3Schema:\n          type: object\n          properties:\n            spec:\n              type: object\n            status:\n              type: object\n```\n\n" +
					"Update controller RBAC to grant `update`/`patch` on the `<resource>/status` subresource separately from the " +
					"main resource.\n\n" +
					"## Learn More\n\n" +
					"See https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#status-subresource " +
					"for status subresource semantics and RBAC implications.",
				FieldPath: fmt.Sprintf(".spec.versions[%d].subresources.status", idx),
			})
		}
	}

	return findings, nil
}

// versionHasStatusProperty returns true if the version's OpenAPI v3 schema
// declares a top-level "status" property.
func versionHasStatusProperty(version map[string]interface{}) bool {
	props, found, _ := unstructured.NestedMap(version, "schema", "openAPIV3Schema", "properties")
	if !found {
		return false
	}
	_, ok := props["status"]
	return ok
}

// versionHasStatusSubresource returns true if the version enables the status subresource.
func versionHasStatusSubresource(version map[string]interface{}) bool {
	_, found, _ := unstructured.NestedMap(version, "subresources", "status")
	return found
}
