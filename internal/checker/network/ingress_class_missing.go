package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// IngressClassMissingChecker detects Ingress resources without an ingressClassName
// or the deprecated kubernetes.io/ingress.class annotation. Without an ingress class,
// the Ingress may not be picked up by any controller or may be handled by the wrong one.
type IngressClassMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *IngressClassMissingChecker) Name() string { return "ingress-class-missing" }

// Description returns a human-readable description.
func (c *IngressClassMissingChecker) Description() string {
	return "Detects Ingress resources without ingressClassName or the deprecated ingress.class annotation."
}

// Categories returns the check categories.
func (c *IngressClassMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *IngressClassMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *IngressClassMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{IngressGVR}
}

// ingressClassAnnotation is the deprecated annotation key for specifying the ingress class.
const ingressClassAnnotation = "kubernetes.io/ingress.class"

// Run executes the ingress-class-missing check against all Ingress resources in the cache.
func (c *IngressClassMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ingress-class-missing check: %w", err)
	}

	ingresses := resources.List(IngressGVR)
	var findings []checker.Finding

	for i := range ingresses {
		ing := &ingresses[i]
		name := ing.GetName()
		namespace := ing.GetNamespace()

		if !hasIngressClass(ing) {
			findings = append(findings, checker.Finding{
				Checker:   "ingress-class-missing",
				Severity:  checker.SeverityLow,
				Resource:  name,
				Namespace: namespace,
				Kind:      "Ingress",
				Message:   fmt.Sprintf("Ingress %q has no ingressClassName or ingress.class annotation. It may not be handled by any ingress controller.", name),
				Remediation: "## Why This Matters\n\n" +
					"Without an explicit IngressClass, this Ingress relies on the cluster's default ingress controller. " +
					"If no default is configured, the Ingress may be silently ignored. If multiple controllers exist, the wrong one may claim it, leading to misrouted traffic or missing security configurations like WAF rules and rate limiting.\n\n" +
					"## How to Fix\n\n" +
					"Set the `ingressClassName` field to explicitly declare which controller should handle this Ingress:\n\n" +
					"```yaml\nspec:\n  ingressClassName: nginx\n  rules:\n    - host: app.example.com\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend:\n              service:\n                name: app\n                port:\n                  number: 80\n```\n\n" +
					"List available IngressClasses with `kubectl get ingressclass` to find the correct class name.\n\n" +
					"## Learn More\n\n" +
					"Refer to the Kubernetes IngressClass documentation. The deprecated `kubernetes.io/ingress.class` annotation " +
					"is still supported but `spec.ingressClassName` is the preferred approach in Kubernetes 1.18+.",
				FieldPath: ".spec.ingressClassName",
			})
		}
	}

	return findings, nil
}

// hasIngressClass returns true if the Ingress has either spec.ingressClassName set
// or the deprecated kubernetes.io/ingress.class annotation.
func hasIngressClass(ing *unstructured.Unstructured) bool {
	// Check spec.ingressClassName.
	className, found, _ := unstructured.NestedString(ing.Object, "spec", "ingressClassName")
	if found && className != "" {
		return true
	}

	// Check deprecated annotation.
	annotations := ing.GetAnnotations()
	if annotations != nil {
		if v, ok := annotations[ingressClassAnnotation]; ok && v != "" {
			return true
		}
	}

	return false
}
