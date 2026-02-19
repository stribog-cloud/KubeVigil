package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ServiceTypeLoadBalancerChecker detects Services exposed as LoadBalancer, which create
// cloud load balancers that may be publicly accessible without proper access controls.
type ServiceTypeLoadBalancerChecker struct{}

// Name returns the kebab-case check ID.
func (c *ServiceTypeLoadBalancerChecker) Name() string { return "service-type-loadbalancer" }

// Description returns a human-readable description.
func (c *ServiceTypeLoadBalancerChecker) Description() string {
	return "Detects Services exposed as LoadBalancer, which create cloud load balancers that may be publicly accessible."
}

// Categories returns the check categories.
func (c *ServiceTypeLoadBalancerChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *ServiceTypeLoadBalancerChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ServiceTypeLoadBalancerChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ServiceGVR}
}

// Run executes the service-type-loadbalancer check against all Services in the cache.
func (c *ServiceTypeLoadBalancerChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("service-type-loadbalancer check: %w", err)
	}

	services := resources.List(ServiceGVR)
	var findings []checker.Finding

	for i := range services {
		svc := &services[i]
		svcType := serviceType(svc)
		if svcType != "LoadBalancer" {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "service-type-loadbalancer",
			Severity:  checker.SeverityMedium,
			Resource:  svc.GetName(),
			Namespace: svc.GetNamespace(),
			Kind:      "Service",
			Message:   fmt.Sprintf("Service %q is exposed as LoadBalancer, which creates a cloud load balancer that may be publicly accessible.", svc.GetName()),
			Remediation: "## Why This Matters\n\n" +
				"LoadBalancer services provision cloud load balancers that are often publicly accessible by default. " +
				"This exposes the service directly to the internet without centralized security controls such as TLS termination, authentication, WAF rules, and rate limiting that an Ingress controller provides.\n\n" +
				"## How to Fix\n\n" +
				"Replace the LoadBalancer service with a ClusterIP service and route traffic through an Ingress controller:\n\n" +
				"```yaml\napiVersion: v1\nkind: Service\nmetadata:\n  name: my-service\nspec:\n  type: ClusterIP\n  ports:\n    - port: 80\n      targetPort: 8080\n  selector:\n    app: my-app\n```\n\n" +
				"If a LoadBalancer is required, use cloud-specific annotations to restrict access (e.g., `service.beta.kubernetes.io/aws-load-balancer-internal: \"true\"`) and configure security groups.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes Service documentation and CIS Kubernetes Benchmark 5.4. " +
				"Minimize the use of LoadBalancer services and prefer Ingress controllers for centralized traffic management.",
			FieldPath: ".spec.type",
		})
	}

	return findings, nil
}

// serviceType extracts the .spec.type field from a Service, defaulting to "ClusterIP".
func serviceType(svc *unstructured.Unstructured) string {
	val, found, err := unstructured.NestedString(svc.Object, "spec", "type")
	if err != nil || !found || val == "" {
		return "ClusterIP"
	}
	return val
}
