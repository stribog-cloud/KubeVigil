package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ServiceTypeNodePortChecker detects Services exposed as NodePort, which bypass ingress
// controls and expose ports directly on all cluster nodes.
type ServiceTypeNodePortChecker struct{}

// Name returns the kebab-case check ID.
func (c *ServiceTypeNodePortChecker) Name() string { return "service-type-nodeport" }

// Description returns a human-readable description.
func (c *ServiceTypeNodePortChecker) Description() string {
	return "Detects Services exposed as NodePort, which bypass ingress controls and expose ports on all cluster nodes."
}

// Categories returns the check categories.
func (c *ServiceTypeNodePortChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *ServiceTypeNodePortChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ServiceTypeNodePortChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ServiceGVR}
}

// Run executes the service-type-nodeport check against all Services in the cache.
func (c *ServiceTypeNodePortChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("service-type-nodeport check: %w", err)
	}

	services := resources.List(ServiceGVR)
	var findings []checker.Finding

	for i := range services {
		svc := &services[i]
		svcType := serviceType(svc)
		if svcType != "NodePort" {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "service-type-nodeport",
			Severity:  checker.SeverityMedium,
			Resource:  svc.GetName(),
			Namespace: svc.GetNamespace(),
			Kind:      "Service",
			Message:   fmt.Sprintf("Service %q is exposed as NodePort, which bypasses ingress controls and exposes ports on all cluster nodes.", svc.GetName()),
			Remediation: "## Why This Matters\n\n" +
				"NodePort services open a port (30000-32767) on every node in the cluster, bypassing Ingress controllers and their centralized security controls. " +
				"Any network client that can reach a cluster node's IP address can access the service, significantly widening the attack surface.\n\n" +
				"## How to Fix\n\n" +
				"Replace the NodePort service with a ClusterIP service and expose it through an Ingress controller:\n\n" +
				"```yaml\napiVersion: v1\nkind: Service\nmetadata:\n  name: my-service\nspec:\n  type: ClusterIP\n  ports:\n    - port: 80\n      targetPort: 8080\n  selector:\n    app: my-app\n```\n\n" +
				"Ingress controllers centralize TLS termination, authentication, rate limiting, and access logging in a single entry point.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes Service documentation and CIS Kubernetes Benchmark 5.4. " +
				"If NodePort is unavoidable, restrict access using firewall rules to limit which source IPs can reach the node ports.",
			FieldPath: ".spec.type",
		})
	}

	return findings, nil
}
