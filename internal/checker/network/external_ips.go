package network

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ExternalIPsChecker detects Services with externalIPs configured, which is a
// man-in-the-middle risk documented in CVE-2020-8554. An attacker with permission
// to create or update Services can intercept traffic destined for those IPs.
type ExternalIPsChecker struct{}

// Name returns the kebab-case check ID.
func (c *ExternalIPsChecker) Name() string { return "external-ips" }

// Description returns a human-readable description.
func (c *ExternalIPsChecker) Description() string {
	return "Detects Services with externalIPs set, which poses a man-in-the-middle risk (CVE-2020-8554)."
}

// Categories returns the check categories.
func (c *ExternalIPsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *ExternalIPsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ExternalIPsChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ServiceGVR}
}

// Run executes the external-ips check against all Services in the cache.
func (c *ExternalIPsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("external-ips check: %w", err)
	}

	services := resources.List(ServiceGVR)
	var findings []checker.Finding

	for i := range services {
		svc := &services[i]
		ips := externalIPs(svc)
		if len(ips) == 0 {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "external-ips",
			Severity:  checker.SeverityHigh,
			Resource:  svc.GetName(),
			Namespace: svc.GetNamespace(),
			Kind:      "Service",
			Message:   fmt.Sprintf("Service %q has externalIPs %s configured, posing a man-in-the-middle risk (CVE-2020-8554).", svc.GetName(), formatIPs(ips)),
			Remediation: "## Why This Matters\n\n" +
				"The `externalIPs` field allows a Service to claim arbitrary IP addresses, enabling CVE-2020-8554. " +
				"An attacker with permission to create or update Services can redirect traffic destined for any external IP through their own pods, performing man-in-the-middle attacks on cluster traffic.\n\n" +
				"## How to Fix\n\n" +
				"Remove the `externalIPs` field and use a LoadBalancer or Ingress to expose the service externally:\n\n" +
				"```yaml\napiVersion: v1\nkind: Service\nmetadata:\n  name: my-service\nspec:\n  type: LoadBalancer\n  ports:\n    - port: 443\n      targetPort: 8443\n  selector:\n    app: my-app\n  # externalIPs: []  # Remove this field entirely\n```\n\n" +
				"Enable the `DenyServiceExternalIPs` admission controller to prevent externalIPs usage cluster-wide.\n\n" +
				"## Learn More\n\n" +
				"See CVE-2020-8554 for details on the externalIPs man-in-the-middle vulnerability. " +
				"The Kubernetes documentation recommends using LoadBalancer or Ingress instead of externalIPs for production services.",
			FieldPath: ".spec.externalIPs",
		})
	}

	return findings, nil
}

// externalIPs extracts .spec.externalIPs from a Service resource.
func externalIPs(svc *unstructured.Unstructured) []string {
	val, found, err := unstructured.NestedStringSlice(svc.Object, "spec", "externalIPs")
	if err != nil || !found {
		return nil
	}
	return val
}

// formatIPs formats a list of IPs as a human-readable string.
func formatIPs(ips []string) string {
	return "[" + strings.Join(ips, ", ") + "]"
}
