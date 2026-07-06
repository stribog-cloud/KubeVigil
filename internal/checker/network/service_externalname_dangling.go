package network

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// clusterInternalExternalNameSuffixes lists externalName suffixes that resolve
// within the cluster itself rather than to an external DNS name, and therefore
// carry no dangling-DNS / subdomain-takeover risk.
var clusterInternalExternalNameSuffixes = []string{
	".svc.cluster.local",
	".svc",
}

// ServiceExternalNameDanglingChecker detects Services of type ExternalName
// pointing to an external DNS name, flagged for manual review as a
// dangling-DNS / subdomain-takeover risk.
type ServiceExternalNameDanglingChecker struct{}

// Name returns the kebab-case check ID.
func (c *ServiceExternalNameDanglingChecker) Name() string { return "service-externalname-dangling" }

// Description returns a human-readable description.
func (c *ServiceExternalNameDanglingChecker) Description() string {
	return "Detects Services of type ExternalName pointing to an external DNS name, a dangling-DNS / subdomain-takeover risk if the domain is ever deregistered."
}

// Categories returns the check categories.
func (c *ServiceExternalNameDanglingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *ServiceExternalNameDanglingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ServiceExternalNameDanglingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ServiceGVR}
}

// Run executes the service-externalname-dangling check against all Services in the cache.
func (c *ServiceExternalNameDanglingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("service-externalname-dangling check: %w", err)
	}

	services := resources.List(ServiceGVR)
	var findings []checker.Finding

	for i := range services {
		svc := &services[i]
		if serviceType(svc) != "ExternalName" {
			continue
		}

		externalName := externalNameOf(svc)
		if externalName == "" || isClusterInternalName(externalName) {
			continue
		}

		name := svc.GetName()
		namespace := svc.GetNamespace()
		findings = append(findings, checker.Finding{
			Checker:   "service-externalname-dangling",
			Severity:  checker.SeverityMedium,
			Resource:  name,
			Namespace: namespace,
			Kind:      "Service",
			Message:   fmt.Sprintf("Service %q is type ExternalName pointing to external domain %q. Review for dangling-DNS / subdomain-takeover risk.", name, externalName),
			Remediation: "## Why This Matters\n\n" +
				"An ExternalName Service makes the cluster's internal DNS resolve to an external domain you do not control the lifecycle of. " +
				"If that external domain is ever deregistered, expires, or is repointed by its registrar while cluster DNS still resolves through it, an attacker can register the abandoned domain and have every in-cluster caller of this Service name silently start talking to attacker-controlled infrastructure — the mechanism behind real-world subdomain-takeover incidents.\n\n" +
				"## How to Fix\n\n" +
				"Review this ExternalName Service to confirm the target domain is still owned and actively maintained by the expected third party:\n\n" +
				"```yaml\napiVersion: v1\nkind: Service\nmetadata:\n  name: vendor-api\nspec:\n  type: ExternalName\n  externalName: legacy-vendor-api.example-vendor.com\n```\n\n" +
				"Set up monitoring/alerting on the external domain's registration status, or replace the ExternalName Service with a pinned IP-based Endpoints object if the vendor's DNS posture cannot be trusted long-term.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes ExternalName Service documentation. " +
				"This finding is informational and requires manual review — the underlying domain's registration status cannot be verified from the manifest alone.",
			FieldPath: ".spec.externalName",
		})
	}

	return findings, nil
}

// externalNameOf extracts the .spec.externalName field from a Service.
func externalNameOf(svc *unstructured.Unstructured) string {
	val, _, _ := unstructured.NestedString(svc.Object, "spec", "externalName")
	return val
}

// isClusterInternalName returns true if the given externalName resolves
// within the cluster itself (e.g. *.svc.cluster.local), carrying no
// dangling-DNS risk.
func isClusterInternalName(externalName string) bool {
	for _, suffix := range clusterInternalExternalNameSuffixes {
		if strings.HasSuffix(externalName, suffix) {
			return true
		}
	}
	return false
}
