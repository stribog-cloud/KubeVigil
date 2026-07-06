package network

import (
	"context"
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// metadataServiceIP is the cloud instance-metadata IP shared across
// AWS/GCP/Azure/DigitalOcean (the link-local address 169.254.169.254).
var metadataServiceIP = net.ParseIP("169.254.169.254")

// MetadataServiceEgressChecker detects namespaces running non-hostNetwork
// workloads that lack an egress NetworkPolicy blocking the cloud
// instance-metadata IP (169.254.169.254) — the standard mitigation for
// SSRF-to-cloud-credential-theft.
type MetadataServiceEgressChecker struct{}

// Name returns the kebab-case check ID.
func (c *MetadataServiceEgressChecker) Name() string { return "metadata-service-egress-unblocked" }

// Description returns a human-readable description.
func (c *MetadataServiceEgressChecker) Description() string {
	return "Detects namespaces with workloads but no NetworkPolicy blocking egress to the cloud instance-metadata IP (169.254.169.254)."
}

// Categories returns the check categories.
func (c *MetadataServiceEgressChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *MetadataServiceEgressChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *MetadataServiceEgressChecker) RequiredResources() []schema.GroupVersionResource {
	resources := []schema.GroupVersionResource{NetworkPolicyGVR, NamespaceGVR}
	resources = append(resources, workload.GVRs()...)
	return resources
}

// Run executes the metadata-service-egress-unblocked check against all Namespaces in the cache.
func (c *MetadataServiceEgressChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("metadata-service-egress-unblocked check: %w", err)
	}

	namespaces := resources.List(NamespaceGVR)
	if len(namespaces) == 0 {
		return nil, nil
	}

	workloadNamespaces := namespacesWithNonHostNetworkWorkloads(resources)
	var findings []checker.Finding

	for i := range namespaces {
		ns := &namespaces[i]
		name := ns.GetName()

		if isSystemNamespace(name) || !workloadNamespaces[name] {
			continue
		}

		policies := resources.ListNamespaced(NetworkPolicyGVR, name)
		if namespaceBlocksMetadataEgress(policies) {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "metadata-service-egress-unblocked",
			Severity:  checker.SeverityHigh,
			Resource:  name,
			Namespace: name,
			Kind:      "Namespace",
			Message:   fmt.Sprintf("Namespace %q runs workloads but has no NetworkPolicy blocking egress to the cloud instance-metadata IP (169.254.169.254).", name),
			Remediation: "## Why This Matters\n\n" +
				"The cloud instance-metadata endpoint at 169.254.169.254 serves node-level credentials and identity documents to any process that can reach it — the exact chain used in the 2019 Capital One breach (SSRF against an application, followed by metadata-service credential theft). " +
				"Without an egress NetworkPolicy blocking this address, any compromised pod in this namespace (via SSRF, RCE, or a malicious dependency) can reach the metadata service directly and steal the node's cloud IAM credentials.\n\n" +
				"## How to Fix\n\n" +
				"Add an egress NetworkPolicy that either denies all egress by default, or explicitly excludes the metadata IP from any allowed CIDR range:\n\n" +
				"```yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: deny-metadata-egress\n  namespace: my-namespace\nspec:\n  podSelector: {}\n  policyTypes:\n    - Egress\n  egress:\n    - to:\n        - ipBlock:\n            cidr: 0.0.0.0/0\n            except:\n              - 169.254.169.254/32\n```\n\n" +
				"This is cloud-agnostic and complements provider-specific mitigations like requiring IMDSv2 on AWS or GKE Workload Identity/metadata concealment.\n\n" +
				"## Learn More\n\n" +
				"See the NSA/CISA Kubernetes Hardening Guide on egress restrictions and MITRE ATT&CK T1552.005 (Cloud Instance Metadata API). " +
				"Blocking 169.254.169.254 at the NetworkPolicy layer protects every workload in the namespace regardless of application-level SSRF defenses.",
		})
	}

	return findings, nil
}

// namespacesWithNonHostNetworkWorkloads returns the set of namespace names
// that contain at least one Pod-owning workload not using hostNetwork.
// hostNetwork pods share the node's network stack directly and are not
// governed by NetworkPolicy, so they are excluded from this check's scope.
func namespacesWithNonHostNetworkWorkloads(cache *checker.ResourceCache) map[string]bool {
	podSpecs := workload.ExtractPodSpecs(cache)
	namespaces := make(map[string]bool, len(podSpecs))
	for i := range podSpecs {
		if !podSpecs[i].Spec.HostNetwork {
			namespaces[podSpecs[i].Namespace] = true
		}
	}
	return namespaces
}

// namespaceBlocksMetadataEgress returns true if any Egress-type NetworkPolicy
// applying to all pods in the namespace (empty podSelector) prevents reaching
// the cloud metadata IP.
func namespaceBlocksMetadataEgress(policies []unstructured.Unstructured) bool {
	for i := range policies {
		pol := &policies[i]
		if !isEmptyPodSelector(pol) {
			continue
		}
		if !containsString(getPolicyTypes(pol), "Egress") {
			continue
		}
		if egressBlocksMetadataIP(pol) {
			return true
		}
	}
	return false
}

// egressBlocksMetadataIP returns true if the policy's egress rules do not
// allow traffic to the metadata IP. An absent or empty egress rule list is a
// default-deny, which blocks everything including the metadata IP.
func egressBlocksMetadataIP(pol *unstructured.Unstructured) bool {
	egress, found, _ := unstructured.NestedSlice(pol.Object, "spec", "egress")
	if !found || len(egress) == 0 {
		return true
	}

	for _, rule := range egress {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		if egressRuleAllowsMetadataIP(ruleMap) {
			return false
		}
	}

	return true
}

// egressRuleAllowsMetadataIP returns true if a single egress rule's "to" peers
// permit traffic to the metadata IP. An absent or empty "to" list means the
// rule is unrestricted and allows all destinations, including the metadata IP.
func egressRuleAllowsMetadataIP(ruleMap map[string]interface{}) bool {
	to, hasTo := ruleMap["to"]
	if !hasTo {
		return true
	}

	toSlice, ok := to.([]interface{})
	if !ok || len(toSlice) == 0 {
		return true
	}

	for _, peer := range toSlice {
		peerMap, ok := peer.(map[string]interface{})
		if !ok {
			continue
		}

		ipBlock, ok := peerMap["ipBlock"].(map[string]interface{})
		if !ok {
			// podSelector/namespaceSelector peers only ever resolve to
			// in-cluster pod IPs — they cannot grant reachability to an
			// external link-local address like the metadata IP.
			continue
		}

		if ipBlockAllowsMetadataIP(ipBlock) {
			return true
		}
	}

	return false
}

// ipBlockAllowsMetadataIP returns true if the ipBlock's cidr covers the
// metadata IP and no entry in its except list carves that address back out.
func ipBlockAllowsMetadataIP(ipBlock map[string]interface{}) bool {
	cidr, _ := ipBlock["cidr"].(string)
	if cidr == "" {
		return false
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil || !network.Contains(metadataServiceIP) {
		return false
	}

	except, _ := ipBlock["except"].([]interface{})
	for _, e := range except {
		exceptCIDR, ok := e.(string)
		if !ok {
			continue
		}
		if _, exceptNet, err := net.ParseCIDR(exceptCIDR); err == nil && exceptNet.Contains(metadataServiceIP) {
			return false
		}
	}

	return true
}
