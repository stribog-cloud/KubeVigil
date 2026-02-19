package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// DefaultDenyChecker detects namespaces that are missing a default-deny ingress
// or egress NetworkPolicy. A default-deny policy has an empty podSelector (selects
// all pods) and declares the policy type but defines no allow rules.
type DefaultDenyChecker struct{}

// Name returns the kebab-case check ID.
func (c *DefaultDenyChecker) Name() string { return "network-policy-default-deny" }

// Description returns a human-readable description.
func (c *DefaultDenyChecker) Description() string {
	return "Detects namespaces missing a default-deny ingress or egress NetworkPolicy."
}

// Categories returns the check categories.
func (c *DefaultDenyChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *DefaultDenyChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *DefaultDenyChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NetworkPolicyGVR, NamespaceGVR}
}

// Run executes the default-deny check against all Namespaces with NetworkPolicies.
func (c *DefaultDenyChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("network-policy-default-deny check: %w", err)
	}

	namespaces := resources.List(NamespaceGVR)
	var findings []checker.Finding

	for i := range namespaces {
		ns := &namespaces[i]
		name := ns.GetName()

		if isSystemNamespace(name) {
			continue
		}

		policies := resources.ListNamespaced(NetworkPolicyGVR, name)
		if len(policies) == 0 {
			// No policies at all — network-policy-missing handles this case.
			continue
		}

		hasDefaultDenyIngress := false
		hasDefaultDenyEgress := false

		for j := range policies {
			pol := &policies[j]
			if !isEmptyPodSelector(pol) {
				continue
			}

			policyTypes := getPolicyTypes(pol)

			if containsString(policyTypes, "Ingress") && isDefaultDenyIngress(pol) {
				hasDefaultDenyIngress = true
			}
			if containsString(policyTypes, "Egress") && isDefaultDenyEgress(pol) {
				hasDefaultDenyEgress = true
			}
		}

		if !hasDefaultDenyIngress {
			findings = append(findings, checker.Finding{
				Checker:   "network-policy-default-deny",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: name,
				Kind:      "Namespace",
				Message:   fmt.Sprintf("Namespace %q is missing a default-deny ingress NetworkPolicy.", name),
				Remediation: "## Why This Matters\n\n" +
					"Without a default-deny ingress policy, all inbound traffic to pods is allowed by default. " +
					"An attacker who gains access to any pod in the cluster can reach services in this namespace, enabling lateral movement and data theft.\n\n" +
					"## How to Fix\n\n" +
					"Create a default-deny ingress NetworkPolicy that selects all pods, then add specific allow rules for legitimate traffic:\n\n" +
					"```yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-ingress\n  namespace: my-namespace\nspec:\n  podSelector: {}\n  policyTypes:\n    - Ingress\n```\n\n" +
					"Then create additional policies with explicit `ingress.from` rules for each service that needs to receive traffic.\n\n" +
					"## Learn More\n\n" +
					"Refer to the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. " +
					"Default-deny is a zero-trust network best practice recommended by the NSA/CISA Kubernetes Hardening Guide.",
			})
		}

		if !hasDefaultDenyEgress {
			findings = append(findings, checker.Finding{
				Checker:   "network-policy-default-deny",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: name,
				Kind:      "Namespace",
				Message:   fmt.Sprintf("Namespace %q is missing a default-deny egress NetworkPolicy.", name),
				Remediation: "## Why This Matters\n\n" +
					"Without a default-deny egress policy, pods can send traffic to any destination, including the internet. " +
					"A compromised pod can exfiltrate sensitive data, contact command-and-control servers, or reach cloud metadata endpoints.\n\n" +
					"## How to Fix\n\n" +
					"Create a default-deny egress NetworkPolicy, then allow only required outbound traffic such as DNS:\n\n" +
					"```yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-egress\n  namespace: my-namespace\nspec:\n  podSelector: {}\n  policyTypes:\n    - Egress\n  egress:\n    - to:\n        - namespaceSelector: {}\n      ports:\n        - port: 53\n          protocol: UDP\n```\n\n" +
					"Add specific egress rules for each external dependency your workloads need.\n\n" +
					"## Learn More\n\n" +
					"Refer to the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. " +
					"Egress restrictions are critical for preventing data exfiltration and limiting blast radius after a compromise.",
			})
		}
	}

	return findings, nil
}

// isEmptyPodSelector returns true if the NetworkPolicy's podSelector is empty
// (i.e., selects all pods in the namespace).
func isEmptyPodSelector(pol *unstructured.Unstructured) bool {
	podSelector, found, _ := unstructured.NestedMap(pol.Object, "spec", "podSelector")
	if !found {
		// Missing podSelector is treated as empty (selects all pods).
		return true
	}
	// An empty map {} also selects all pods.
	return len(podSelector) == 0
}

// getPolicyTypes extracts the policyTypes list from a NetworkPolicy.
func getPolicyTypes(pol *unstructured.Unstructured) []string {
	raw, found, _ := unstructured.NestedSlice(pol.Object, "spec", "policyTypes")
	if !found {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// isDefaultDenyIngress returns true if the policy has no ingress rules or an empty ingress list,
// indicating it denies all inbound traffic.
func isDefaultDenyIngress(pol *unstructured.Unstructured) bool {
	ingress, found, _ := unstructured.NestedSlice(pol.Object, "spec", "ingress")
	// Not found or empty means default deny.
	return !found || len(ingress) == 0
}

// isDefaultDenyEgress returns true if the policy has no egress rules or an empty egress list,
// indicating it denies all outbound traffic.
func isDefaultDenyEgress(pol *unstructured.Unstructured) bool {
	egress, found, _ := unstructured.NestedSlice(pol.Object, "spec", "egress")
	// Not found or empty means default deny.
	return !found || len(egress) == 0
}
