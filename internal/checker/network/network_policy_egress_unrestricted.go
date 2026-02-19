package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// EgressUnrestrictedChecker detects namespaces without any egress NetworkPolicy
// restrictions. Without egress policies, pods can reach any external destination.
type EgressUnrestrictedChecker struct{}

// Name returns the kebab-case check ID.
func (c *EgressUnrestrictedChecker) Name() string { return "network-policy-egress-unrestricted" }

// Description returns a human-readable description.
func (c *EgressUnrestrictedChecker) Description() string {
	return "Detects namespaces without egress NetworkPolicy restrictions, allowing pods to reach any external destination."
}

// Categories returns the check categories.
func (c *EgressUnrestrictedChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *EgressUnrestrictedChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EgressUnrestrictedChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NetworkPolicyGVR, NamespaceGVR}
}

// Run executes the egress-unrestricted check against all Namespaces in the cache.
func (c *EgressUnrestrictedChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("network-policy-egress-unrestricted check: %w", err)
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
		hasEgressPolicy := false

		for j := range policies {
			pol := &policies[j]
			policyTypes := getPolicyTypes(pol)
			if containsString(policyTypes, "Egress") {
				hasEgressPolicy = true
				break
			}
		}

		if !hasEgressPolicy {
			findings = append(findings, checker.Finding{
				Checker:   "network-policy-egress-unrestricted",
				Severity:  checker.SeverityMedium,
				Resource:  name,
				Namespace: name,
				Kind:      "Namespace",
				Message:   fmt.Sprintf("Namespace %q has no NetworkPolicy with egress restrictions. Pods can reach any external destination.", name),
				Remediation: "## Why This Matters\n\n" +
					"Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. " +
					"A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.\n\n" +
					"## How to Fix\n\n" +
					"Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:\n\n" +
					"```yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: restrict-egress\n  namespace: my-namespace\nspec:\n  podSelector: {}\n  policyTypes:\n    - Egress\n  egress:\n    - to:\n        - namespaceSelector: {}\n      ports:\n        - port: 53\n          protocol: UDP\n```\n\n" +
					"Add additional egress rules for specific services your workloads need to reach.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. " +
					"Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.",
			})
		}
	}

	return findings, nil
}
