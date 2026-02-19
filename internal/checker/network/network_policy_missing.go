package network

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// PolicyMissingChecker detects namespaces that have no NetworkPolicy defined,
// leaving all pods in the namespace without any network-level access controls.
type PolicyMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *PolicyMissingChecker) Name() string { return "network-policy-missing" }

// Description returns a human-readable description.
func (c *PolicyMissingChecker) Description() string {
	return "Detects namespaces with no NetworkPolicy defined, leaving pods without network-level access controls."
}

// Categories returns the check categories.
func (c *PolicyMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryNetwork}
}

// SupportedModes returns which scan modes this check supports.
func (c *PolicyMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PolicyMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NetworkPolicyGVR, NamespaceGVR}
}

// Run executes the network-policy-missing check against all Namespaces in the cache.
func (c *PolicyMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("network-policy-missing check: %w", err)
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
			findings = append(findings, checker.Finding{
				Checker:   "network-policy-missing",
				Severity:  checker.SeverityHigh,
				Resource:  name,
				Namespace: name,
				Kind:      "Namespace",
				Message:   fmt.Sprintf("Namespace %q has no NetworkPolicy defined. All pods are unrestricted.", name),
				Remediation: "## Why This Matters\n\n" +
					"Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. " +
					"If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.\n\n" +
					"## How to Fix\n\n" +
					"Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:\n\n" +
					"```yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-all\n  namespace: my-namespace\nspec:\n  podSelector: {}\n  policyTypes:\n    - Ingress\n    - Egress\n```\n\n" +
					"After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. " +
					"A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.",
			})
		}
	}

	return findings, nil
}
