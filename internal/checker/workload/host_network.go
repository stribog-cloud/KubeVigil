package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HostNetworkChecker detects pods with hostNetwork: true enabled.
// When hostNetwork is true, containers share the host's network namespace,
// bypassing Kubernetes network policies and gaining access to all host network
// interfaces and ports.
type HostNetworkChecker struct{}

// Name returns the kebab-case check ID.
func (c *HostNetworkChecker) Name() string { return "host-network" }

// Description returns a human-readable description.
func (c *HostNetworkChecker) Description() string {
	return "Detects pods with hostNetwork: true, which bypasses network policies and exposes the host network."
}

// Categories returns the check categories.
func (c *HostNetworkChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *HostNetworkChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *HostNetworkChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the host-network check against all workload resources in the cache.
func (c *HostNetworkChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("host-network check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		if !info.Spec.HostNetwork {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "host-network",
			Severity:  checker.SeverityCritical,
			Resource:  info.ResourceName,
			Namespace: info.Namespace,
			Kind:      info.Kind,
			Container: "",
			Message:   fmt.Sprintf("%s %q has hostNetwork enabled, bypassing network policies and exposing the host network.", info.Kind, info.ResourceName),
			Remediation: "## Why This Matters\n\n" +
				"Containers with hostNetwork bypass Kubernetes NetworkPolicies entirely and gain access to all network interfaces " +
				"on the node, including the node's IP address and loopback. An attacker can use this to sniff traffic from other pods, " +
				"access node-local services such as the kubelet API on port 10250, or impersonate the node on the network.\n\n" +
				"## How to Fix\n\n" +
				"Disable host networking in the pod spec and use Kubernetes Services for exposure:\n\n" +
				"```yaml\nspec:\n  hostNetwork: false\n```\n\n" +
				"Use ClusterIP Services, NodePort, LoadBalancer, or Ingress resources to expose your application. " +
				"Only CNI plugins, kube-proxy, and certain monitoring agents legitimately need host networking.\n\n" +
				"## Learn More\n\n" +
				"This aligns with CIS Benchmark 5.2.4 and the Pod Security Standards \"Baseline\" profile. " +
				"Network namespace isolation is essential for NetworkPolicy enforcement and cluster network segmentation.",
			FieldPath:    ".spec.hostNetwork",
			CurrentValue: true,
			DesiredValue: false,
			FixHint: &checker.FixHint{
				Safety:      checker.FixLikelySafe,
				Description: "Disables host network sharing.",
				Impact:      "Containers binding to host ports will lose network access.",
				Operation:   checker.FixOpSet,
			},
		})
	}

	return findings, nil
}
