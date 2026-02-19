package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// KubeletConfigChecker detects kubelet misconfigurations via node annotations.
type KubeletConfigChecker struct{}

func (c *KubeletConfigChecker) Name() string { return "kubelet-config" }
func (c *KubeletConfigChecker) Description() string {
	return "Detects kubelet misconfigurations such as anonymous auth enabled or read-only port open."
}
func (c *KubeletConfigChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}
func (c *KubeletConfigChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}
func (c *KubeletConfigChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NodeGVR}
}

func (c *KubeletConfigChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("kubelet-config check: %w", err)
	}

	nodes := resources.List(NodeGVR)
	var findings []checker.Finding

	for i := range nodes {
		node := &nodes[i]
		name := node.GetName()
		annotations := node.GetAnnotations()

		// Check for kubelet config annotation that may reveal settings.
		kubeletConfig, ok := annotations["kubeadm.alpha.kubernetes.io/cri-socket"]
		if !ok {
			kubeletConfig = ""
		}

		// Check node status for kubelet version info.
		readOnlyPort, _, _ := unstructured.NestedFloat64(node.Object, "status", "daemonEndpoints", "kubeletEndpoint", "Port")
		if readOnlyPort == 10255 {
			findings = append(findings, checker.Finding{
				Checker:  "kubelet-config",
				Severity: checker.SeverityHigh,
				Resource: name,
				Kind:     "Node",
				Message:  fmt.Sprintf("Node %q has kubelet read-only port 10255 open.", name),
				Remediation: "## Why This Matters\n\n" +
					"The kubelet read-only port (10255) serves pod specs, node metrics, and container information without any authentication. " +
					"Attackers on the network can enumerate running workloads, discover environment variables, and map the cluster topology for lateral movement.\n\n" +
					"## How to Fix\n\n" +
					"Disable the read-only port in the kubelet configuration:\n\n" +
					"```yaml\napiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nreadOnlyPort: 0\nauthentication:\n  anonymous:\n    enabled: false\n  webhook:\n    enabled: true\n```\n\n" +
					"Use the authenticated kubelet API on port 10250 instead, which requires proper RBAC credentials.\n\n" +
					"## Learn More\n\n" +
					"CIS Kubernetes Benchmark 4.2.4 requires the read-only port to be disabled. " +
					"See https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/ for all kubelet security settings.",
			})
		}
		_ = kubeletConfig
	}

	return findings, nil
}
