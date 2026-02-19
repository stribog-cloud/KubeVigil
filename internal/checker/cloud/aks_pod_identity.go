package cloud

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// AKSPodIdentityChecker detects AKS clusters still using the deprecated
// aad-pod-identity instead of Azure Workload Identity.
type AKSPodIdentityChecker struct{}

// Name returns the check ID.
func (c *AKSPodIdentityChecker) Name() string { return "aks-pod-identity" }

// Description returns a human-readable description.
func (c *AKSPodIdentityChecker) Description() string {
	return "Detects AKS clusters using deprecated aad-pod-identity instead of Azure Workload Identity."
}

// Categories returns the check categories.
func (c *AKSPodIdentityChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCloudProvider}
}

// SupportedModes returns which scan modes this check supports.
func (c *AKSPodIdentityChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *AKSPodIdentityChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NodeGVR, DaemonSetGVR}
}

// Run executes the AKS pod identity check.
func (c *AKSPodIdentityChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("aks-pod-identity check: %w", err)
	}

	nodes := resources.List(NodeGVR)
	if detectProvider(nodes) != ProviderAKS {
		return nil, nil
	}

	// Look for aad-pod-identity DaemonSets (nmi or mic components).
	daemonsets := resources.List(DaemonSetGVR)
	for _, ds := range daemonsets {
		if isAADPodIdentityComponent(ds) {
			findings = append(findings, checker.Finding{
				Checker:   "aks-pod-identity",
				Severity:  checker.SeverityMedium,
				Resource:  ds.GetName(),
				Namespace: ds.GetNamespace(),
				Kind:      "DaemonSet",
				Message:   fmt.Sprintf("DaemonSet %q is a deprecated aad-pod-identity component. Migrate to Azure Workload Identity.", ds.GetName()),
				Remediation: "## Why This Matters\n\n" +
					"aad-pod-identity is deprecated and has known security vulnerabilities, including a NMI (Node Managed Identity) " +
					"component that runs as a privileged DaemonSet with host networking. It is no longer receiving security updates, leaving your cluster exposed.\n\n" +
					"## How to Fix\n\n" +
					"Migrate to Azure Workload Identity, which uses federated identity credentials:\n\n" +
					"```yaml\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: my-app-sa\n  annotations:\n    azure.workload.identity/client-id: <managed-identity-client-id>\n  labels:\n    azure.workload.identity/use: \"true\"\n```\n\n" +
					"After migrating all workloads, remove the aad-pod-identity DaemonSet components (nmi and mic) from the cluster.\n\n" +
					"## Learn More\n\n" +
					"See https://learn.microsoft.com/en-us/azure/aks/workload-identity-migrate-from-pod-identity for the official migration guide from aad-pod-identity to Azure Workload Identity.",
			})
		}
	}

	return findings, nil
}

// isAADPodIdentityComponent checks if a DaemonSet is part of aad-pod-identity.
func isAADPodIdentityComponent(ds unstructured.Unstructured) bool {
	name := strings.ToLower(ds.GetName())
	if strings.Contains(name, "aad-pod-identity") || strings.Contains(name, "nmi") || strings.Contains(name, "mic") {
		// Verify by checking container images.
		containers, _, _ := unstructured.NestedSlice(ds.Object, "spec", "template", "spec", "containers")
		for _, c := range containers {
			cm, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			image, _ := cm["image"].(string)
			if strings.Contains(image, "aad-pod-identity") || strings.Contains(image, "nmi") {
				return true
			}
		}
	}
	return false
}
