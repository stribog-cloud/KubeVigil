package cloud

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ProviderDetectionChecker auto-detects the cloud provider from node labels
// and reports it as an informational finding.
type ProviderDetectionChecker struct{}

// Name returns the check ID.
func (c *ProviderDetectionChecker) Name() string { return "cloud-provider-detection" }

// Description returns a human-readable description.
func (c *ProviderDetectionChecker) Description() string {
	return "Auto-detects cloud provider (EKS, GKE, AKS) from node labels and reports for provider-specific check enablement."
}

// Categories returns the check categories.
func (c *ProviderDetectionChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryCloudProvider}
}

// SupportedModes returns which scan modes this check supports.
func (c *ProviderDetectionChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ProviderDetectionChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{NodeGVR}
}

// Run executes the cloud provider detection check.
func (c *ProviderDetectionChecker) Run(ctx context.Context, resources *checker.ResourceCache) (findings []checker.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cloud-provider-detection check: %w", err)
	}

	nodes := resources.List(NodeGVR)
	if len(nodes) == 0 {
		return nil, nil
	}

	provider := detectProvider(nodes)
	if provider == ProviderUnknown {
		return nil, nil
	}

	findings = append(findings, checker.Finding{
		Checker:  "cloud-provider-detection",
		Severity: checker.SeverityInfo,
		Resource: "cluster",
		Kind:     "Cluster",
		Message:  fmt.Sprintf("Detected cloud provider: %s. Provider-specific security checks are enabled.", string(provider)),
		Remediation: "## Why This Matters\n\n" +
			"This is an informational finding. KubeVigil auto-detected your cloud provider from node labels to enable " +
			"provider-specific security checks. No action is required unless the detection is incorrect.\n\n" +
			"## How to Fix\n\n" +
			"No fix needed. Review the provider-specific checks enabled for your cluster:\n\n" +
			"```yaml\n# Detection is based on node labels:\n# AWS/EKS:  eks.amazonaws.com/nodegroup\n# GCP/GKE:  cloud.google.com/gke-nodepool\n# Azure/AKS: kubernetes.azure.com/cluster\n```\n\n" +
			"Ensure you review findings from provider-specific checks (EKS IMDS access, GKE metadata concealment, AKS pod identity).\n\n" +
			"## Learn More\n\n" +
			"Each cloud provider has unique security considerations for Kubernetes. See your provider's security best practices: " +
			"AWS EKS Best Practices, GKE Hardening Guide, or AKS Security Baseline.",
	})

	return findings, nil
}
