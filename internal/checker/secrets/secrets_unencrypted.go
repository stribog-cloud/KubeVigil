package secrets

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// namespaceGVR is the GVR for Namespace resources.
var namespaceGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}

// managedClusterLabels contains labels that indicate a managed Kubernetes cluster.
// If any namespace (typically kube-system) has one of these labels, we assume encryption
// at rest is managed by the cloud provider.
var managedClusterLabels = []string{
	"eks.amazonaws.com/component",
	"cloud.google.com/gke-version",
	"addonmanager.kubernetes.io/mode",
	"kubernetes.azure.com/managedby",
}

// managedClusterAnnotations contains annotations that indicate a managed Kubernetes cluster.
var managedClusterAnnotations = []string{
	"eks.amazonaws.com/nodegroup",
	"cloud.google.com/gke-nodepool",
	"kubernetes.azure.com/agentpool",
}

// UnencryptedChecker detects when the cluster may not have encryption at rest configured
// for Secrets. This is a heuristic check since EncryptionConfiguration is not directly
// queryable via the standard Kubernetes API.
type UnencryptedChecker struct{}

// Name returns the kebab-case check ID.
func (c *UnencryptedChecker) Name() string { return "secrets-unencrypted" }

// Description returns a human-readable description.
func (c *UnencryptedChecker) Description() string {
	return "Detects when the cluster may not have encryption at rest configured for Secrets. Uses heuristics since EncryptionConfiguration is not queryable via the standard API."
}

// Categories returns the check categories.
func (c *UnencryptedChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategorySecrets}
}

// SupportedModes returns which scan modes this check supports.
// This check is live-only since encryption at rest is not detectable from manifests.
func (c *UnencryptedChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *UnencryptedChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{namespaceGVR}
}

// Run executes the secrets-unencrypted check against cluster namespaces.
func (c *UnencryptedChecker) Run(ctx context.Context, cache *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("secrets-unencrypted check: %w", err)
	}

	namespaces := cache.List(namespaceGVR)

	// No namespaces in cache means no data to analyze.
	if len(namespaces) == 0 {
		return nil, nil
	}

	// Check if the cluster appears to be a managed Kubernetes service.
	if isManagedCluster(namespaces) {
		return nil, nil
	}

	// Cannot verify encryption at rest — emit advisory finding.
	return []checker.Finding{
		{
			Checker:   "secrets-unencrypted",
			Severity:  checker.SeverityCritical,
			Resource:  "etcd",
			Namespace: "",
			Kind:      "Cluster",
			Message:   "Cluster etcd encryption at rest could not be verified. Ensure EncryptionConfiguration is enabled for Secret resources.",
			Remediation: "## Why This Matters\n\n" +
				"By default, Kubernetes stores Secrets as base64-encoded plaintext in etcd. " +
				"Anyone with direct etcd access or an etcd backup can read every secret in the " +
				"cluster, including database passwords, API keys, and TLS private keys.\n\n" +
				"## How to Fix\n\n" +
				"Configure encryption at rest via the API server EncryptionConfiguration:\n\n" +
				"```yaml\napiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: [secrets]\n    providers:\n      - aescbc:\n          keys:\n            - name: key1\n              secret: <base64-encoded-key>\n      - identity: {}\n```\n\n" +
				"For managed clusters (EKS, GKE, AKS), enable the cloud-native KMS envelope " +
				"encryption option. For self-managed clusters, use a KMS provider or the " +
				"secretbox provider for local encryption.\n\n" +
				"## Learn More\n\n" +
				"CIS Kubernetes Benchmark 1.2.29 requires encryption at rest for etcd. " +
				"See the Kubernetes encrypting data at rest documentation for setup details.",
		},
	}, nil
}

// isManagedCluster checks whether the cluster appears to be a managed Kubernetes service
// by inspecting namespace labels and annotations for cloud provider markers.
func isManagedCluster(namespaces []unstructured.Unstructured) bool {
	for i := range namespaces {
		ns := &namespaces[i]
		labels := ns.GetLabels()
		annotations := ns.GetAnnotations()

		for _, label := range managedClusterLabels {
			if _, ok := labels[label]; ok {
				return true
			}
		}
		for _, annotation := range managedClusterAnnotations {
			if _, ok := annotations[annotation]; ok {
				return true
			}
		}
	}
	return false
}
