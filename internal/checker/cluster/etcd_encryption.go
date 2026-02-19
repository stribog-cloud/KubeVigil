package cluster

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// EtcdEncryptionChecker detects when etcd encryption is not configured.
type EtcdEncryptionChecker struct{}

// Name returns the kebab-case identifier for this check.
func (c *EtcdEncryptionChecker) Name() string { return "etcd-encryption" }

// Description returns a human-readable summary of what this check detects.
func (c *EtcdEncryptionChecker) Description() string {
	return "Detects etcd encryption configuration status; secrets may be stored in plaintext."
}

// Categories returns the security categories this check belongs to.
func (c *EtcdEncryptionChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryClusterConfig}
}

// SupportedModes returns the scan modes (manifest, live, or both) that support this check.
func (c *EtcdEncryptionChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes GVRs this check needs to operate.
func (c *EtcdEncryptionChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{ConfigMapGVR}
}

// Run executes the check against cached resources and returns any findings.
func (c *EtcdEncryptionChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("etcd-encryption check: %w", err)
	}

	cms := resources.ListNamespaced(ConfigMapGVR, "kube-system")
	var findings []checker.Finding

	encryptionFound := false
	for i := range cms {
		cm := &cms[i]
		name := cm.GetName()
		if name != "kubeadm-config" && name != "kube-apiserver" {
			continue
		}

		data, found, _ := unstructured.NestedStringMap(cm.Object, "data")
		if !found {
			continue
		}

		for _, v := range data {
			if containsFlag(v, "--encryption-provider-config") {
				encryptionFound = true
				break
			}
		}
	}

	if len(cms) > 0 && !encryptionFound {
		findings = append(findings, checker.Finding{
			Checker:   "etcd-encryption",
			Severity:  checker.SeverityCritical,
			Resource:  "kube-apiserver",
			Namespace: "kube-system",
			Kind:      "ConfigMap",
			Message:   "No etcd encryption configuration found; secrets may be stored in plaintext in etcd.",
			Remediation: "## Why This Matters\n\n" +
				"Without encryption at rest, all Kubernetes Secrets are stored as plaintext in etcd. " +
				"Anyone with access to etcd backups, snapshots, or the etcd data directory can read every secret in the cluster, including database passwords, API keys, and TLS certificates.\n\n" +
				"## How to Fix\n\n" +
				"Configure an EncryptionConfiguration and pass it to the API server:\n\n" +
				"```yaml\napiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: [secrets]\n    providers:\n      - aescbc:\n          keys:\n            - name: key1\n              secret: <base64-encoded-key>\n      - identity: {}\n```\n\n" +
				"Then add `--encryption-provider-config=/path/to/config.yaml` to the API server flags. On managed clusters (EKS, GKE, AKS), enable KMS-backed envelope encryption through the provider console.\n\n" +
				"## Learn More\n\n" +
				"CIS Kubernetes Benchmark 1.2.29 requires encryption at rest for etcd. " +
				"See https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/ for setup and key rotation procedures.",
		})
	}

	return findings, nil
}
