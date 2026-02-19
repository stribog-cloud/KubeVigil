package storage

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// PVCNoEncryptionChecker detects PVCs using StorageClasses without encryption configuration.
// Cloud providers support encrypted volumes but it's not always the default.
type PVCNoEncryptionChecker struct{}

// Name returns the kebab-case check ID.
func (c *PVCNoEncryptionChecker) Name() string { return "pvc-no-encryption" }

// Description returns a human-readable description.
func (c *PVCNoEncryptionChecker) Description() string {
	return "Detects PVCs using StorageClasses without encryption configuration."
}

// Categories returns the check categories.
func (c *PVCNoEncryptionChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *PVCNoEncryptionChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PVCNoEncryptionChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{PersistentVolumeClaimGVR, StorageClassGVR}
}

// encryptionParameters are StorageClass parameters that indicate encryption is enabled.
var encryptionParameters = []string{
	"encrypted",
	"encryption",
	"csi.storage.k8s.io/encrypt",
	"disk-encryption-kms-key",
}

// Run executes the pvc-no-encryption check.
func (c *PVCNoEncryptionChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("pvc-no-encryption check: %w", err)
	}

	// Build StorageClass encryption map.
	scEncrypted := buildStorageClassEncryptionMap(resources)

	pvcs := resources.List(PersistentVolumeClaimGVR)
	var findings []checker.Finding

	for i := range pvcs {
		pvc := &pvcs[i]
		scName, _, _ := unstructured.NestedString(pvc.Object, "spec", "storageClassName")
		if scName == "" {
			continue
		}

		encrypted, known := scEncrypted[scName]
		if known && encrypted {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "pvc-no-encryption",
			Severity:  checker.SeverityMedium,
			Resource:  pvc.GetName(),
			Namespace: pvc.GetNamespace(),
			Kind:      "PersistentVolumeClaim",
			Message:   fmt.Sprintf("PVC %q uses StorageClass %q which has no encryption configuration.", pvc.GetName(), scName),
			Remediation: "## Why This Matters\n\n" +
				"PVCs without encryption store data in plaintext on the underlying disk. If the storage media is " +
				"decommissioned, stolen, or accessed by an unauthorized party, all data is readable. This is especially " +
				"critical for volumes storing credentials, PII, or financial data.\n\n" +
				"## How to Fix\n\n" +
				"Create a StorageClass with encryption enabled and reference it in your PVC:\n\n" +
				"```yaml\napiVersion: storage.k8s.io/v1\nkind: StorageClass\nmetadata:\n  name: encrypted-gp3\nprovisioner: ebs.csi.aws.com\nparameters:\n  encrypted: \"true\"\n  kmsKeyId: arn:aws:kms:...:key/...   # Optional: customer-managed key\n---\napiVersion: v1\nkind: PersistentVolumeClaim\nspec:\n  storageClassName: encrypted-gp3\n```\n\n" +
				"Each cloud provider has its own encryption parameter: AWS EBS (`encrypted: \"true\"`), GCP PD (CMEK via `disk-encryption-kms-key`), Azure Disk (SSE enabled by default).\n\n" +
				"## Learn More\n\n" +
				"See your cloud provider's CSI driver documentation for encryption configuration. The CIS Kubernetes Benchmark " +
				"recommends encrypting persistent volumes at rest.",
			FieldPath: ".spec.storageClassName",
		})
	}

	return findings, nil
}

// buildStorageClassEncryptionMap returns a map of StorageClass name → whether encryption is configured.
func buildStorageClassEncryptionMap(resources *checker.ResourceCache) map[string]bool {
	result := make(map[string]bool)
	scs := resources.List(StorageClassGVR)

	for i := range scs {
		sc := &scs[i]
		name := sc.GetName()
		params, _, _ := unstructured.NestedStringMap(sc.Object, "parameters")

		encrypted := false
		for _, key := range encryptionParameters {
			if val, ok := params[key]; ok {
				if val == "true" || val == "1" || val == "yes" || val != "" {
					encrypted = true
					break
				}
			}
		}
		result[name] = encrypted
	}
	return result
}
