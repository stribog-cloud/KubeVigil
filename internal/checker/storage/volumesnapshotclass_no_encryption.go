package storage

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// VolumeSnapshotClassNoEncryptionChecker detects VolumeSnapshotClass resources
// without an encryption parameter set. Snapshots of an encrypted volume are
// not automatically encrypted by every CSI driver unless the snapshot class
// explicitly requests it.
type VolumeSnapshotClassNoEncryptionChecker struct{}

// Name returns the kebab-case check ID.
func (c *VolumeSnapshotClassNoEncryptionChecker) Name() string {
	return "volumesnapshotclass-no-encryption"
}

// Description returns a human-readable description.
func (c *VolumeSnapshotClassNoEncryptionChecker) Description() string {
	return "Detects VolumeSnapshotClass resources without an encryption parameter configured."
}

// Categories returns the check categories.
func (c *VolumeSnapshotClassNoEncryptionChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *VolumeSnapshotClassNoEncryptionChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *VolumeSnapshotClassNoEncryptionChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{VolumeSnapshotClassGVR}
}

// Run executes the volumesnapshotclass-no-encryption check.
func (c *VolumeSnapshotClassNoEncryptionChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("volumesnapshotclass-no-encryption check: %w", err)
	}

	vscs := resources.List(VolumeSnapshotClassGVR)
	var findings []checker.Finding

	for i := range vscs {
		vsc := &vscs[i]
		name := vsc.GetName()

		params, _, _ := unstructured.NestedStringMap(vsc.Object, "parameters")
		if volumeSnapshotClassEncrypted(params) {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:  "volumesnapshotclass-no-encryption",
			Severity: checker.SeverityMedium,
			Resource: name,
			Kind:     "VolumeSnapshotClass",
			Message:  fmt.Sprintf("VolumeSnapshotClass %q has no encryption parameter configured; snapshots of encrypted volumes may not be encrypted at rest.", name),
			Remediation: "## Why This Matters\n\n" +
				"Not every CSI driver automatically encrypts a VolumeSnapshot just because the source volume was encrypted. " +
				"Without an explicit encryption parameter on the VolumeSnapshotClass, snapshot data — which contains a full " +
				"point-in-time copy of the volume's contents, including credentials, PII, or financial data — may be stored " +
				"unencrypted in the underlying snapshot storage.\n\n" +
				"## How to Fix\n\n" +
				"Set an encryption parameter on the VolumeSnapshotClass, matching your CSI driver's convention:\n\n" +
				"```yaml\napiVersion: snapshot.storage.k8s.io/v1\nkind: VolumeSnapshotClass\nmetadata:\n  name: encrypted-snapshots\ndriver: ebs.csi.aws.com\ndeletionPolicy: Delete\nparameters:\n  encrypted: \"true\"          # Or your CSI driver's equivalent key\n```\n\n" +
				"Each cloud provider's CSI driver has its own parameter name for snapshot encryption — consult its documentation.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes VolumeSnapshotClass documentation and your CSI driver's snapshot encryption guide. This " +
				"mirrors the same at-rest encryption rationale already applied to PVCs by pvc-no-encryption.",
			FieldPath: ".parameters",
		})
	}

	return findings, nil
}

// volumeSnapshotClassEncrypted returns true if the VolumeSnapshotClass parameters
// contain any recognized encryption indicator, reusing the same heuristic
// parameter-name list and matching logic as pvc-no-encryption.
func volumeSnapshotClassEncrypted(params map[string]string) bool {
	for _, key := range encryptionParameters {
		if val, ok := params[key]; ok {
			if val == "true" || val == "1" || val == "yes" || val != "" {
				return true
			}
		}
	}
	return false
}
