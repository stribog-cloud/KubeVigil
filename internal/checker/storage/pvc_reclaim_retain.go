package storage

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// PVCReclaimRetainChecker detects PersistentVolumes with reclaimPolicy: Retain
// that are in Released state. These volumes contain data but are not bound to
// any claim, representing potential data exposure.
type PVCReclaimRetainChecker struct{}

// Name returns the kebab-case check ID.
func (c *PVCReclaimRetainChecker) Name() string { return "pvc-reclaim-retain" }

// Description returns a human-readable description.
func (c *PVCReclaimRetainChecker) Description() string {
	return "Detects PersistentVolumes with Retain reclaim policy in Released state, which may expose data."
}

// Categories returns the check categories.
func (c *PVCReclaimRetainChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *PVCReclaimRetainChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PVCReclaimRetainChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{PersistentVolumeGVR}
}

// Run executes the pvc-reclaim-retain check.
func (c *PVCReclaimRetainChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("pvc-reclaim-retain check: %w", err)
	}

	pvs := resources.List(PersistentVolumeGVR)
	var findings []checker.Finding

	for i := range pvs {
		pv := &pvs[i]
		reclaimPolicy, _, _ := unstructured.NestedString(pv.Object, "spec", "persistentVolumeReclaimPolicy")
		phase, _, _ := unstructured.NestedString(pv.Object, "status", "phase")

		if reclaimPolicy == "Retain" && phase == "Released" {
			findings = append(findings, checker.Finding{
				Checker:  "pvc-reclaim-retain",
				Severity: checker.SeverityMedium,
				Resource: pv.GetName(),
				Kind:     "PersistentVolume",
				Message:  fmt.Sprintf("PV %q has reclaimPolicy Retain and is in Released state; it contains data but is unbound.", pv.GetName()),
				Remediation: "## Why This Matters\n\n" +
					"PersistentVolumes with Retain policy keep their data even after the associated PVC is deleted. " +
					"When left in Released state, these volumes contain potentially sensitive data that is no longer managed " +
					"by any workload. If the volume is re-bound or the underlying storage is reused, the previous data may be exposed.\n\n" +
					"## How to Fix\n\n" +
					"Either clean up the released PV or change the reclaim policy:\n\n" +
					"```yaml\n# Option 1: Delete the released PV after backing up data\n# kubectl delete pv <pv-name>\n\n# Option 2: Change reclaim policy for future PVCs\napiVersion: storage.k8s.io/v1\nkind: StorageClass\nmetadata:\n  name: standard\nreclaimPolicy: Delete            # Automatically clean up on PVC deletion\n```\n\n" +
					"For sensitive data, ensure volumes are securely wiped before the PV is deleted or reused.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes PersistentVolume documentation on reclaim policies. Use Retain only when you have " +
					"operational procedures for manually managing released volume lifecycle and data cleanup.",
				FieldPath: ".spec.persistentVolumeReclaimPolicy",
			})
		}
	}

	return findings, nil
}
