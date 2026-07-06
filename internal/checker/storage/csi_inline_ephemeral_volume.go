package storage

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// CSIInlineEphemeralVolumeChecker detects Pods using CSI ephemeral inline volumes
// (spec.volumes[].csi set directly on the pod), which bypass PVC/StorageClass
// admission entirely. Inline CSI volumes can grant node-level or credential
// access depending on the driver and skip the normal storage provisioning
// review path.
//
// NOTE: The spec for this check calls for comparing the driver against a
// configurable allowlist (mirroring image-registry-allowlist's policy-driven
// pattern). KubeVigil's policy configuration (internal/checker.Policies) does
// not yet have an AllowedCSIDrivers field — adding one is out of scope for
// this package. Until that policy surface exists, every inline CSI volume is
// flagged for manual review.
type CSIInlineEphemeralVolumeChecker struct{}

// Name returns the kebab-case check ID.
func (c *CSIInlineEphemeralVolumeChecker) Name() string { return "csi-inline-ephemeral-volume" }

// Description returns a human-readable description.
func (c *CSIInlineEphemeralVolumeChecker) Description() string {
	return "Detects Pods using CSI inline ephemeral volumes, which bypass PVC/StorageClass admission review."
}

// Categories returns the check categories.
func (c *CSIInlineEphemeralVolumeChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *CSIInlineEphemeralVolumeChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CSIInlineEphemeralVolumeChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the csi-inline-ephemeral-volume check against all workload resources in the cache.
func (c *CSIInlineEphemeralVolumeChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("csi-inline-ephemeral-volume check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		for j := range info.Spec.Volumes {
			vol := &info.Spec.Volumes[j]
			if vol.CSI == nil || vol.CSI.Driver == "" {
				continue
			}

			findings = append(findings, checker.Finding{
				Checker:   "csi-inline-ephemeral-volume",
				Severity:  checker.SeverityMedium,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q uses inline CSI ephemeral volume %q with driver %q, bypassing PVC/StorageClass provisioning review.", info.Kind, info.ResourceName, vol.Name, vol.CSI.Driver),
				Remediation: "## Why This Matters\n\n" +
					"CSI ephemeral inline volumes are declared directly on the pod (`spec.volumes[].csi`), skipping the normal " +
					"PVC/StorageClass provisioning path and any admission control built around it. Depending on the driver, " +
					"inline volumes can expose node-level resources or secrets (e.g. the Secrets Store CSI driver) directly to " +
					"the pod without the review a StorageClass-based PVC would typically receive.\n\n" +
					"## How to Fix\n\n" +
					"Prefer PVC-based provisioning through a reviewed StorageClass wherever possible:\n\n" +
					"```yaml\n# Instead of an inline CSI volume:\n# volumes:\n#   - name: v\n#     csi:\n#       driver: csi.example.com/secrets-store\nvolumes:\n  - name: v\n    persistentVolumeClaim:\n      claimName: reviewed-pvc\n```\n\n" +
					"If inline CSI volumes are required (e.g. Secrets Store CSI driver for injecting secrets), restrict which " +
					"drivers may be used via an admission policy (OPA Gatekeeper/Kyverno) and track approved drivers explicitly.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes CSI Ephemeral Volumes documentation and NSA/CISA Kubernetes Hardening Guide 1.3 " +
					"(minimize host resource access) for guidance on reviewing storage driver access.",
				FieldPath: fmt.Sprintf(".spec.volumes[%d].csi.driver", j),
			})
		}
	}

	return findings, nil
}
