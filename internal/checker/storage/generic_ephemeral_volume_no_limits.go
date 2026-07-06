package storage

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// GenericEphemeralVolumeNoLimitsChecker detects Pods using a generic ephemeral
// volume (spec.volumes[].ephemeral.volumeClaimTemplate) whose claim template
// has no resources.requests.storage limit, allowing unbounded per-pod
// dynamically-provisioned ephemeral storage consumption.
type GenericEphemeralVolumeNoLimitsChecker struct{}

// Name returns the kebab-case check ID.
func (c *GenericEphemeralVolumeNoLimitsChecker) Name() string {
	return "generic-ephemeral-volume-no-limits"
}

// Description returns a human-readable description.
func (c *GenericEphemeralVolumeNoLimitsChecker) Description() string {
	return "Detects generic ephemeral volumes whose claim template has no storage request, allowing unbounded consumption."
}

// Categories returns the check categories.
func (c *GenericEphemeralVolumeNoLimitsChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *GenericEphemeralVolumeNoLimitsChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *GenericEphemeralVolumeNoLimitsChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the generic-ephemeral-volume-no-limits check against all workload resources in the cache.
func (c *GenericEphemeralVolumeNoLimitsChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("generic-ephemeral-volume-no-limits check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		for j := range info.Spec.Volumes {
			vol := &info.Spec.Volumes[j]
			if vol.Ephemeral == nil || vol.Ephemeral.VolumeClaimTemplate == nil {
				continue
			}

			requests := vol.Ephemeral.VolumeClaimTemplate.Spec.Resources.Requests
			if requests != nil {
				if _, ok := requests[corev1.ResourceStorage]; ok {
					continue
				}
			}

			findings = append(findings, checker.Finding{
				Checker:   "generic-ephemeral-volume-no-limits",
				Severity:  checker.SeverityLow,
				Resource:  info.ResourceName,
				Namespace: info.Namespace,
				Kind:      info.Kind,
				Message:   fmt.Sprintf("%s %q has generic ephemeral volume %q without a storage request; the claim template can consume unbounded storage.", info.Kind, info.ResourceName, vol.Name),
				Remediation: "## Why This Matters\n\n" +
					"Generic ephemeral volumes dynamically provision a PVC per-pod from a claim template. Without a " +
					"resources.requests.storage value, provisioners may apply an implementation-defined default (or reject " +
					"the claim), and there is no declared upper bound on how much storage a single pod's ephemeral volume " +
					"can consume — the same unbounded-consumption risk that resource-limits-missing addresses for CPU/memory, " +
					"now for per-pod dynamically-provisioned storage.\n\n" +
					"## How to Fix\n\n" +
					"Set an explicit storage request on the ephemeral volume's claim template:\n\n" +
					"```yaml\nvolumes:\n  - name: scratch\n    ephemeral:\n      volumeClaimTemplate:\n        spec:\n          accessModes: [\"ReadWriteOnce\"]\n          resources:\n            requests:\n              storage: 5Gi           # Set to expected max usage\n```\n\n" +
					"Size conservatively based on expected workload usage and monitor actual consumption to tune the request.\n\n" +
					"## Learn More\n\n" +
					"See the Kubernetes Generic Ephemeral Volumes documentation. Bounding ephemeral storage requests protects " +
					"against a single pod exhausting cluster storage capacity.",
				FieldPath: fmt.Sprintf(".spec.volumes[%d].ephemeral.volumeClaimTemplate.spec.resources.requests.storage", j),
			})
		}
	}

	return findings, nil
}
