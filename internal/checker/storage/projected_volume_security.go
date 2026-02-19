package storage

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// ProjectedVolumeSecurityChecker detects projected volumes with defaultMode that's
// too permissive (world-readable token files). Should be 0600 or 0400.
type ProjectedVolumeSecurityChecker struct{}

// Name returns the kebab-case check ID.
func (c *ProjectedVolumeSecurityChecker) Name() string { return "projected-volume-security" }

// Description returns a human-readable description.
func (c *ProjectedVolumeSecurityChecker) Description() string {
	return "Detects projected volumes with overly permissive defaultMode (should be 0600 or less)."
}

// Categories returns the check categories.
func (c *ProjectedVolumeSecurityChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *ProjectedVolumeSecurityChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *ProjectedVolumeSecurityChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// maxSafeMode is the maximum file mode considered safe for projected volumes (0600 = owner rw).
const maxSafeMode int32 = 0o600

// Run executes the projected-volume-security check.
func (c *ProjectedVolumeSecurityChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("projected-volume-security check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		for j := range info.Spec.Volumes {
			if info.Spec.Volumes[j].Projected == nil {
				continue
			}

			vol := &info.Spec.Volumes[j]
			mode := vol.Projected.DefaultMode
			if mode == nil {
				// Kubernetes default is 0644, which is too permissive.
				findings = append(findings, checker.Finding{
					Checker:   "projected-volume-security",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Message:   fmt.Sprintf("%s %q has projected volume %q with default mode 0644 (Kubernetes default); token files are world-readable.", info.Kind, info.ResourceName, vol.Name),
					Remediation: fmt.Sprintf("## Why This Matters\n\n"+
						"The Kubernetes default file mode for projected volumes is 0644 (world-readable). This means any process "+
						"in the pod can read service account tokens, secrets, and configmaps mounted via projected volumes. "+
						"An attacker who gains code execution in one container can harvest credentials from these files.\n\n"+
						"## How to Fix\n\n"+
						"Set a restrictive defaultMode on the projected volume:\n\n"+
						"```yaml\nspec:\n  volumes:\n    - name: %s\n      projected:\n        defaultMode: 0400         # Owner read-only\n        sources:\n          - serviceAccountToken:\n              path: token\n```\n\n"+
						"Use 0400 (owner read-only) for tokens, or 0600 (owner read-write) if the application needs to modify the files.\n\n"+
						"## Learn More\n\n"+
						"See the Kubernetes Projected Volumes documentation. The CIS Benchmark recommends restricting file permissions "+
						"on mounted secrets and tokens to prevent unauthorized access within the pod.", vol.Name),
					FieldPath: fmt.Sprintf(".spec.volumes[%d].projected.defaultMode", j),
				})
				continue
			}

			if *mode > maxSafeMode {
				findings = append(findings, checker.Finding{
					Checker:   "projected-volume-security",
					Severity:  checker.SeverityMedium,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Message:   fmt.Sprintf("%s %q has projected volume %q with defaultMode %#o which is too permissive.", info.Kind, info.ResourceName, vol.Name, *mode),
					Remediation: fmt.Sprintf("## Why This Matters\n\n"+
						"Projected volumes with overly permissive file modes allow any process in the pod to read sensitive data "+
						"such as service account tokens and secrets. If a container is compromised, the attacker can easily "+
						"harvest these credentials to escalate privileges or move laterally within the cluster.\n\n"+
						"## How to Fix\n\n"+
						"Reduce the defaultMode to restrict file access:\n\n"+
						"```yaml\nspec:\n  volumes:\n    - name: %s\n      projected:\n        defaultMode: 0400         # Owner read-only (was too permissive)\n        sources:\n          - serviceAccountToken:\n              path: token\n```\n\n"+
						"Use 0400 for read-only access or 0600 if the application must write to the mounted files.\n\n"+
						"## Learn More\n\n"+
						"See the Kubernetes Projected Volumes documentation for defaultMode details. The CIS Benchmark recommends "+
						"file modes of 0600 or lower for sensitive volume mounts to limit exposure within the pod.", vol.Name),
					FieldPath: fmt.Sprintf(".spec.volumes[%d].projected.defaultMode", j),
				})
			}
		}
	}

	return findings, nil
}
