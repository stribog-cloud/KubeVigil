package storage

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// EmptyDirSizeLimitChecker detects emptyDir volumes without a sizeLimit.
// Without a limit, a container can fill the node disk via unlimited emptyDir.
type EmptyDirSizeLimitChecker struct{}

// Name returns the kebab-case check ID.
func (c *EmptyDirSizeLimitChecker) Name() string { return "emptydir-size-limit" }

// Description returns a human-readable description.
func (c *EmptyDirSizeLimitChecker) Description() string {
	return "Detects emptyDir volumes without a sizeLimit, allowing containers to fill node disk."
}

// Categories returns the check categories.
func (c *EmptyDirSizeLimitChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryStorage}
}

// SupportedModes returns which scan modes this check supports.
func (c *EmptyDirSizeLimitChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *EmptyDirSizeLimitChecker) RequiredResources() []schema.GroupVersionResource {
	return workload.GVRs()
}

// Run executes the emptydir-size-limit check.
func (c *EmptyDirSizeLimitChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("emptydir-size-limit check: %w", err)
	}

	specs := workload.ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		for j := range info.Spec.Volumes {
			if info.Spec.Volumes[j].EmptyDir == nil {
				continue
			}
			if info.Spec.Volumes[j].EmptyDir.SizeLimit == nil || info.Spec.Volumes[j].EmptyDir.SizeLimit.IsZero() {
				findings = append(findings, checker.Finding{
					Checker:   "emptydir-size-limit",
					Severity:  checker.SeverityLow,
					Resource:  info.ResourceName,
					Namespace: info.Namespace,
					Kind:      info.Kind,
					Message:   fmt.Sprintf("%s %q has emptyDir volume %q without sizeLimit; a container can fill the node disk.", info.Kind, info.ResourceName, info.Spec.Volumes[j].Name),
					Remediation: fmt.Sprintf("## Why This Matters\n\n"+
						"An emptyDir volume without a sizeLimit allows a container to write unlimited data to the node's filesystem. "+
						"A compromised or misbehaving container can fill the entire node disk, causing kubelet failures, pod evictions, "+
						"and node instability that affects all workloads on that node.\n\n"+
						"## How to Fix\n\n"+
						"Set a sizeLimit on the emptyDir volume based on expected usage:\n\n"+
						"```yaml\nspec:\n  volumes:\n    - name: %s\n      emptyDir:\n        sizeLimit: 1Gi           # Set to expected max usage\n        medium: \"\"               # Or Memory for tmpfs\n```\n\n"+
						"When the limit is exceeded, the pod will be evicted. Size conservatively and monitor actual usage to tune the limit.\n\n"+
						"## Learn More\n\n"+
						"See the Kubernetes Volumes documentation on emptyDir. Setting sizeLimit is a defense-in-depth measure "+
						"that protects node stability alongside resource quotas and LimitRanges.", info.Spec.Volumes[j].Name),
					FieldPath: fmt.Sprintf(".spec.volumes[%d].emptyDir.sizeLimit", j),
				})
			}
		}
	}

	return findings, nil
}
