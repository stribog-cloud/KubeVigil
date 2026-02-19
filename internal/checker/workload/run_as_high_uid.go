package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// minSafeUID is the minimum UID considered safe. UIDs below this threshold
// (but above 0) overlap with system accounts on many Linux distributions.
const minSafeUID int64 = 10000

// RunAsHighUIDChecker detects containers where runAsUser is explicitly set to
// a UID below 10000. Low UIDs overlap with system users and may grant
// unintended privileges if the container escapes to the host.
type RunAsHighUIDChecker struct{}

// Name returns the kebab-case check ID.
func (c *RunAsHighUIDChecker) Name() string { return "run-as-high-uid" }

// Description returns a human-readable description.
func (c *RunAsHighUIDChecker) Description() string {
	return "Detects containers with runAsUser set to a UID below 10000."
}

// Categories returns the check categories.
func (c *RunAsHighUIDChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *RunAsHighUIDChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *RunAsHighUIDChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the run-as-high-uid check against all workload resources in the cache.
//
// Only flags containers where runAsUser IS explicitly set to a value between 1 and 9999
// (inclusive). UID 0 is handled by the run-as-root checker. If runAsUser is not set at
// all, this checker does not flag it.
func (c *RunAsHighUIDChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("run-as-high-uid check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]
		podSC := info.Spec.SecurityContext

		IterateContainers(info, func(container corev1.Container, ct ContainerType, idx int) {
			effectiveUID := resolveRunAsUser(podSC, container.SecurityContext)

			// Only flag if runAsUser is explicitly set to a value in (0, minSafeUID).
			// UID 0 is the run-as-root checker's responsibility.
			// No runAsUser set at all is also not our concern.
			if effectiveUID == nil || *effectiveUID <= 0 || *effectiveUID >= minSafeUID {
				return
			}

			findings = append(findings, checker.Finding{
				Checker:     "run-as-high-uid",
				Severity:    checker.SeverityLow,
				Resource:    info.ResourceName,
				Namespace:   info.Namespace,
				Kind:        info.Kind,
				Container:   container.Name,
				Message:     fmt.Sprintf("Container %q runs as UID %d, which is below the recommended minimum of %d.", container.Name, *effectiveUID, minSafeUID),
				Remediation: fmt.Sprintf("Set securityContext.runAsUser to a UID >= %d to avoid overlap with system accounts.", minSafeUID),
				FieldPath:   containerFieldPath(ct, idx, "securityContext.runAsUser"),
			})
		})
	}

	return findings, nil
}
