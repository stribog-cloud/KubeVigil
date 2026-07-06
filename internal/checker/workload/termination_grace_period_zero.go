package workload

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// TerminationGracePeriodZeroChecker detects pods with
// terminationGracePeriodSeconds: 0, which forces an immediate SIGKILL and
// skips preStop hooks entirely.
type TerminationGracePeriodZeroChecker struct{}

// Name returns the kebab-case check ID.
func (c *TerminationGracePeriodZeroChecker) Name() string { return "termination-grace-period-zero" }

// Description returns a human-readable description.
func (c *TerminationGracePeriodZeroChecker) Description() string {
	return "Detects pods with terminationGracePeriodSeconds: 0, which forces an immediate SIGKILL and skips preStop hooks."
}

// Categories returns the check categories.
func (c *TerminationGracePeriodZeroChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryWorkload}
}

// SupportedModes returns which scan modes this check supports.
func (c *TerminationGracePeriodZeroChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *TerminationGracePeriodZeroChecker) RequiredResources() []schema.GroupVersionResource {
	return GVRs()
}

// Run executes the termination-grace-period-zero check against all workload resources in the cache.
func (c *TerminationGracePeriodZeroChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("termination-grace-period-zero check: %w", err)
	}

	specs := ExtractPodSpecs(resources)
	var findings []checker.Finding

	for i := range specs {
		info := &specs[i]

		if info.Spec.TerminationGracePeriodSeconds == nil || *info.Spec.TerminationGracePeriodSeconds != 0 {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:   "termination-grace-period-zero",
			Severity:  checker.SeverityLow,
			Resource:  info.ResourceName,
			Namespace: info.Namespace,
			Kind:      info.Kind,
			Message:   fmt.Sprintf("%s %q sets terminationGracePeriodSeconds to 0, forcing an immediate SIGKILL.", info.Kind, info.ResourceName),
			Remediation: "## Why This Matters\n\n" +
				"A terminationGracePeriodSeconds of 0 forces the kubelet to send SIGKILL immediately, skipping preStop hooks " +
				"entirely and giving the application no chance to flush logs, close connections gracefully, or complete " +
				"in-flight requests. Beyond the reliability impact, this is also a documented pattern for suppressing " +
				"shutdown-time audit or logging hooks before they can run — a subtle anti-forensics technique.\n\n" +
				"## How to Fix\n\n" +
				"Remove the terminationGracePeriodSeconds override (falls back to the 30-second default) or set an explicit " +
				"positive value that gives your application enough time to shut down cleanly:\n\n" +
				"```yaml\nspec:\n  terminationGracePeriodSeconds: 30\n```\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes documentation on pod termination for how terminationGracePeriodSeconds interacts with " +
				"preStop hooks and SIGTERM/SIGKILL signal delivery.",
			FieldPath:    ".spec.terminationGracePeriodSeconds",
			CurrentValue: int64(0),
			DesiredValue: nil,
			FixHint: &checker.FixHint{
				Safety:      checker.FixLikelySafe,
				Description: "Removes terminationGracePeriodSeconds: 0, restoring the default 30-second grace period.",
				Impact:      "Pods take up to 30 seconds longer to terminate; preStop hooks run to completion instead of being skipped.",
				Operation:   checker.FixOpRemove,
			},
		})
	}

	return findings, nil
}
