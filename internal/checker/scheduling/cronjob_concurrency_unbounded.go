package scheduling

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// CronJobConcurrencyUnboundedChecker detects CronJob resources with
// concurrencyPolicy: Allow (the default) and no startingDeadlineSeconds,
// allowing an unbounded pile-up of concurrent Job runs if the workload runs
// longer than its schedule interval.
type CronJobConcurrencyUnboundedChecker struct{}

// Name returns the kebab-case check ID.
func (c *CronJobConcurrencyUnboundedChecker) Name() string { return "cronjob-concurrency-unbounded" }

// Description returns a human-readable description.
func (c *CronJobConcurrencyUnboundedChecker) Description() string {
	return "Detects CronJobs allowing unbounded concurrent runs with no startingDeadlineSeconds bound."
}

// Categories returns the check categories.
func (c *CronJobConcurrencyUnboundedChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *CronJobConcurrencyUnboundedChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *CronJobConcurrencyUnboundedChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{CronJobGVR}
}

// Run executes the cronjob-concurrency-unbounded check.
func (c *CronJobConcurrencyUnboundedChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cronjob-concurrency-unbounded check: %w", err)
	}

	cronjobs := resources.List(CronJobGVR)
	var findings []checker.Finding

	for i := range cronjobs {
		cj := &cronjobs[i]

		policy, _, _ := unstructured.NestedString(cj.Object, "spec", "concurrencyPolicy")
		if policy != "" && policy != "Allow" {
			// Forbid or Replace already bound the concurrency risk.
			continue
		}

		if _, found, _ := unstructured.NestedFieldNoCopy(cj.Object, "spec", "startingDeadlineSeconds"); found {
			continue
		}

		name := cj.GetName()
		ns := cj.GetNamespace()

		findings = append(findings, checker.Finding{
			Checker:   "cronjob-concurrency-unbounded",
			Severity:  checker.SeverityLow,
			Resource:  name,
			Namespace: ns,
			Kind:      "CronJob",
			Message:   fmt.Sprintf("CronJob %q allows concurrent runs (concurrencyPolicy: Allow or unset) with no startingDeadlineSeconds bound; overlapping runs can pile up unbounded.", name),
			Remediation: "## Why This Matters\n\n" +
				"With concurrencyPolicy left at its default (Allow) and no startingDeadlineSeconds, a CronJob whose runs " +
				"take longer than its schedule interval will keep launching new, overlapping Job runs indefinitely. Each " +
				"run consumes scheduler and node capacity, and enough pile-up can starve the cluster's own resources — an " +
				"operational denial-of-service against the scheduler.\n\n" +
				"## How to Fix\n\n" +
				"Either forbid concurrent runs, or bound how late a missed run may start:\n\n" +
				"```yaml\napiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: nightly-report\nspec:\n  schedule: \"0 2 * * *\"\n  concurrencyPolicy: Forbid       # Or: Allow + startingDeadlineSeconds\n  startingDeadlineSeconds: 300    # Skip a run if it can't start within 5 minutes\n```\n\n" +
				"Use `Forbid` when overlapping runs would be incorrect (most batch jobs); use `Allow` with a " +
				"startingDeadlineSeconds bound only when overlap is intentional and safe.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes CronJob documentation on concurrencyPolicy and startingDeadlineSeconds.",
			FieldPath: ".spec.concurrencyPolicy",
			FixHint: &checker.FixHint{
				Safety:      checker.FixLikelySafe,
				Description: "Sets concurrencyPolicy to Forbid to prevent overlapping Job runs.",
				Impact:      "CronJobs that intentionally allow overlapping runs will instead skip a new run while a previous run is still active.",
				Operation:   checker.FixOpSet,
			},
		})
	}

	return findings, nil
}
