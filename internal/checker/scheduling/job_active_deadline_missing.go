package scheduling

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// JobActiveDeadlineMissingChecker detects Job resources without
// spec.activeDeadlineSeconds set, meaning a runaway or hung Job can consume
// cluster resources indefinitely with no automatic cutoff.
type JobActiveDeadlineMissingChecker struct{}

// Name returns the kebab-case check ID.
func (c *JobActiveDeadlineMissingChecker) Name() string { return "job-active-deadline-missing" }

// Description returns a human-readable description.
func (c *JobActiveDeadlineMissingChecker) Description() string {
	return "Detects Jobs without activeDeadlineSeconds, allowing a runaway Job to run indefinitely."
}

// Categories returns the check categories.
func (c *JobActiveDeadlineMissingChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *JobActiveDeadlineMissingChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *JobActiveDeadlineMissingChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{JobGVR}
}

// Run executes the job-active-deadline-missing check.
func (c *JobActiveDeadlineMissingChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("job-active-deadline-missing check: %w", err)
	}

	jobs := resources.List(JobGVR)
	var findings []checker.Finding

	for i := range jobs {
		job := &jobs[i]

		if _, found, _ := unstructured.NestedFieldNoCopy(job.Object, "spec", "activeDeadlineSeconds"); found {
			continue
		}

		name := job.GetName()
		ns := job.GetNamespace()

		findings = append(findings, checker.Finding{
			Checker:   "job-active-deadline-missing",
			Severity:  checker.SeverityLow,
			Resource:  name,
			Namespace: ns,
			Kind:      "Job",
			Message:   fmt.Sprintf("Job %q has no activeDeadlineSeconds set; a runaway or hung Job can consume cluster resources indefinitely.", name),
			Remediation: "## Why This Matters\n\n" +
				"Without activeDeadlineSeconds, a Job that hangs (e.g., waiting on an unreachable dependency) or misbehaves " +
				"(e.g., an infinite retry loop) has no automatic cutoff. It can occupy node resources and scheduler capacity " +
				"indefinitely, degrading the cluster for other workloads.\n\n" +
				"## How to Fix\n\n" +
				"Set an activeDeadlineSeconds appropriate for the Job's expected runtime:\n\n" +
				"```yaml\napiVersion: batch/v1\nkind: Job\nmetadata:\n  name: batch-processor\nspec:\n  activeDeadlineSeconds: 3600   # Kill the Job if it runs longer than 1 hour\n  template:\n    spec:\n      containers:\n        - name: processor\n          image: batch-processor:v1\n```\n\n" +
				"Choose a deadline generously above the expected p99 runtime to avoid killing legitimate long-running work.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes Jobs documentation on activeDeadlineSeconds. This is a resource-hygiene control, similar " +
				"in spirit to pod-disruption-budget and priority-class-missing.",
			FieldPath: ".spec.activeDeadlineSeconds",
		})
	}

	return findings, nil
}
