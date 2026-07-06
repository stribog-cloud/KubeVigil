package scheduling

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// excessivePriorityThreshold is the value at or above which a custom
// PriorityClass is considered to be encroaching on the system-reserved
// range (system-cluster-critical is 2000000000).
const excessivePriorityThreshold int64 = 1_000_000_000

// PriorityClassExcessiveValueChecker detects custom PriorityClass resources
// with a value approaching the system-reserved range, created by non-system
// workloads — a priority-abuse / scheduling-DoS pattern that can effectively
// guarantee preemption over the entire cluster.
type PriorityClassExcessiveValueChecker struct{}

// Name returns the kebab-case check ID.
func (c *PriorityClassExcessiveValueChecker) Name() string { return "priority-class-excessive-value" }

// Description returns a human-readable description.
func (c *PriorityClassExcessiveValueChecker) Description() string {
	return "Detects custom PriorityClass resources with a value approaching the system-reserved range."
}

// Categories returns the check categories.
func (c *PriorityClassExcessiveValueChecker) Categories() []checker.Category {
	return []checker.Category{checker.CategoryScheduling}
}

// SupportedModes returns which scan modes this check supports.
func (c *PriorityClassExcessiveValueChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}

// RequiredResources returns the Kubernetes resource types this check needs.
func (c *PriorityClassExcessiveValueChecker) RequiredResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{PriorityClassGVR}
}

// Run executes the priority-class-excessive-value check.
func (c *PriorityClassExcessiveValueChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("priority-class-excessive-value check: %w", err)
	}

	pcs := resources.List(PriorityClassGVR)
	var findings []checker.Finding

	for i := range pcs {
		pc := &pcs[i]
		name := pc.GetName()

		if systemPriorityClasses[name] {
			continue
		}

		value, ok := priorityClassValue(pc)
		if !ok || value < excessivePriorityThreshold {
			continue
		}

		findings = append(findings, checker.Finding{
			Checker:  "priority-class-excessive-value",
			Severity: checker.SeverityMedium,
			Resource: name,
			Kind:     "PriorityClass",
			Message:  fmt.Sprintf("PriorityClass %q has value %d, approaching the system-reserved range; ordinary workloads using it can preempt nearly everything in the cluster.", name, value),
			Remediation: "## Why This Matters\n\n" +
				"PriorityClass values at or near the system-reserved range (system-cluster-critical is 2000000000) let an " +
				"ordinary team's PriorityClass effectively guarantee preemption over the entire cluster. Unlike " +
				"priority-class-system (which flags workloads using the two built-in system classes), this flags newly " +
				"created custom PriorityClass objects whose value itself is excessive — a scheduling-DoS / priority-abuse " +
				"pattern where one team can starve every other workload.\n\n" +
				"## How to Fix\n\n" +
				"Lower the PriorityClass value well below the system-reserved range:\n\n" +
				"```yaml\napiVersion: scheduling.k8s.io/v1\nkind: PriorityClass\nmetadata:\n  name: my-team-critical\nvalue: 100000              # Well below the 1,000,000,000 system-reserved threshold\npreemptionPolicy: PreemptLowerPriority\nglobalDefault: false\n```\n\n" +
				"Establish a tiered priority scheme for application workloads (e.g., critical: 500000, medium: 100000, low: " +
				"10000) that stays well clear of system-reserved values.\n\n" +
				"## Learn More\n\n" +
				"See the Kubernetes Pod Priority and Preemption documentation. MITRE ATT&CK T1489 (Service Stop) covers the " +
				"resource-starvation framing this check defends against.",
			FieldPath:    ".value",
			CurrentValue: value,
		})
	}

	return findings, nil
}

// priorityClassValue extracts the top-level value field from a PriorityClass.
// It tries int64 (live cluster data), then float64 (JSON-decoded manifests),
// then a quoted string (`value: "2000000000"` — an ordinary authoring mistake
// that a silent int-only extraction would default to 0, defeating detection at
// exactly the system-critical threshold). ok is false only when no numeric
// value could be resolved.
func priorityClassValue(obj *unstructured.Unstructured) (int64, bool) {
	if v, ok, err := unstructured.NestedInt64(obj.Object, "value"); err == nil && ok {
		return v, true
	}
	if v, ok, err := unstructured.NestedFloat64(obj.Object, "value"); err == nil && ok {
		return int64(v), true
	}
	if s, ok, err := unstructured.NestedString(obj.Object, "value"); err == nil && ok {
		if v, perr := strconv.ParseInt(strings.TrimSpace(s), 10, 64); perr == nil {
			return v, true
		}
	}
	return 0, false
}
