package report

import "github.com/stribog-cloud/kubevigil/internal/checker"

// AggregatedFinding groups findings that share the same checker + severity
// within a namespace. This reduces report bloat when many resources have
// the same issue (even with resource-specific messages).
type AggregatedFinding struct {
	Checker     string
	Severity    checker.Severity
	Message     string
	Remediation string
	Frameworks  []checker.FrameworkRef
	Resources   []AggregatedResource
}

// AggregatedResource identifies a single resource within an aggregated group.
type AggregatedResource struct {
	Name      string // formatted "ns/Kind/name"
	Container string
	FieldPath string
	Message   string // resource-specific message for drilldown
}

// aggregateFindings groups findings by (Checker, Severity) key, preserving
// severity order. Findings with count == 1 are returned as-is in a single-resource group.
func aggregateFindings(findings []checker.Finding) []AggregatedFinding {
	type groupKey struct {
		checker  string
		severity checker.Severity
	}

	groups := make(map[groupKey]*AggregatedFinding)
	var order []groupKey

	for i := range findings {
		f := &findings[i]
		key := groupKey{checker: f.Checker, severity: f.Severity}

		agg, ok := groups[key]
		if !ok {
			agg = &AggregatedFinding{
				Checker:     f.Checker,
				Severity:    f.Severity,
				Message:     f.Message,
				Remediation: f.Remediation,
				Frameworks:  f.Frameworks,
			}
			groups[key] = agg
			order = append(order, key)
		}

		agg.Resources = append(agg.Resources, AggregatedResource{
			Name:      formatResource(f),
			Container: f.Container,
			FieldPath: f.FieldPath,
			Message:   f.Message,
		})
	}

	result := make([]AggregatedFinding, len(order))
	for i, key := range order {
		result[i] = *groups[key]
	}
	return result
}
