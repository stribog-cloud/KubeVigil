package policy

import "github.com/stribog-cloud/kubevigil/internal/checker"

// ParseSeverity converts a policy severity string to a checker.Severity.
// An empty string defaults to Medium (a sensible middle ground for custom
// policies); any other unrecognized value is an error.
func ParseSeverity(s string) (checker.Severity, error) {
	if s == "" {
		return checker.SeverityMedium, nil
	}
	return checker.ParseSeverity(s)
}
