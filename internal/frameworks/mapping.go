// Package frameworks provides compliance framework mappings for security checks.
// Each check maps to one or more industry frameworks (CIS, MITRE ATT&CK, NSA/CISA).
package frameworks

import (
	"sort"
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// mapper is a function that returns framework references for a given check.
type mapper func() map[string][]checker.FrameworkRef

var mappers []mapper

func registerMapper(m mapper) {
	mappers = append(mappers, m)
}

// LookupAll returns all framework references for a check across all frameworks.
func LookupAll(checkName string) []checker.FrameworkRef {
	var result []checker.FrameworkRef
	for _, m := range mappers {
		if refs, ok := m()[checkName]; ok {
			result = append(result, refs...)
		}
	}
	return result
}

// LookupByFramework returns framework references for a check filtered to a single framework.
func LookupByFramework(checkName, framework string) []checker.FrameworkRef {
	all := LookupAll(checkName)
	var result []checker.FrameworkRef
	for _, ref := range all {
		if ref.Framework == framework {
			result = append(result, ref)
		}
	}
	return result
}

// FrameworkNames returns the names of all registered frameworks sorted alphabetically.
func FrameworkNames() []string {
	seen := make(map[string]bool)
	for _, m := range mappers {
		for _, refs := range m() {
			for _, ref := range refs {
				seen[ref.Framework] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AttachFrameworks populates the Frameworks field on each finding based on check name.
func AttachFrameworks(findings []checker.Finding) {
	for i := range findings {
		findings[i].Frameworks = LookupAll(findings[i].Checker)
	}
}

// NormalizeFramework extracts the framework name from a possibly version-qualified
// string (e.g., "cis-1.8" → "cis", "mitre" → "mitre").
func NormalizeFramework(framework string) string {
	// Known framework names — strip version suffix if present.
	for _, name := range []string{"cis", "mitre", "nsa"} {
		if framework == name || strings.HasPrefix(framework, name+"-") {
			return name
		}
	}
	return framework
}

// ControlCounts returns the total number of unique control IDs per framework
// across all registered mappers.
func ControlCounts() map[string]int {
	seen := make(map[string]map[string]bool) // framework → set of controlIDs
	for _, m := range mappers {
		for _, refs := range m() {
			for _, ref := range refs {
				if seen[ref.Framework] == nil {
					seen[ref.Framework] = make(map[string]bool)
				}
				seen[ref.Framework][ref.ControlID] = true
			}
		}
	}
	counts := make(map[string]int, len(seen))
	for fw, ids := range seen {
		counts[fw] = len(ids)
	}
	return counts
}

// AllControlIDs returns all unique control IDs per framework, sorted alphabetically.
func AllControlIDs() map[string][]string {
	seen := make(map[string]map[string]bool)
	for _, m := range mappers {
		for _, refs := range m() {
			for _, ref := range refs {
				if seen[ref.Framework] == nil {
					seen[ref.Framework] = make(map[string]bool)
				}
				seen[ref.Framework][ref.ControlID] = true
			}
		}
	}
	result := make(map[string][]string, len(seen))
	for fw, ids := range seen {
		controls := make([]string, 0, len(ids))
		for id := range ids {
			controls = append(controls, id)
		}
		sort.Strings(controls)
		result[fw] = controls
	}
	return result
}

// FilterByFramework returns only findings that map to the given framework.
// Findings must have Frameworks populated (call AttachFrameworks first).
// The framework parameter can be version-qualified (e.g., "cis-1.8") or plain (e.g., "cis").
func FilterByFramework(findings []checker.Finding, framework string) []checker.Finding {
	normalized := NormalizeFramework(framework)
	var result []checker.Finding
	for i := range findings {
		for _, ref := range findings[i].Frameworks {
			if ref.Framework == normalized {
				result = append(result, findings[i])
				break
			}
		}
	}
	return result
}
