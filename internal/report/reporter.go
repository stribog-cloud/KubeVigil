// Package report provides formatters for scan results.
package report

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

// Reporter formats scan results for output.
type Reporter interface {
	// Name returns the format name (e.g., "text", "json").
	Name() string
	// Generate writes the formatted scan result to w.
	Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error
}

var reporters = map[string]Reporter{}

func register(r Reporter) {
	reporters[r.Name()] = r
}

// Get returns a reporter by name. Returns an error if not found.
func Get(name string) (Reporter, error) {
	r, ok := reporters[name]
	if !ok {
		return nil, fmt.Errorf("unknown reporter: %q", name)
	}
	return r, nil
}

// Configurable is implemented by reporters that accept runtime configuration.
type Configurable interface {
	SetConfig(cfg *config.Config)
}

// Names returns all registered reporter names sorted alphabetically.
func Names() []string {
	names := make([]string, 0, len(reporters))
	for n := range reporters {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// sortFindings sorts findings by severity descending, then namespace, then
// resource name, then checker name for deterministic output.
func sortFindings(findings []checker.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].Namespace != findings[j].Namespace {
			return findings[i].Namespace < findings[j].Namespace
		}
		if findings[i].Resource != findings[j].Resource {
			return findings[i].Resource < findings[j].Resource
		}
		return findings[i].Checker < findings[j].Checker
	})
}

// formatFrameworks returns a compact string of framework references.
// Example: "CIS 5.2.1 · MITRE T1611 · NSA 3.1"
func formatFrameworks(refs []checker.FrameworkRef) string {
	if len(refs) == 0 {
		return ""
	}
	parts := make([]string, len(refs))
	for i := range refs {
		parts[i] = strings.ToUpper(refs[i].Framework) + " " + refs[i].ControlID
	}
	return strings.Join(parts, " · ")
}

// severityEmoji returns an emoji indicator for the severity level.
func severityEmoji(s checker.Severity) string {
	switch s {
	case checker.SeverityCritical:
		return "\xf0\x9f\x94\xb4" // red circle
	case checker.SeverityHigh:
		return "\xf0\x9f\x9f\xa0" // orange circle
	case checker.SeverityMedium:
		return "\xf0\x9f\x9f\xa1" // yellow circle
	case checker.SeverityLow:
		return "\xf0\x9f\x94\xb5" // blue circle
	default:
		return "\xe2\xac\x9c" // white circle
	}
}

// formatDuration formats a duration with at most 2 decimal places.
// Examples: "5.87s", "42ms", "1m23.45s".
func formatDuration(d time.Duration) string {
	d = d.Round(10 * time.Millisecond)
	return d.String()
}

func init() {
	register(&TextReporter{})
	register(&JSONReporter{})
}
