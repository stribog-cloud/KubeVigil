// Package report provides formatters for scan results.
package report

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/stribog-cloud/kubevigil/internal/checker"
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

func init() {
	register(&TextReporter{})
	register(&JSONReporter{})
}
