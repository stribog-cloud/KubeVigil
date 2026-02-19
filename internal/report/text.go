package report

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/fatih/color"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// TextReporter writes human-readable colored text output.
type TextReporter struct{}

// Name returns "text".
func (r *TextReporter) Name() string { return "text" }

// Generate writes a formatted text report to w.
func (r *TextReporter) Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Header
	fmt.Fprintln(w, "══════════════════════════════════════════════════")
	fmt.Fprintln(w, "KubeVigil Scan Report")
	fmt.Fprintln(w, "══════════════════════════════════════════════════")
	fmt.Fprintln(w)

	// Scan metadata
	fmt.Fprintf(w, "Scan Mode:       %s\n", result.ScanMeta.ScanMode)
	fmt.Fprintf(w, "Duration:        %s\n", result.ScanMeta.Duration)
	fmt.Fprintf(w, "Checks Run:      %d\n", result.ScanMeta.ChecksRun)
	fmt.Fprintf(w, "Checks Skipped:  %d\n", result.ScanMeta.ChecksSkipped)
	fmt.Fprintf(w, "Checks Errored:  %d\n", result.ScanMeta.ChecksErrored)

	// Cluster info (live mode only)
	if result.ScanMeta.ScanMode == checker.ScanModeLive {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Server Version:  %s\n", result.ClusterInfo.ServerVersion)
		fmt.Fprintf(w, "Context:         %s\n", result.ClusterInfo.ContextName)
		fmt.Fprintf(w, "Node Count:      %d\n", result.ClusterInfo.NodeCount)
	}

	// Findings
	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "──────────────────────────────────────────────────")
	fmt.Fprintf(w, "Findings (%d total)\n", len(sorted))
	fmt.Fprintln(w, "──────────────────────────────────────────────────")

	for i := range sorted {
		fmt.Fprintln(w)
		badge := severityBadge(sorted[i].Severity)
		fmt.Fprintf(w, "[%s] %s\n", badge, sorted[i].Checker)

		var resource string
		if sorted[i].Namespace != "" {
			resource = sorted[i].Namespace + "/" + sorted[i].Kind + "/" + sorted[i].Resource
		} else {
			resource = sorted[i].Kind + "/" + sorted[i].Resource
		}
		fmt.Fprintf(w, "  Resource:    %s\n", resource)

		if sorted[i].Container != "" {
			fmt.Fprintf(w, "  Container:   %s\n", sorted[i].Container)
		}
		fmt.Fprintf(w, "  Message:     %s\n", sorted[i].Message)
		fmt.Fprintf(w, "  Remediation: %s\n", sorted[i].Remediation)
		if sorted[i].FieldPath != "" {
			fmt.Fprintf(w, "  Field:       %s\n", sorted[i].FieldPath)
		}
	}

	// Summary
	counts := countBySeverity(sorted)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "──────────────────────────────────────────────────")
	fmt.Fprintln(w, "Summary")
	fmt.Fprintln(w, "──────────────────────────────────────────────────")
	fmt.Fprintf(w, "Total: %d findings\n", len(sorted))
	fmt.Fprintf(w, "  Critical: %d\n", counts[checker.SeverityCritical])
	fmt.Fprintf(w, "  High:     %d\n", counts[checker.SeverityHigh])
	fmt.Fprintf(w, "  Medium:   %d\n", counts[checker.SeverityMedium])
	fmt.Fprintf(w, "  Low:      %d\n", counts[checker.SeverityLow])
	fmt.Fprintf(w, "  Info:     %d\n", counts[checker.SeverityInfo])

	return nil
}

// severityBadge returns a colorized severity label.
func severityBadge(s checker.Severity) string {
	label := s.String()
	switch s {
	case checker.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint(label)
	case checker.SeverityHigh:
		return color.New(color.FgRed).Sprint(label)
	case checker.SeverityMedium:
		return color.New(color.FgYellow).Sprint(label)
	case checker.SeverityLow:
		return color.New(color.FgCyan).Sprint(label)
	default:
		return label
	}
}

// countBySeverity returns a count of findings per severity level.
func countBySeverity(findings []checker.Finding) map[checker.Severity]int {
	counts := make(map[checker.Severity]int)
	for i := range findings {
		counts[findings[i].Severity]++
	}
	return counts
}
