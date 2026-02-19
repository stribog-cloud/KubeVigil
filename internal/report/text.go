package report

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/fatih/color"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/version"
)

// TextReporter writes human-readable colored text output.
// When SummaryOnly is true, individual findings are omitted and only the
// summary table (severity counts by namespace) is shown.
type TextReporter struct {
	SummaryOnly bool
}

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

	// Executive Summary
	summary := ComputeSummary(result)
	fmt.Fprintln(w, "──────────────────────────────────────────────────")
	fmt.Fprintln(w, "Executive Summary")
	fmt.Fprintln(w, "──────────────────────────────────────────────────")
	fmt.Fprintf(w, "Posture Score:   %d/100\n", summary.PostureScore)
	fmt.Fprintf(w, "Total Findings:  %d\n", len(result.Findings))
	fmt.Fprintf(w, "  Critical: %d  High: %d  Medium: %d  Low: %d  Info: %d\n",
		summary.SeverityCounts[checker.SeverityCritical],
		summary.SeverityCounts[checker.SeverityHigh],
		summary.SeverityCounts[checker.SeverityMedium],
		summary.SeverityCounts[checker.SeverityLow],
		summary.SeverityCounts[checker.SeverityInfo])
	fmt.Fprintf(w, "Resources:       %d affected across %d namespaces\n", summary.UniqueResources, summary.UniqueNamespaces)
	fmt.Fprintf(w, "Check Coverage:  %d ran, %d with findings, %d clean, %d skipped, %d errored\n",
		summary.CheckCoverage.TotalRun, summary.CheckCoverage.WithFindings,
		summary.CheckCoverage.Clean, summary.CheckCoverage.Skipped, summary.CheckCoverage.Errored)

	if len(summary.CheckAggregates) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Findings by Check:")
		for i := range summary.CheckAggregates {
			agg := &summary.CheckAggregates[i]
			fmt.Fprintf(w, "  [%s] %-30s  %d findings across %d resources\n",
				agg.Severity, agg.Checker, agg.Count, agg.Resources)
		}
	}
	fmt.Fprintln(w)

	// Scan metadata
	fmt.Fprintf(w, "KubeVigil:       %s\n", version.Version)
	fmt.Fprintf(w, "Scan Mode:       %s\n", result.ScanMeta.ScanMode)
	fmt.Fprintf(w, "Duration:        %s\n", formatDuration(result.ScanMeta.Duration))

	// Cluster info (live mode only)
	if result.ScanMeta.ScanMode == checker.ScanModeLive {
		fmt.Fprintf(w, "Server Version:  %s\n", result.ClusterInfo.ServerVersion)
		fmt.Fprintf(w, "Context:         %s\n", result.ClusterInfo.ContextName)
		fmt.Fprintf(w, "Node Count:      %d\n", result.ClusterInfo.NodeCount)
		if result.ClusterInfo.NamespaceCount > 0 {
			fmt.Fprintf(w, "Namespaces:      %d\n", result.ClusterInfo.NamespaceCount)
		}
	}

	// Findings
	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "──────────────────────────────────────────────────")
	fmt.Fprintf(w, "Findings (%d total)\n", len(sorted))
	fmt.Fprintln(w, "──────────────────────────────────────────────────")

	if !r.SummaryOnly {
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
			if fw := formatFrameworks(sorted[i].Frameworks); fw != "" {
				fmt.Fprintf(w, "  Frameworks:  %s\n", fw)
			}
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

	// Per-namespace breakdown in summary mode.
	if r.SummaryOnly {
		groups := groupByNamespace(sorted)
		namespaces := sortedNamespaces(groups)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "By Namespace:")
		for _, ns := range namespaces {
			label := ns
			if ns == "" {
				label = "(cluster-scoped)"
			}
			nsCounts := countBySeverity(groups[ns])
			fmt.Fprintf(w, "  %-30s  C:%-4d H:%-4d M:%-4d L:%-4d I:%-4d\n",
				label, nsCounts[checker.SeverityCritical], nsCounts[checker.SeverityHigh],
				nsCounts[checker.SeverityMedium], nsCounts[checker.SeverityLow], nsCounts[checker.SeverityInfo])
		}
	}

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
