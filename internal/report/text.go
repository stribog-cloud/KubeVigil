package report

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
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

	cfg := config.Default()

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

	// Top Risks (omitted in summary-only mode)
	if !r.SummaryOnly && len(summary.TopRisks) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "──────────────────────────────────────────────────")
		fmt.Fprintln(w, "Top Risks")
		fmt.Fprintln(w, "──────────────────────────────────────────────────")
		for i := range summary.TopRisks {
			tr := &summary.TopRisks[i]
			badge := severityBadge(tr.Severity)
			var resource string
			if tr.Namespace != "" {
				resource = tr.Namespace + "/" + tr.Kind + "/" + tr.Resource
			} else {
				resource = tr.Kind + "/" + tr.Resource
			}
			badgeStr := fmt.Sprintf("[%s]", badge)
			fmt.Fprintf(w, "  %-10s %s — %s\n", badgeStr, tr.Checker, resource)
			fmt.Fprintf(w, "             %s\n", tr.Message)
		}
	}

	// Findings
	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "──────────────────────────────────────────────────")
	fmt.Fprintf(w, "Findings (%d total)\n", len(sorted))
	fmt.Fprintln(w, "──────────────────────────────────────────────────")

	// Per-namespace breakdown in summary mode (moved up from old Summary section).
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

	if !r.SummaryOnly {
		writeTextTierFindings(w, sorted, cfg)
	}

	// Compliance Summary
	complianceSummary := buildTextComplianceSummary(sorted)
	if len(complianceSummary) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "──────────────────────────────────────────────────")
		fmt.Fprintln(w, "Compliance")
		fmt.Fprintln(w, "──────────────────────────────────────────────────")
		for _, cs := range complianceSummary {
			fmt.Fprintf(w, "  %-18s %s\n", cs.displayName+":", cs.detail)
		}
	}

	// Passed Checks
	if len(summary.PassedChecks) > 0 {
		fmt.Fprintln(w)
		names := summary.PassedChecks
		if len(names) > 10 {
			remaining := len(names) - 10
			fmt.Fprintf(w, "Checks Passed (%d): %s, ... and %d more\n",
				len(names), strings.Join(names[:10], ", "), remaining)
		} else {
			fmt.Fprintf(w, "Checks Passed (%d): %s\n",
				len(names), strings.Join(names, ", "))
		}
	}

	return nil
}

// writeTextTierFindings writes findings grouped by namespace tier (Application,
// Infrastructure, Cluster-Scoped) using config.ClassifyNamespace.
func writeTextTierFindings(w io.Writer, sorted []checker.Finding, cfg *config.Config) {
	var appFindings, infraFindings, clusterFindings []checker.Finding
	for i := range sorted {
		nsType := config.ClassifyNamespace(cfg, sorted[i].Namespace)
		switch nsType {
		case config.NamespaceInfrastructure:
			infraFindings = append(infraFindings, sorted[i])
		case config.NamespaceClusterScoped:
			clusterFindings = append(clusterFindings, sorted[i])
		default:
			appFindings = append(appFindings, sorted[i])
		}
	}

	if len(appFindings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "── Application Namespaces ──────────────────────")
		writeTextFindings(w, appFindings)
	}

	if len(infraFindings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "── Infrastructure Namespaces ───────────────────")
		writeTextFindings(w, infraFindings)
	}

	if len(clusterFindings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "── Cluster-Scoped ──────────────────────────────")
		writeTextFindings(w, clusterFindings)
	}
}

// writeTextFindings writes individual finding details.
func writeTextFindings(w io.Writer, findings []checker.Finding) {
	for i := range findings {
		fmt.Fprintln(w)
		badge := severityBadge(findings[i].Severity)
		fmt.Fprintf(w, "[%s] %s\n", badge, findings[i].Checker)

		var resource string
		if findings[i].Namespace != "" {
			resource = findings[i].Namespace + "/" + findings[i].Kind + "/" + findings[i].Resource
		} else {
			resource = findings[i].Kind + "/" + findings[i].Resource
		}
		fmt.Fprintf(w, "  Resource:    %s\n", resource)

		if findings[i].Container != "" {
			fmt.Fprintf(w, "  Container:   %s\n", findings[i].Container)
		}
		fmt.Fprintf(w, "  Message:     %s\n", findings[i].Message)
		fmt.Fprintf(w, "  Remediation: %s\n", findings[i].Remediation)
		if findings[i].FieldPath != "" {
			fmt.Fprintf(w, "  Field:       %s\n", findings[i].FieldPath)
		}
		if fw := formatFrameworks(findings[i].Frameworks); fw != "" {
			fmt.Fprintf(w, "  Frameworks:  %s\n", fw)
		}
	}
}

// textComplianceEntry holds a framework display name and control count detail.
type textComplianceEntry struct {
	displayName string
	detail      string
}

// textFrameworkDisplayName returns a human-readable framework name with version.
// It normalizes the version to always have a "v" prefix for display.
func textFrameworkDisplayName(framework, ver string) string {
	fw := strings.ToUpper(framework)
	displayVer := ver
	if !strings.HasPrefix(ver, "v") {
		displayVer = "v" + ver
	}
	switch fw {
	case "CIS":
		return "CIS " + displayVer
	case "MITRE":
		return "MITRE ATT&CK " + displayVer
	case "NSA":
		return "NSA/CISA " + displayVer
	default:
		if ver != "" {
			return fw + " " + displayVer
		}
		return fw
	}
}

// textFrameworkControlNoun returns the appropriate noun for a framework's controls.
func textFrameworkControlNoun(framework string, count int) string {
	fw := strings.ToUpper(framework)
	switch fw {
	case "MITRE":
		if count == 1 {
			return "technique"
		}
		return "techniques"
	default:
		if count == 1 {
			return "control violated"
		}
		return "controls violated"
	}
}

// buildTextComplianceSummary builds compliance summary entries from findings.
// It groups unique control IDs per framework and returns entries sorted by
// framework name.
func buildTextComplianceSummary(findings []checker.Finding) []textComplianceEntry {
	type fwInfo struct {
		displayName string
		controls    map[string]struct{}
	}

	fwMap := make(map[string]*fwInfo)
	var fwOrder []string

	for i := range findings {
		for _, ref := range findings[i].Frameworks {
			fw := strings.ToUpper(ref.Framework)
			info, ok := fwMap[fw]
			if !ok {
				info = &fwInfo{
					displayName: textFrameworkDisplayName(ref.Framework, ref.Version),
					controls:    make(map[string]struct{}),
				}
				fwMap[fw] = info
				fwOrder = append(fwOrder, fw)
			}
			info.controls[ref.ControlID] = struct{}{}
		}
	}

	if len(fwOrder) == 0 {
		return nil
	}

	sort.Strings(fwOrder)

	entries := make([]textComplianceEntry, 0, len(fwOrder))
	for _, fw := range fwOrder {
		info := fwMap[fw]
		count := len(info.controls)
		noun := textFrameworkControlNoun(fw, count)
		entries = append(entries, textComplianceEntry{
			displayName: info.displayName,
			detail:      fmt.Sprintf("%d %s", count, noun),
		})
	}
	return entries
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
