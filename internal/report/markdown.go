package report

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/version"
)

// MarkdownReporter writes scan results as Markdown grouped by namespace.
type MarkdownReporter struct {
	// Config is optional; when set, enables namespace classification.
	Config *config.Config
}

// Name returns "markdown".
func (r *MarkdownReporter) Name() string { return "markdown" }

// SetConfig sets the config for namespace classification.
func (r *MarkdownReporter) SetConfig(cfg *config.Config) { r.Config = cfg }

// Generate writes a Markdown-formatted report to w.
func (r *MarkdownReporter) Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	fmt.Fprintln(w, "# KubeVigil Scan Report")
	fmt.Fprintln(w)

	// Executive Summary.
	summary := ComputeSummary(result)
	fmt.Fprintln(w, "## Executive Summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Posture Score: %d/100**\n", summary.PostureScore)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| KubeVigil | %s |\n", version.Version)
	fmt.Fprintf(w, "| Scan Mode | %s |\n", result.ScanMeta.ScanMode)
	fmt.Fprintf(w, "| Duration | %s |\n", formatDuration(result.ScanMeta.Duration))
	fmt.Fprintf(w, "| Total Findings | %d |\n", len(result.Findings))
	fmt.Fprintf(w, "| Resources Affected | %d |\n", summary.UniqueResources)
	fmt.Fprintf(w, "| Namespaces | %d |\n", summary.UniqueNamespaces)
	fmt.Fprintf(w, "| Checks Run | %d |\n", summary.CheckCoverage.TotalRun)
	fmt.Fprintf(w, "| Checks with Findings | %d |\n", summary.CheckCoverage.WithFindings)
	fmt.Fprintf(w, "| Checks Clean | %d |\n", summary.CheckCoverage.Clean)
	fmt.Fprintf(w, "| Checks Skipped | %d |\n", summary.CheckCoverage.Skipped)
	fmt.Fprintf(w, "| Checks Errored | %d |\n", summary.CheckCoverage.Errored)
	if summary.CheckCoverage.TotalRun > 0 {
		passRate := 100 * summary.CheckCoverage.Clean / summary.CheckCoverage.TotalRun
		fmt.Fprintf(w, "| Pass Rate | %d%% |\n", passRate)
	}
	fmt.Fprintln(w)

	// Findings by check aggregation (collapsible when > 10 checks).
	if len(summary.CheckAggregates) > 0 {
		if len(summary.CheckAggregates) > 10 {
			fmt.Fprintf(w, "<details>\n<summary><b>Findings by Check (%d)</b></summary>\n\n", len(summary.CheckAggregates))
		} else {
			fmt.Fprintln(w, "### Findings by Check")
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "| Severity | Check | Findings | Resources |\n")
		fmt.Fprintf(w, "|----------|-------|----------|-----------|\n")
		for i := range summary.CheckAggregates {
			agg := &summary.CheckAggregates[i]
			emoji := severityEmoji(agg.Severity)
			fmt.Fprintf(w, "| %s %s | %s | %d | %d |\n",
				emoji, agg.Severity, agg.Checker, agg.Count, agg.Resources)
		}
		if len(summary.CheckAggregates) > 10 {
			fmt.Fprintln(w, "\n</details>")
		}
		fmt.Fprintln(w)
	}

	// Findings.
	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	counts := countBySeverity(sorted)

	fmt.Fprintf(w, "## Findings (%d total)\n", len(sorted))
	fmt.Fprintln(w)

	// Severity summary table.
	fmt.Fprintf(w, "| Severity | Count |\n")
	fmt.Fprintf(w, "|----------|-------|\n")
	fmt.Fprintf(w, "| %s Critical | %d |\n", severityEmoji(checker.SeverityCritical), counts[checker.SeverityCritical])
	fmt.Fprintf(w, "| %s High | %d |\n", severityEmoji(checker.SeverityHigh), counts[checker.SeverityHigh])
	fmt.Fprintf(w, "| %s Medium | %d |\n", severityEmoji(checker.SeverityMedium), counts[checker.SeverityMedium])
	fmt.Fprintf(w, "| %s Low | %d |\n", severityEmoji(checker.SeverityLow), counts[checker.SeverityLow])
	fmt.Fprintf(w, "| %s Info | %d |\n", severityEmoji(checker.SeverityInfo), counts[checker.SeverityInfo])
	fmt.Fprintln(w)

	// Checks Passed section.
	if len(summary.PassedChecks) > 0 {
		fmt.Fprintf(w, "### Checks Passed (%d)\n", len(summary.PassedChecks))
		fmt.Fprintln(w)
		fmt.Fprintln(w, "<details>")
		fmt.Fprintf(w, "<summary>%d checks ran with zero findings</summary>\n\n", len(summary.PassedChecks))
		for _, name := range summary.PassedChecks {
			fmt.Fprintf(w, "- `%s`\n", name)
		}
		fmt.Fprintln(w, "\n</details>")
		fmt.Fprintln(w)
	}

	// Compliance summary (frameworks).
	fwGroups := buildFrameworkGroups(sorted)
	if len(fwGroups) > 0 {
		fmt.Fprintln(w, "## Compliance Summary")
		fmt.Fprintln(w)
		for _, fg := range fwGroups {
			fmt.Fprintf(w, "### %s\n", fg.Framework)
			fmt.Fprintln(w)
			fmt.Fprintln(w, "| Control | Title | Severity | Resources |")
			fmt.Fprintln(w, "|---------|-------|----------|-----------|")
			for _, ctrl := range fg.Controls {
				fmt.Fprintf(w, "| %s | %s | %s | %d |\n",
					ctrl.ControlID, ctrl.Title, ctrl.Severity, ctrl.Count)
			}
			fmt.Fprintln(w)
		}
	}

	if len(sorted) == 0 {
		return nil
	}

	// Group findings by namespace and classify.
	cfg := r.Config
	if cfg == nil {
		cfg = config.Default()
	}

	nsGroups := groupByNamespace(sorted)
	namespaces := sortedNamespaces(nsGroups)
	aggregate := !cfg.Settings.NoAggregate

	var appNS, infraNS, clusterNS []string
	appCounts := make(map[checker.Severity]int)
	infraCounts := make(map[checker.Severity]int)
	clusterCounts := make(map[checker.Severity]int)
	appTotal, infraTotal, clusterTotal := 0, 0, 0

	for _, ns := range namespaces {
		nsCounts := countBySeverity(nsGroups[ns])
		nsTotal := len(nsGroups[ns])
		switch config.ClassifyNamespace(cfg, ns) {
		case config.NamespaceInfrastructure:
			infraNS = append(infraNS, ns)
			infraTotal += nsTotal
			for sev, c := range nsCounts {
				infraCounts[sev] += c
			}
		case config.NamespaceClusterScoped:
			clusterNS = append(clusterNS, ns)
			clusterTotal += nsTotal
			for sev, c := range nsCounts {
				clusterCounts[sev] += c
			}
		default:
			appNS = append(appNS, ns)
			appTotal += nsTotal
			for sev, c := range nsCounts {
				appCounts[sev] += c
			}
		}
	}

	// Category breakdown table.
	if appTotal+infraTotal+clusterTotal > 0 {
		fmt.Fprintln(w, "### Category Breakdown")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Category | Findings | Critical | High | Medium | Low | Info |")
		fmt.Fprintln(w, "|----------|----------|----------|------|--------|-----|------|")
		if appTotal > 0 {
			fmt.Fprintf(w, "| Application | %d | %d | %d | %d | %d | %d |\n",
				appTotal, appCounts[checker.SeverityCritical], appCounts[checker.SeverityHigh],
				appCounts[checker.SeverityMedium], appCounts[checker.SeverityLow], appCounts[checker.SeverityInfo])
		}
		if infraTotal > 0 {
			fmt.Fprintf(w, "| Infrastructure | %d | %d | %d | %d | %d | %d |\n",
				infraTotal, infraCounts[checker.SeverityCritical], infraCounts[checker.SeverityHigh],
				infraCounts[checker.SeverityMedium], infraCounts[checker.SeverityLow], infraCounts[checker.SeverityInfo])
		}
		if clusterTotal > 0 {
			fmt.Fprintf(w, "| Cluster-Scoped | %d | %d | %d | %d | %d | %d |\n",
				clusterTotal, clusterCounts[checker.SeverityCritical], clusterCounts[checker.SeverityHigh],
				clusterCounts[checker.SeverityMedium], clusterCounts[checker.SeverityLow], clusterCounts[checker.SeverityInfo])
		}
		fmt.Fprintln(w)
	}

	// Application namespace sections.
	if len(appNS) > 0 {
		fmt.Fprintln(w, "## Application Namespaces")
		fmt.Fprintln(w)
		writeMarkdownNSSections(w, appNS, nsGroups, aggregate)
	}

	// Infrastructure namespace sections.
	if len(infraNS) > 0 {
		fmt.Fprintln(w, "## Infrastructure Namespaces")
		fmt.Fprintln(w)
		writeMarkdownNSSections(w, infraNS, nsGroups, aggregate)
	}

	// Cluster-scoped sections.
	if len(clusterNS) > 0 {
		fmt.Fprintln(w, "## Cluster-Scoped Resources")
		fmt.Fprintln(w)
		writeMarkdownNSSections(w, clusterNS, nsGroups, aggregate)
	}

	// Fallback: if no classification produced sections, render all.
	if len(appNS) == 0 && len(infraNS) == 0 && len(clusterNS) == 0 {
		writeMarkdownNSSections(w, namespaces, nsGroups, aggregate)
	}

	return nil
}

// writeMarkdownNSSections writes namespace sections for the given namespace list.
// When aggregate is true, findings with the same checker+message are grouped.
func writeMarkdownNSSections(w io.Writer, namespaces []string, groups map[string][]checker.Finding, aggregate bool) {
	for _, ns := range namespaces {
		label := namespaceSectionLabel(ns)
		nsFindings := groups[ns]
		nsCounts := countBySeverity(nsFindings)

		// Build severity summary suffix.
		var sevParts []string
		if c := nsCounts[checker.SeverityCritical]; c > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%s%d", severityEmoji(checker.SeverityCritical), c))
		}
		if c := nsCounts[checker.SeverityHigh]; c > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%s%d", severityEmoji(checker.SeverityHigh), c))
		}
		if c := nsCounts[checker.SeverityMedium]; c > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%s%d", severityEmoji(checker.SeverityMedium), c))
		}
		if c := nsCounts[checker.SeverityLow]; c > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%s%d", severityEmoji(checker.SeverityLow), c))
		}
		if c := nsCounts[checker.SeverityInfo]; c > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%s%d", severityEmoji(checker.SeverityInfo), c))
		}

		if len(sevParts) > 0 {
			fmt.Fprintf(w, "### %s (%d findings — %s)\n", label, len(nsFindings), strings.Join(sevParts, " "))
		} else {
			fmt.Fprintf(w, "### %s\n", label)
		}
		fmt.Fprintln(w)

		if aggregate {
			writeMarkdownAggregatedTable(w, nsFindings)
		} else {
			writeMarkdownFlatTable(w, nsFindings)
		}
		fmt.Fprintln(w)

		// Write remediation grouped by check.
		writeMarkdownRemediation(w, nsFindings)
	}
}

// writeMarkdownFlatTable writes one row per finding (no aggregation).
func writeMarkdownFlatTable(w io.Writer, findings []checker.Finding) {
	fmt.Fprintf(w, "| Severity | Check | Resource | Message | Frameworks |\n")
	fmt.Fprintf(w, "|----------|-------|----------|---------|-----------|\n")
	for i := range findings {
		resource := formatResource(&findings[i])
		fw := formatFrameworks(findings[i].Frameworks)
		emoji := severityEmoji(findings[i].Severity)
		fmt.Fprintf(w, "| %s %s | %s | %s | %s | %s |\n",
			emoji, findings[i].Severity, findings[i].Checker, resource, findings[i].Message, fw)
	}
}

// writeMarkdownAggregatedTable groups findings by checker+severity and shows
// a count with expandable resource list for groups > 1.
func writeMarkdownAggregatedTable(w io.Writer, findings []checker.Finding) {
	aggs := aggregateFindings(findings)
	fmt.Fprintf(w, "| Severity | Check | Resources | Message | Frameworks |\n")
	fmt.Fprintf(w, "|----------|-------|-----------|---------|-----------|\n")
	for i := range aggs {
		emoji := severityEmoji(aggs[i].Severity)
		fw := formatFrameworks(aggs[i].Frameworks)
		if len(aggs[i].Resources) == 1 {
			res := aggs[i].Resources[0].Name
			if aggs[i].Resources[0].Container != "" {
				res += " (" + aggs[i].Resources[0].Container + ")"
			}
			fmt.Fprintf(w, "| %s %s | %s | %s | %s | %s |\n",
				emoji, aggs[i].Severity, aggs[i].Checker, res, aggs[i].Message, fw)
		} else {
			fmt.Fprintf(w, "| %s %s | %s | **%d resources** | %s | %s |\n",
				emoji, aggs[i].Severity, aggs[i].Checker, len(aggs[i].Resources), aggs[i].Message, fw)
		}
	}

	// Write expandable resource lists for aggregated groups.
	for i := range aggs {
		if len(aggs[i].Resources) > 1 {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "<details>\n<summary>%s: %d affected resources</summary>\n\n",
				aggs[i].Checker, len(aggs[i].Resources))
			for _, r := range aggs[i].Resources {
				res := r.Name
				if r.Container != "" {
					res += " (" + r.Container + ")"
				}
				fmt.Fprintf(w, "- `%s`\n", res)
			}
			fmt.Fprintln(w, "\n</details>")
		}
	}
}

// writeMarkdownRemediation writes collapsible remediation blocks grouped by check.
// Only checks that have remediation text are shown.
func writeMarkdownRemediation(w io.Writer, findings []checker.Finding) {
	// Group findings by checker, preserving first remediation and listing resources.
	type checkGroup struct {
		remediation string
		resources   []string
		count       int
	}
	groups := make(map[string]*checkGroup)
	var order []string
	for i := range findings {
		if findings[i].Remediation == "" {
			continue
		}
		g, ok := groups[findings[i].Checker]
		if !ok {
			g = &checkGroup{remediation: findings[i].Remediation}
			groups[findings[i].Checker] = g
			order = append(order, findings[i].Checker)
		}
		g.count++
		g.resources = append(g.resources, formatResource(&findings[i]))
	}

	for _, checkName := range order {
		g := groups[checkName]
		fmt.Fprintf(w, "<details>\n<summary>Remediation: %s (%d resources affected)</summary>\n\n",
			checkName, g.count)
		fmt.Fprintln(w, g.remediation)
		fmt.Fprintln(w)
		fmt.Fprintf(w, "**Affected resources:** %s\n\n", strings.Join(g.resources, ", "))
		fmt.Fprintln(w, "</details>")
		fmt.Fprintln(w)
	}
}

// groupByNamespace groups findings by namespace. Cluster-scoped findings (empty namespace)
// are grouped under the empty string key.
func groupByNamespace(findings []checker.Finding) map[string][]checker.Finding {
	groups := make(map[string][]checker.Finding)
	for i := range findings {
		ns := findings[i].Namespace
		groups[ns] = append(groups[ns], findings[i])
	}
	return groups
}

// sortedNamespaces returns namespace keys sorted alphabetically,
// with the empty string (cluster-scoped) always last.
func sortedNamespaces(groups map[string][]checker.Finding) []string {
	var namespaces []string
	hasCluster := false
	for ns := range groups {
		if ns == "" {
			hasCluster = true
			continue
		}
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	if hasCluster {
		namespaces = append(namespaces, "")
	}
	return namespaces
}

// namespaceSectionLabel returns the display label for a namespace section header.
func namespaceSectionLabel(ns string) string {
	if ns == "" {
		return "Cluster-Scoped"
	}
	return ns
}

// formatResource builds a resource identifier string.
func formatResource(f *checker.Finding) string {
	if f.Namespace != "" {
		return f.Namespace + "/" + f.Kind + "/" + f.Resource
	}
	return f.Kind + "/" + f.Resource
}

func init() {
	register(&MarkdownReporter{})
}
