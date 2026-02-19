package fix

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ReportOptions controls the content and formatting of a fix report.
type ReportOptions struct {
	// Timestamp is the time to display in the report header.
	// If zero, defaults to time.Now().
	Timestamp time.Time
	// RiskLevel is the risk level used for the fix operation.
	RiskLevel RiskLevel
	// Applied is true if fixes were applied, false for dry-run mode.
	Applied bool
	// BackupDir is the backup directory path. Empty means no backup was created.
	BackupDir string
	// SourcePath is the path to the source manifests that were scanned.
	SourcePath string
}

// GenerateFixReport produces a Markdown fix report (FIX-REPORT.md content)
// from a fix plan and options. The report includes a summary, per-file changes,
// impact warnings, skipped findings, manual remediation guidance, and restore
// instructions.
func GenerateFixReport(plan *Plan, opts ReportOptions) ([]byte, error) {
	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	var b strings.Builder

	writeHeader(&b, ts, opts)
	writeSummary(&b, &plan.Summary)
	writeChangesByFile(&b, plan.Summary.Results)
	writeWhatCouldBreak(&b, plan.Summary.Results)
	writeSkippedFindings(&b, plan.Summary.SkipReasons, plan.Summary.Results)
	writeManualRemediation(&b, plan.Summary.Results)
	writeRestoreInstructions(&b, opts)

	return []byte(b.String()), nil
}

// WriteFixReport generates a fix report and writes it to the given file path.
func WriteFixReport(plan *Plan, opts ReportOptions, path string) error {
	data, err := GenerateFixReport(plan, opts)
	if err != nil {
		return fmt.Errorf("generating fix report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing fix report to %s: %w", path, err)
	}
	return nil
}

// writeHeader writes the report header with timestamp, risk level, mode, and source path.
func writeHeader(b *strings.Builder, ts time.Time, opts ReportOptions) {
	fmt.Fprintf(b, "# KubeVigil Fix Report\n\n")

	mode := "Dry-run"
	if opts.Applied {
		mode = "Applied"
	}

	fmt.Fprintf(b, "- **Timestamp:** %s\n", ts.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(b, "- **Risk level:** %s\n", string(opts.RiskLevel))
	fmt.Fprintf(b, "- **Mode:** %s\n", mode)
	if opts.SourcePath != "" {
		fmt.Fprintf(b, "- **Source:** %s\n", opts.SourcePath)
	}
	fmt.Fprintf(b, "\n")
}

// writeSummary writes the summary table section.
func writeSummary(b *strings.Builder, summary *Summary) {
	fmt.Fprintf(b, "## Summary\n\n")
	fmt.Fprintf(b, "| Metric | Count |\n")
	fmt.Fprintf(b, "|--------|-------|\n")
	fmt.Fprintf(b, "| Files scanned | %d |\n", summary.FilesScanned)
	fmt.Fprintf(b, "| Files modified | %d |\n", summary.FilesModified)
	fmt.Fprintf(b, "| Files failed | %d |\n", summary.FilesFailed)
	fmt.Fprintf(b, "| Total findings | %d |\n", summary.TotalFindings)
	fmt.Fprintf(b, "| Applied | %d |\n", summary.Applied)
	fmt.Fprintf(b, "| Skipped | %d |\n", summary.Skipped)
	fmt.Fprintf(b, "\n")

	// Risk breakdown (deterministic order).
	if len(summary.ByRisk) > 0 {
		fmt.Fprintf(b, "**By risk classification:**\n\n")
		riskOrder := []checker.FixSafety{
			checker.FixSafe,
			checker.FixLikelySafe,
			checker.FixPotentiallyBreaking,
			checker.FixManualOnly,
		}
		for _, safety := range riskOrder {
			if count, ok := summary.ByRisk[safety]; ok && count > 0 {
				fmt.Fprintf(b, "- %s: %d\n", string(safety), count)
			}
		}
		fmt.Fprintf(b, "\n")
	}
}

// writeChangesByFile writes the per-file changes section.
func writeChangesByFile(b *strings.Builder, results []Result) {
	// Collect applied results grouped by file path.
	fileResults := make(map[string][]Result)
	for i := range results {
		if results[i].Applied {
			fileResults[results[i].FilePath] = append(fileResults[results[i].FilePath], results[i])
		}
	}

	fmt.Fprintf(b, "## Changes by File\n\n")

	if len(fileResults) == 0 {
		fmt.Fprintf(b, "No changes were applied.\n\n")
		return
	}

	// Sort file paths for deterministic output.
	filePaths := make([]string, 0, len(fileResults))
	for fp := range fileResults {
		filePaths = append(filePaths, fp)
	}
	sort.Strings(filePaths)

	for _, fp := range filePaths {
		fixes := fileResults[fp]
		fmt.Fprintf(b, "### `%s`\n\n", fp)
		for _, r := range fixes {
			fmt.Fprintf(b, "- **%s** %s/%s (check: `%s`, safety: %s): %s\n",
				r.Kind, r.Namespace, r.Resource, r.CheckID, string(r.Safety), r.Description)
		}
		fmt.Fprintf(b, "\n")
	}
}

// writeWhatCouldBreak writes the impact warnings section for non-safe applied fixes.
// This section is omitted entirely if there are no applicable entries.
func writeWhatCouldBreak(b *strings.Builder, results []Result) {
	var warnings []Result
	for i := range results {
		r := &results[i]
		if r.Applied && r.Impact != "" &&
			(r.Safety == checker.FixLikelySafe || r.Safety == checker.FixPotentiallyBreaking) {
			warnings = append(warnings, *r)
		}
	}

	if len(warnings) == 0 {
		return
	}

	fmt.Fprintf(b, "## What Could Break\n\n")
	for _, w := range warnings {
		fmt.Fprintf(b, "- **%s** %s/%s (check: `%s`, safety: %s): %s\n",
			w.Kind, w.Namespace, w.Resource, w.CheckID, string(w.Safety), w.Impact)
	}
	fmt.Fprintf(b, "\n")
}

// writeSkippedFindings writes the skipped findings section grouped by reason.
// This section is omitted entirely if there are no skipped fixes.
func writeSkippedFindings(b *strings.Builder, skipReasons map[string]int, results []Result) {
	if len(skipReasons) == 0 {
		return
	}

	// Filter out manual_only from the skip reasons — those get their own section.
	hasNonManual := false
	for reason := range skipReasons {
		if reason != "manual_only" {
			hasNonManual = true
			break
		}
	}

	if !hasNonManual {
		return
	}

	fmt.Fprintf(b, "## Skipped Findings\n\n")

	// Sort reasons for deterministic output.
	reasons := make([]string, 0, len(skipReasons))
	for reason := range skipReasons {
		if reason == "manual_only" {
			continue
		}
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)

	for _, reason := range reasons {
		count := skipReasons[reason]
		label := reportSkipReasonLabel(reason)
		fmt.Fprintf(b, "### %s (%d)\n\n", label, count)

		// List the individual skipped results for this reason.
		for i := range results {
			if !results[i].Applied && results[i].SkipReason == reason {
				fmt.Fprintf(b, "- **%s** %s/%s (check: `%s`, safety: %s): %s\n",
					results[i].Kind, results[i].Namespace, results[i].Resource,
					results[i].CheckID, string(results[i].Safety), results[i].Description)
			}
		}
		fmt.Fprintf(b, "\n")
	}
}

// writeManualRemediation writes guidance for findings that require manual intervention.
// This section is omitted entirely if there are no manual-only findings.
func writeManualRemediation(b *strings.Builder, results []Result) {
	var manualResults []Result
	for i := range results {
		r := &results[i]
		if !r.Applied && (r.Safety == checker.FixManualOnly || strings.Contains(r.SkipReason, "manual")) {
			manualResults = append(manualResults, *r)
		}
	}

	if len(manualResults) == 0 {
		return
	}

	fmt.Fprintf(b, "## Manual Remediation\n\n")
	fmt.Fprintf(b, "The following findings cannot be auto-fixed and require manual intervention:\n\n")
	for _, r := range manualResults {
		fmt.Fprintf(b, "- **%s** %s/%s (check: `%s`): %s\n",
			r.Kind, r.Namespace, r.Resource, r.CheckID, r.Description)
	}
	fmt.Fprintf(b, "\n")
}

// writeRestoreInstructions writes the restore instructions section.
func writeRestoreInstructions(b *strings.Builder, opts ReportOptions) {
	fmt.Fprintf(b, "## Restore Instructions\n\n")

	if opts.BackupDir != "" {
		fmt.Fprintf(b, "A backup was created before applying fixes.\n\n")
		fmt.Fprintf(b, "**Backup directory:** `%s`\n\n", opts.BackupDir)
		fmt.Fprintf(b, "To restore all files:\n\n")
		fmt.Fprintf(b, "```bash\ncp -r %s/* <original-path>/\n```\n\n", opts.BackupDir)
		fmt.Fprintf(b, "See `%s/RESTORE.md` for individual file restore commands.\n", opts.BackupDir)
	} else {
		fmt.Fprintf(b, "No backup was created (dry-run mode).\n")
	}
}

// reportSkipReasonLabel maps internal skip reason keys to human-readable labels
// for use in fix reports.
func reportSkipReasonLabel(reason string) string {
	switch reason {
	case "system_namespace":
		return "System namespace"
	case "risk_level":
		return "Risk level exceeded"
	case "check_not_selected":
		return "Check filtered"
	case "severity_not_selected":
		return "Severity filtered"
	case "namespace_not_selected":
		return "Namespace filtered"
	case "namespace_excluded":
		return "Namespace excluded"
	case "known_workload":
		return "Known system workload"
	case "manual_only":
		return "Manual only"
	default:
		return reason
	}
}
