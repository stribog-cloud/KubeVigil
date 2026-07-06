package report

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"slices"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/version"
)

// CSVReporter writes scan results as CSV.
type CSVReporter struct {
	// Config is optional; when set, enables namespace classification.
	Config *config.Config
}

// csvSafe neutralizes CSV formula injection (CWE-1236). A cell whose first
// character is one of = + - @ (or a leading tab/carriage-return) is interpreted
// as a formula by Excel, Google Sheets, and LibreOffice, so a hostile
// Kubernetes resource name like `=cmd|'/c calc'!A0` would execute when a
// reviewer opens the exported CSV. Prefixing such a cell with a single quote
// forces the spreadsheet to treat it as literal text while remaining
// human-readable. Empty cells are left untouched.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// Name returns "csv".
func (r *CSVReporter) Name() string { return "csv" }

// SetConfig sets the config for namespace classification.
func (r *CSVReporter) SetConfig(cfg *config.Config) { r.Config = cfg }

// Generate writes the scan findings as CSV to w.
func (r *CSVReporter) Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	cfg := r.Config
	if cfg == nil {
		cfg = config.Default()
	}

	summary := ComputeSummary(result)

	// Metadata header (comment lines).
	fmt.Fprintf(w, "# KubeVigil Scan Report\n")
	fmt.Fprintf(w, "# Version: %s\n", version.Version)
	fmt.Fprintf(w, "# Scan Mode: %s\n", result.ScanMeta.ScanMode)
	fmt.Fprintf(w, "# Date: %s\n", result.ScanMeta.StartTime.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(w, "# Posture Score: %d/100\n", summary.PostureScore)
	fmt.Fprintf(w, "# Total Findings: %d\n", len(sorted))

	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header.
	if err := cw.Write([]string{
		"Severity", "Checker", "Namespace", "Namespace_Type", "Kind", "Resource", "Container",
		"Message", "Remediation", "FieldPath", "Frameworks", "Auto_Fixable", "CurrentValue", "DesiredValue",
	}); err != nil {
		return err
	}

	for i := range sorted {
		autoFixable := "false"
		if sorted[i].FixHint != nil {
			autoFixable = "true"
		}
		currentVal := ""
		if sorted[i].CurrentValue != nil {
			currentVal = fmt.Sprintf("%v", sorted[i].CurrentValue)
		}
		desiredVal := ""
		if sorted[i].DesiredValue != nil {
			desiredVal = fmt.Sprintf("%v", sorted[i].DesiredValue)
		}
		if err := cw.Write([]string{
			sorted[i].Severity.String(),
			sorted[i].Checker,
			csvSafe(sorted[i].Namespace),
			config.ClassifyNamespace(cfg, sorted[i].Namespace).String(),
			csvSafe(sorted[i].Kind),
			csvSafe(sorted[i].Resource),
			csvSafe(sorted[i].Container),
			csvSafe(sorted[i].Message),
			csvSafe(sorted[i].Remediation),
			csvSafe(sorted[i].FieldPath),
			formatFrameworks(sorted[i].Frameworks),
			autoFixable,
			csvSafe(currentVal),
			csvSafe(desiredVal),
		}); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	register(&CSVReporter{})
}
