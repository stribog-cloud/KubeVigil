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
			sorted[i].Namespace,
			config.ClassifyNamespace(cfg, sorted[i].Namespace).String(),
			sorted[i].Kind,
			sorted[i].Resource,
			sorted[i].Container,
			sorted[i].Message,
			sorted[i].Remediation,
			sorted[i].FieldPath,
			formatFrameworks(sorted[i].Frameworks),
			autoFixable,
			currentVal,
			desiredVal,
		}); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	register(&CSVReporter{})
}
