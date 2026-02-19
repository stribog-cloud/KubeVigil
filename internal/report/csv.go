package report

import (
	"context"
	"encoding/csv"
	"io"
	"slices"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
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

	cw := csv.NewWriter(w)
	defer cw.Flush()

	cfg := r.Config
	if cfg == nil {
		cfg = config.Default()
	}

	// Header.
	if err := cw.Write([]string{
		"Severity", "Checker", "Namespace", "Namespace_Type", "Kind", "Resource", "Container", "Message", "Remediation", "FieldPath", "Frameworks",
	}); err != nil {
		return err
	}

	for i := range sorted {
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
		}); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	register(&CSVReporter{})
}
