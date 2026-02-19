package report

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// JSONReporter writes scan results as pretty-printed JSON.
type JSONReporter struct{}

// Name returns "json".
func (r *JSONReporter) Name() string { return "json" }

// Generate writes the scan result as formatted JSON to w.
func (r *JSONReporter) Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	// Ensure findings is never null in JSON.
	if sorted == nil {
		sorted = []checker.Finding{}
	}

	report := jsonReport{
		Version: "1",
		ScanResult: jsonScanResult{
			Findings:    sorted,
			ClusterInfo: result.ClusterInfo,
			ScanMeta: jsonScanMeta{
				StartTime:     result.ScanMeta.StartTime,
				Duration:      result.ScanMeta.Duration.String(),
				ChecksRun:     result.ScanMeta.ChecksRun,
				ChecksSkipped: result.ScanMeta.ChecksSkipped,
				ChecksErrored: result.ScanMeta.ChecksErrored,
				ScanMode:      result.ScanMeta.ScanMode,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

type jsonReport struct {
	Version    string         `json:"version"`
	ScanResult jsonScanResult `json:"scan_result"`
}

type jsonScanResult struct {
	Findings    []checker.Finding   `json:"findings"`
	ClusterInfo checker.ClusterInfo `json:"cluster_info"`
	ScanMeta    jsonScanMeta        `json:"scan_meta"`
}

type jsonScanMeta struct {
	StartTime     time.Time        `json:"start_time"`
	Duration      string           `json:"duration"`
	ChecksRun     int              `json:"checks_run"`
	ChecksSkipped int              `json:"checks_skipped"`
	ChecksErrored int              `json:"checks_errored"`
	ScanMode      checker.ScanMode `json:"scan_mode"`
}
