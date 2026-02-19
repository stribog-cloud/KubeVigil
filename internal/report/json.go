package report

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/version"
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

	summary := ComputeSummary(result)

	report := jsonReport{
		Version:     "1",
		ToolVersion: version.Version,
		ScanResult: jsonScanResult{
			Summary:     newJSONSummary(&summary),
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
	Version     string         `json:"version"`
	ToolVersion string         `json:"tool_version"`
	ScanResult  jsonScanResult `json:"scan_result"`
}

type jsonScanResult struct {
	Summary     jsonSummary         `json:"summary"`
	Findings    []checker.Finding   `json:"findings"`
	ClusterInfo checker.ClusterInfo `json:"cluster_info"`
	ScanMeta    jsonScanMeta        `json:"scan_meta"`
}

type jsonSummary struct {
	PostureScore     int               `json:"posture_score"`
	TotalFindings    int               `json:"total_findings"`
	Critical         int               `json:"critical"`
	High             int               `json:"high"`
	Medium           int               `json:"medium"`
	Low              int               `json:"low"`
	Info             int               `json:"info"`
	UniqueResources  int               `json:"unique_resources"`
	UniqueNamespaces int               `json:"unique_namespaces"`
	CheckCoverage    jsonCheckCoverage `json:"check_coverage"`
}

type jsonCheckCoverage struct {
	TotalRun     int `json:"total_run"`
	WithFindings int `json:"with_findings"`
	Clean        int `json:"clean"`
	Skipped      int `json:"skipped"`
	Errored      int `json:"errored"`
}

func newJSONSummary(s *ExecutiveSummary) jsonSummary {
	return jsonSummary{
		PostureScore:     s.PostureScore,
		TotalFindings:    s.SeverityCounts[checker.SeverityCritical] + s.SeverityCounts[checker.SeverityHigh] + s.SeverityCounts[checker.SeverityMedium] + s.SeverityCounts[checker.SeverityLow] + s.SeverityCounts[checker.SeverityInfo],
		Critical:         s.SeverityCounts[checker.SeverityCritical],
		High:             s.SeverityCounts[checker.SeverityHigh],
		Medium:           s.SeverityCounts[checker.SeverityMedium],
		Low:              s.SeverityCounts[checker.SeverityLow],
		Info:             s.SeverityCounts[checker.SeverityInfo],
		UniqueResources:  s.UniqueResources,
		UniqueNamespaces: s.UniqueNamespaces,
		CheckCoverage: jsonCheckCoverage{
			TotalRun:     s.CheckCoverage.TotalRun,
			WithFindings: s.CheckCoverage.WithFindings,
			Clean:        s.CheckCoverage.Clean,
			Skipped:      s.CheckCoverage.Skipped,
			Errored:      s.CheckCoverage.Errored,
		},
	}
}

type jsonScanMeta struct {
	StartTime     time.Time        `json:"start_time"`
	Duration      string           `json:"duration"`
	ChecksRun     int              `json:"checks_run"`
	ChecksSkipped int              `json:"checks_skipped"`
	ChecksErrored int              `json:"checks_errored"`
	ScanMode      checker.ScanMode `json:"scan_mode"`
}
