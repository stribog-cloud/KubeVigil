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
	PostureScore      int                  `json:"posture_score"`
	AppPostureScore   int                  `json:"app_posture_score"`
	InfraPostureScore int                  `json:"infra_posture_score"`
	TotalFindings     int                  `json:"total_findings"`
	Critical          int                  `json:"critical"`
	High              int                  `json:"high"`
	Medium            int                  `json:"medium"`
	Low               int                  `json:"low"`
	Info              int                  `json:"info"`
	UniqueResources   int                  `json:"unique_resources"`
	UniqueNamespaces  int                  `json:"unique_namespaces"`
	CheckCoverage     jsonCheckCoverage    `json:"check_coverage"`
	PassedChecks      []string             `json:"passed_checks"`
	TopRisks          []checker.Finding    `json:"top_risks"`
	CheckAggregates   []jsonCheckAggregate `json:"check_aggregates"`
	TierBreakdown     jsonTierBreakdown    `json:"tier_breakdown"`
}

// jsonCheckAggregate summarises findings for a single check in JSON output.
type jsonCheckAggregate struct {
	Checker      string `json:"checker"`
	Severity     string `json:"severity"`
	Count        int    `json:"count"`
	Resources    int    `json:"resources"`
	Namespaces   int    `json:"namespaces"`
	AppCount     int    `json:"app_count"`
	InfraCount   int    `json:"infra_count"`
	ClusterCount int    `json:"cluster_count"`
}

// jsonTierBreakdown groups findings by deployment tier.
type jsonTierBreakdown struct {
	App     jsonTierStats `json:"app"`
	Infra   jsonTierStats `json:"infra"`
	Cluster jsonTierStats `json:"cluster"`
}

// jsonTierStats holds severity counts for a deployment tier.
type jsonTierStats struct {
	Namespaces int `json:"namespaces"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Info       int `json:"info"`
}

type jsonCheckCoverage struct {
	TotalRun     int `json:"total_run"`
	WithFindings int `json:"with_findings"`
	Clean        int `json:"clean"`
	Skipped      int `json:"skipped"`
	Errored      int `json:"errored"`
}

func newJSONSummary(s *ExecutiveSummary) jsonSummary {
	// Ensure slices are never nil so JSON outputs [] instead of null.
	passedChecks := s.PassedChecks
	if passedChecks == nil {
		passedChecks = []string{}
	}

	topRisks := s.TopRisks
	if topRisks == nil {
		topRisks = []checker.Finding{}
	}

	aggregates := make([]jsonCheckAggregate, 0, len(s.CheckAggregates))
	for _, agg := range s.CheckAggregates {
		aggregates = append(aggregates, jsonCheckAggregate{
			Checker:      agg.Checker,
			Severity:     agg.Severity.String(),
			Count:        agg.Count,
			Resources:    agg.Resources,
			Namespaces:   agg.Namespaces,
			AppCount:     agg.AppCount,
			InfraCount:   agg.InfraCount,
			ClusterCount: agg.ClusterCount,
		})
	}

	return jsonSummary{
		PostureScore:      s.PostureScore,
		AppPostureScore:   s.AppPostureScore,
		InfraPostureScore: s.InfraPostureScore,
		TotalFindings:     s.SeverityCounts[checker.SeverityCritical] + s.SeverityCounts[checker.SeverityHigh] + s.SeverityCounts[checker.SeverityMedium] + s.SeverityCounts[checker.SeverityLow] + s.SeverityCounts[checker.SeverityInfo],
		Critical:          s.SeverityCounts[checker.SeverityCritical],
		High:              s.SeverityCounts[checker.SeverityHigh],
		Medium:            s.SeverityCounts[checker.SeverityMedium],
		Low:               s.SeverityCounts[checker.SeverityLow],
		Info:              s.SeverityCounts[checker.SeverityInfo],
		UniqueResources:   s.UniqueResources,
		UniqueNamespaces:  s.UniqueNamespaces,
		CheckCoverage: jsonCheckCoverage{
			TotalRun:     s.CheckCoverage.TotalRun,
			WithFindings: s.CheckCoverage.WithFindings,
			Clean:        s.CheckCoverage.Clean,
			Skipped:      s.CheckCoverage.Skipped,
			Errored:      s.CheckCoverage.Errored,
		},
		PassedChecks:    passedChecks,
		TopRisks:        topRisks,
		CheckAggregates: aggregates,
		TierBreakdown: jsonTierBreakdown{
			App: jsonTierStats{
				Namespaces: s.AppStats.Count,
				Critical:   s.AppStats.SeverityCounts[checker.SeverityCritical],
				High:       s.AppStats.SeverityCounts[checker.SeverityHigh],
				Medium:     s.AppStats.SeverityCounts[checker.SeverityMedium],
				Low:        s.AppStats.SeverityCounts[checker.SeverityLow],
				Info:       s.AppStats.SeverityCounts[checker.SeverityInfo],
			},
			Infra: jsonTierStats{
				Namespaces: s.InfraStats.Count,
				Critical:   s.InfraStats.SeverityCounts[checker.SeverityCritical],
				High:       s.InfraStats.SeverityCounts[checker.SeverityHigh],
				Medium:     s.InfraStats.SeverityCounts[checker.SeverityMedium],
				Low:        s.InfraStats.SeverityCounts[checker.SeverityLow],
				Info:       s.InfraStats.SeverityCounts[checker.SeverityInfo],
			},
			Cluster: jsonTierStats{
				Critical: s.ClusterScopedCounts[checker.SeverityCritical],
				High:     s.ClusterScopedCounts[checker.SeverityHigh],
				Medium:   s.ClusterScopedCounts[checker.SeverityMedium],
				Low:      s.ClusterScopedCounts[checker.SeverityLow],
				Info:     s.ClusterScopedCounts[checker.SeverityInfo],
			},
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
