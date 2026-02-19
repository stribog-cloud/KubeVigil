package report

import (
	"context"
	"io"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/version"
)

// YAMLReporter writes scan results as YAML.
type YAMLReporter struct{}

// Name returns "yaml".
func (r *YAMLReporter) Name() string { return "yaml" }

// Generate writes the scan result as YAML to w.
func (r *YAMLReporter) Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	if sorted == nil {
		sorted = []checker.Finding{}
	}

	summary := ComputeSummary(result)

	report := yamlReport{
		Version:     "1",
		ToolVersion: version.Version,
		ScanResult: yamlScanResult{
			Summary:     newYAMLSummary(&summary),
			Findings:    sorted,
			ClusterInfo: result.ClusterInfo,
			ScanMeta: yamlScanMeta{
				StartTime:     result.ScanMeta.StartTime,
				Duration:      result.ScanMeta.Duration.String(),
				ChecksRun:     result.ScanMeta.ChecksRun,
				ChecksSkipped: result.ScanMeta.ChecksSkipped,
				ChecksErrored: result.ScanMeta.ChecksErrored,
				ScanMode:      result.ScanMeta.ScanMode.String(),
			},
		},
	}

	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(report); err != nil {
		return err
	}
	return enc.Close()
}

type yamlReport struct {
	Version     string         `yaml:"version"`
	ToolVersion string         `yaml:"tool_version"`
	ScanResult  yamlScanResult `yaml:"scan_result"`
}

type yamlScanResult struct {
	Summary     yamlSummary         `yaml:"summary"`
	Findings    []checker.Finding   `yaml:"findings"`
	ClusterInfo checker.ClusterInfo `yaml:"cluster_info"`
	ScanMeta    yamlScanMeta        `yaml:"scan_meta"`
}

type yamlSummary struct {
	PostureScore      int                  `yaml:"posture_score"`
	AppPostureScore   int                  `yaml:"app_posture_score"`
	InfraPostureScore int                  `yaml:"infra_posture_score"`
	TotalFindings     int                  `yaml:"total_findings"`
	Critical          int                  `yaml:"critical"`
	High              int                  `yaml:"high"`
	Medium            int                  `yaml:"medium"`
	Low               int                  `yaml:"low"`
	Info              int                  `yaml:"info"`
	UniqueResources   int                  `yaml:"unique_resources"`
	UniqueNamespaces  int                  `yaml:"unique_namespaces"`
	CheckCoverage     yamlCheckCoverage    `yaml:"check_coverage"`
	PassedChecks      []string             `yaml:"passed_checks"`
	TopRisks          []checker.Finding    `yaml:"top_risks"`
	CheckAggregates   []yamlCheckAggregate `yaml:"check_aggregates"`
	TierBreakdown     yamlTierBreakdown    `yaml:"tier_breakdown"`
}

// yamlCheckCoverage summarises check execution in YAML output.
type yamlCheckCoverage struct {
	TotalRun     int `yaml:"total_run"`
	WithFindings int `yaml:"with_findings"`
	Clean        int `yaml:"clean"`
	Skipped      int `yaml:"skipped"`
	Errored      int `yaml:"errored"`
}

// yamlCheckAggregate summarises findings for a single check in YAML output.
type yamlCheckAggregate struct {
	Checker      string `yaml:"checker"`
	Severity     string `yaml:"severity"`
	Count        int    `yaml:"count"`
	Resources    int    `yaml:"resources"`
	Namespaces   int    `yaml:"namespaces"`
	AppCount     int    `yaml:"app_count"`
	InfraCount   int    `yaml:"infra_count"`
	ClusterCount int    `yaml:"cluster_count"`
}

// yamlTierBreakdown groups findings by deployment tier.
type yamlTierBreakdown struct {
	App     yamlTierStats `yaml:"app"`
	Infra   yamlTierStats `yaml:"infra"`
	Cluster yamlTierStats `yaml:"cluster"`
}

// yamlTierStats holds severity counts for a deployment tier.
type yamlTierStats struct {
	Namespaces int `yaml:"namespaces"`
	Critical   int `yaml:"critical"`
	High       int `yaml:"high"`
	Medium     int `yaml:"medium"`
	Low        int `yaml:"low"`
	Info       int `yaml:"info"`
}

type yamlScanMeta struct {
	StartTime     time.Time `yaml:"start_time"`
	Duration      string    `yaml:"duration"`
	ChecksRun     int       `yaml:"checks_run"`
	ChecksSkipped int       `yaml:"checks_skipped"`
	ChecksErrored int       `yaml:"checks_errored"`
	ScanMode      string    `yaml:"scan_mode"`
}

func newYAMLSummary(s *ExecutiveSummary) yamlSummary {
	// Ensure slices are never nil so YAML outputs [] instead of omitting.
	passedChecks := s.PassedChecks
	if passedChecks == nil {
		passedChecks = []string{}
	}

	topRisks := s.TopRisks
	if topRisks == nil {
		topRisks = []checker.Finding{}
	}

	aggregates := make([]yamlCheckAggregate, 0, len(s.CheckAggregates))
	for _, agg := range s.CheckAggregates {
		aggregates = append(aggregates, yamlCheckAggregate{
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

	return yamlSummary{
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
		CheckCoverage: yamlCheckCoverage{
			TotalRun:     s.CheckCoverage.TotalRun,
			WithFindings: s.CheckCoverage.WithFindings,
			Clean:        s.CheckCoverage.Clean,
			Skipped:      s.CheckCoverage.Skipped,
			Errored:      s.CheckCoverage.Errored,
		},
		PassedChecks:    passedChecks,
		TopRisks:        topRisks,
		CheckAggregates: aggregates,
		TierBreakdown: yamlTierBreakdown{
			App: yamlTierStats{
				Namespaces: s.AppStats.Count,
				Critical:   s.AppStats.SeverityCounts[checker.SeverityCritical],
				High:       s.AppStats.SeverityCounts[checker.SeverityHigh],
				Medium:     s.AppStats.SeverityCounts[checker.SeverityMedium],
				Low:        s.AppStats.SeverityCounts[checker.SeverityLow],
				Info:       s.AppStats.SeverityCounts[checker.SeverityInfo],
			},
			Infra: yamlTierStats{
				Namespaces: s.InfraStats.Count,
				Critical:   s.InfraStats.SeverityCounts[checker.SeverityCritical],
				High:       s.InfraStats.SeverityCounts[checker.SeverityHigh],
				Medium:     s.InfraStats.SeverityCounts[checker.SeverityMedium],
				Low:        s.InfraStats.SeverityCounts[checker.SeverityLow],
				Info:       s.InfraStats.SeverityCounts[checker.SeverityInfo],
			},
			Cluster: yamlTierStats{
				Critical: s.ClusterScopedCounts[checker.SeverityCritical],
				High:     s.ClusterScopedCounts[checker.SeverityHigh],
				Medium:   s.ClusterScopedCounts[checker.SeverityMedium],
				Low:      s.ClusterScopedCounts[checker.SeverityLow],
				Info:     s.ClusterScopedCounts[checker.SeverityInfo],
			},
		},
	}
}

func init() {
	register(&YAMLReporter{})
}
