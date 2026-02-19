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
			Summary: yamlSummary{
				PostureScore:     summary.PostureScore,
				TotalFindings:    len(result.Findings),
				Critical:         summary.SeverityCounts[checker.SeverityCritical],
				High:             summary.SeverityCounts[checker.SeverityHigh],
				Medium:           summary.SeverityCounts[checker.SeverityMedium],
				Low:              summary.SeverityCounts[checker.SeverityLow],
				Info:             summary.SeverityCounts[checker.SeverityInfo],
				UniqueResources:  summary.UniqueResources,
				UniqueNamespaces: summary.UniqueNamespaces,
			},
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
	PostureScore     int `yaml:"posture_score"`
	TotalFindings    int `yaml:"total_findings"`
	Critical         int `yaml:"critical"`
	High             int `yaml:"high"`
	Medium           int `yaml:"medium"`
	Low              int `yaml:"low"`
	Info             int `yaml:"info"`
	UniqueResources  int `yaml:"unique_resources"`
	UniqueNamespaces int `yaml:"unique_namespaces"`
}

type yamlScanMeta struct {
	StartTime     time.Time `yaml:"start_time"`
	Duration      string    `yaml:"duration"`
	ChecksRun     int       `yaml:"checks_run"`
	ChecksSkipped int       `yaml:"checks_skipped"`
	ChecksErrored int       `yaml:"checks_errored"`
	ScanMode      string    `yaml:"scan_mode"`
}

func init() {
	register(&YAMLReporter{})
}
