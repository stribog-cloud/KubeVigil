package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/version"
)

// SARIFReporter writes scan results in SARIF 2.1.0 format.
type SARIFReporter struct{}

// Name returns "sarif".
func (r *SARIFReporter) Name() string { return "sarif" }

// Generate writes a SARIF 2.1.0 JSON report to w.
func (r *SARIFReporter) Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	// Collect unique rules.
	ruleIndex := make(map[string]int)
	var rules []sarifRule
	for i := range sorted {
		if _, ok := ruleIndex[sorted[i].Checker]; !ok {
			rule := sarifRule{
				ID:               sorted[i].Checker,
				ShortDescription: sarifMessage{Text: sorted[i].Checker},
				DefaultConfig: sarifRuleConfig{
					Level: sarifLevel(sorted[i].Severity),
				},
			}
			if len(sorted[i].Frameworks) > 0 {
				props := &sarifRuleProperties{}
				for j := range sorted[i].Frameworks {
					props.Tags = append(props.Tags,
						fmt.Sprintf("%s/%s/%s", sorted[i].Frameworks[j].Framework,
							sorted[i].Frameworks[j].Version, sorted[i].Frameworks[j].ControlID))
				}
				rule.Properties = props
			}
			ruleIndex[sorted[i].Checker] = len(rules)
			rules = append(rules, rule)
		}
	}

	// Build results.
	var results []sarifResult
	for i := range sorted {
		sr := sarifResult{
			RuleID:    sorted[i].Checker,
			RuleIndex: ruleIndex[sorted[i].Checker],
			Level:     sarifLevel(sorted[i].Severity),
			Message:   sarifMessage{Text: sorted[i].Message},
		}
		if sorted[i].FieldPath != "" {
			sr.Locations = []sarifLocation{
				{
					LogicalLocations: []sarifLogicalLocation{
						{
							Name:               sorted[i].Resource,
							FullyQualifiedName: formatResource(&sorted[i]),
							DecoratedName:      sorted[i].FieldPath,
						},
					},
				},
			}
		}
		results = append(results, sr)
	}

	summary := ComputeSummary(result)

	report := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "kubevigil",
						Version:        version.Version,
						InformationURI: "https://github.com/stribog-cloud/kubevigil",
						Rules:          rules,
					},
				},
				Results: results,
				Properties: sarifRunProperties{
					PostureScore:     summary.PostureScore,
					TotalFindings:    len(sorted),
					Critical:         summary.SeverityCounts[checker.SeverityCritical],
					High:             summary.SeverityCounts[checker.SeverityHigh],
					Medium:           summary.SeverityCounts[checker.SeverityMedium],
					Low:              summary.SeverityCounts[checker.SeverityLow],
					Info:             summary.SeverityCounts[checker.SeverityInfo],
					UniqueResources:  summary.UniqueResources,
					UniqueNamespaces: summary.UniqueNamespaces,
					ChecksRun:        summary.CheckCoverage.TotalRun,
					ChecksWithFind:   summary.CheckCoverage.WithFindings,
					ChecksClean:      summary.CheckCoverage.Clean,
					ChecksSkipped:    summary.CheckCoverage.Skipped,
					ChecksErrored:    summary.CheckCoverage.Errored,
				},
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

// sarifLevel maps checker severity to SARIF result level.
func sarifLevel(s checker.Severity) string {
	switch s {
	case checker.SeverityCritical, checker.SeverityHigh:
		return "error"
	case checker.SeverityMedium:
		return "warning"
	case checker.SeverityLow, checker.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// SARIF 2.1.0 types.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool          `json:"tool"`
	Results    []sarifResult      `json:"results"`
	Properties sarifRunProperties `json:"properties"`
}

type sarifRunProperties struct {
	PostureScore     int `json:"posture_score"`
	TotalFindings    int `json:"total_findings"`
	Critical         int `json:"critical"`
	High             int `json:"high"`
	Medium           int `json:"medium"`
	Low              int `json:"low"`
	Info             int `json:"info"`
	UniqueResources  int `json:"unique_resources"`
	UniqueNamespaces int `json:"unique_namespaces"`
	ChecksRun        int `json:"checks_run"`
	ChecksWithFind   int `json:"checks_with_findings"`
	ChecksClean      int `json:"checks_clean"`
	ChecksSkipped    int `json:"checks_skipped"`
	ChecksErrored    int `json:"checks_errored"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string               `json:"id"`
	ShortDescription sarifMessage         `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig      `json:"defaultConfiguration"`
	Properties       *sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	DecoratedName      string `json:"decoratedName,omitempty"`
}

func init() {
	register(&SARIFReporter{})
}
