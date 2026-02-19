package report

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"slices"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// JUnitReporter writes scan results as JUnit XML.
type JUnitReporter struct{}

// Name returns "junit".
func (r *JUnitReporter) Name() string { return "junit" }

// Generate writes a JUnit XML report to w.
func (r *JUnitReporter) Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	sorted := slices.Clone(result.Findings)
	sortFindings(sorted)

	// Group findings by checker name as test suites.
	suiteMap := make(map[string][]checker.Finding)
	var suiteOrder []string
	for i := range sorted {
		name := sorted[i].Checker
		if _, exists := suiteMap[name]; !exists {
			suiteOrder = append(suiteOrder, name)
		}
		suiteMap[name] = append(suiteMap[name], sorted[i])
	}

	summary := ComputeSummary(result)

	var suites junitTestSuites
	suites.Tests = len(sorted)
	suites.Failures = len(sorted)
	suites.Properties = []junitProperty{
		{Name: "posture_score", Value: fmt.Sprintf("%d", summary.PostureScore)},
		{Name: "total_findings", Value: fmt.Sprintf("%d", len(sorted))},
		{Name: "critical", Value: fmt.Sprintf("%d", summary.SeverityCounts[checker.SeverityCritical])},
		{Name: "high", Value: fmt.Sprintf("%d", summary.SeverityCounts[checker.SeverityHigh])},
		{Name: "medium", Value: fmt.Sprintf("%d", summary.SeverityCounts[checker.SeverityMedium])},
		{Name: "low", Value: fmt.Sprintf("%d", summary.SeverityCounts[checker.SeverityLow])},
		{Name: "info", Value: fmt.Sprintf("%d", summary.SeverityCounts[checker.SeverityInfo])},
		{Name: "unique_resources", Value: fmt.Sprintf("%d", summary.UniqueResources)},
		{Name: "unique_namespaces", Value: fmt.Sprintf("%d", summary.UniqueNamespaces)},
		{Name: "checks_run", Value: fmt.Sprintf("%d", summary.CheckCoverage.TotalRun)},
		{Name: "checks_with_findings", Value: fmt.Sprintf("%d", summary.CheckCoverage.WithFindings)},
		{Name: "checks_clean", Value: fmt.Sprintf("%d", summary.CheckCoverage.Clean)},
		{Name: "checks_skipped", Value: fmt.Sprintf("%d", summary.CheckCoverage.Skipped)},
		{Name: "checks_errored", Value: fmt.Sprintf("%d", summary.CheckCoverage.Errored)},
	}

	for _, name := range suiteOrder {
		findings := suiteMap[name]
		suite := junitTestSuite{
			Name:     name,
			Tests:    len(findings),
			Failures: len(findings),
		}
		for i := range findings {
			failText := fmt.Sprintf("Severity: %s\nMessage: %s\nRemediation: %s",
				findings[i].Severity, findings[i].Message, findings[i].Remediation)
			if fw := formatFrameworks(findings[i].Frameworks); fw != "" {
				failText += "\nFrameworks: " + fw
			}
			tc := junitTestCase{
				Name:      formatResource(&findings[i]),
				ClassName: findings[i].Checker,
				Failure: &junitFailure{
					Message: findings[i].Message,
					Type:    findings[i].Severity.String(),
					Text:    failText,
				},
			}
			suite.TestCases = append(suite.TestCases, tc)
		}
		suites.Suites = append(suites.Suites, suite)
	}

	if _, err := fmt.Fprint(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(suites)
}

type junitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Properties []junitProperty  `xml:"properties>property,omitempty"`
	Suites     []junitTestSuite `xml:"testsuite"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

func init() {
	register(&JUnitReporter{})
}
