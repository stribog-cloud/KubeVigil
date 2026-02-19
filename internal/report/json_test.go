package report

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestJSONReporter_EmptyFindings(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	// Must be valid JSON with "findings": [] not null.
	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	var sr map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["scan_result"], &sr))
	assert.Equal(t, "[]", string(sr["findings"]))
}

func TestJSONReporter_SeverityAsString(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Kind:        "Deployment",
				Message:     "test",
				Remediation: "fix it",
			},
		},
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "\"severity\": \"Critical\"")
	assert.NotContains(t, out, "\"severity\": 4")
}

func TestJSONReporter_DurationFormat(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 42 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "\"duration\": \"42ms\"")
}

func TestJSONReporter_SchemaVersion(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	assert.Equal(t, "\"1\"", string(parsed["version"]))
}

func TestJSONReporter_ValidJSON(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := populatedResult()
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	// Must round-trip as valid JSON.
	var report jsonReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	assert.Equal(t, "1", report.Version)
	assert.Len(t, report.ScanResult.Findings, 2)
}

func TestJSONReporter_FindingsSorted(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "resource-limits-missing",
				Severity:    checker.SeverityMedium,
				Resource:    "web",
				Kind:        "Deployment",
				Message:     "Missing resource limits",
				Remediation: "Add limits",
			},
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Kind:        "Deployment",
				Message:     "Privileged container",
				Remediation: "Disable privileged",
			},
		},
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	var report jsonReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	require.Len(t, report.ScanResult.Findings, 2)
	assert.Equal(t, checker.SeverityCritical, report.ScanResult.Findings[0].Severity)
	assert.Equal(t, checker.SeverityMedium, report.ScanResult.Findings[1].Severity)
}

func TestJSONReporter_ScanModeAsString(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "\"scan_mode\": \"Manifest\"")
}

func TestJSONReporter_CancelledContext(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}

// richResult returns a scan result with multiple findings across namespaces
// and check names for testing the new summary fields.
func richResult() *checker.ScanResult {
	return &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
				Container:   "nginx",
				Message:     "Privileged container",
				Remediation: "Disable privileged",
			},
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "worker",
				Namespace:   "backend",
				Kind:        "Deployment",
				Container:   "worker",
				Message:     "Privileged container",
				Remediation: "Disable privileged",
			},
			{
				Checker:     "run-as-root",
				Severity:    checker.SeverityHigh,
				Resource:    "api",
				Namespace:   "default",
				Kind:        "Deployment",
				Container:   "api",
				Message:     "Runs as root",
				Remediation: "Set runAsNonRoot: true",
			},
		},
		ScanMeta: checker.ScanMeta{
			StartTime:     time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			Duration:      50 * time.Millisecond,
			ChecksRun:     10,
			ChecksSkipped: 0,
			ChecksErrored: 0,
			ScanMode:      checker.ScanModeManifest,
			CheckNames:    []string{"privileged", "run-as-root", "read-only-rootfs", "host-network", "host-pid"},
		},
	}
}

func TestJSONReporter_CheckAggregates(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	var sr map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["scan_result"], &sr))

	var summary map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sr["summary"], &summary))

	require.Contains(t, summary, "check_aggregates")

	var aggregates []jsonCheckAggregate
	require.NoError(t, json.Unmarshal(summary["check_aggregates"], &aggregates))
	require.NotEmpty(t, aggregates)

	var found bool
	for _, agg := range aggregates {
		if agg.Checker == "privileged" {
			found = true
			assert.Equal(t, "Critical", agg.Severity)
			assert.Equal(t, 2, agg.Count)
			assert.Equal(t, 2, agg.Resources)
			assert.Equal(t, 2, agg.Namespaces)
			break
		}
	}
	assert.True(t, found, "expected privileged in check_aggregates")
}

func TestJSONReporter_PassedChecks(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	var sr map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["scan_result"], &sr))

	var summary map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sr["summary"], &summary))

	require.Contains(t, summary, "passed_checks")

	var passed []string
	require.NoError(t, json.Unmarshal(summary["passed_checks"], &passed))
	assert.Contains(t, passed, "read-only-rootfs")
	assert.Contains(t, passed, "host-network")
	assert.Contains(t, passed, "host-pid")
	assert.NotContains(t, passed, "privileged")
	assert.NotContains(t, passed, "run-as-root")
}

func TestJSONReporter_TopRisks(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	var sr map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["scan_result"], &sr))

	var summary map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sr["summary"], &summary))

	require.Contains(t, summary, "top_risks")

	var topRisks []checker.Finding
	require.NoError(t, json.Unmarshal(summary["top_risks"], &topRisks))
	require.NotEmpty(t, topRisks)

	assert.Equal(t, checker.SeverityCritical, topRisks[0].Severity)
}

func TestJSONReporter_TierBreakdown(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	var sr map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["scan_result"], &sr))

	var summary map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sr["summary"], &summary))

	require.Contains(t, summary, "tier_breakdown")

	var tier jsonTierBreakdown
	require.NoError(t, json.Unmarshal(summary["tier_breakdown"], &tier))

	assert.True(t, tier.App.Critical > 0 || tier.App.High > 0,
		"expected app tier to have findings")
}

func TestJSONReporter_PerTierPostureScores(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	var sr map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["scan_result"], &sr))

	var summary map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sr["summary"], &summary))

	require.Contains(t, summary, "app_posture_score")
	require.Contains(t, summary, "infra_posture_score")

	var appScore int
	require.NoError(t, json.Unmarshal(summary["app_posture_score"], &appScore))
	assert.GreaterOrEqual(t, appScore, 0)
	assert.LessOrEqual(t, appScore, 100)

	var infraScore int
	require.NoError(t, json.Unmarshal(summary["infra_posture_score"], &infraScore))
	assert.GreaterOrEqual(t, infraScore, 0)
	assert.LessOrEqual(t, infraScore, 100)
}

func TestJSONReporter_NullSafety(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	var sr map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["scan_result"], &sr))

	var summary map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sr["summary"], &summary))

	assert.Equal(t, "[]", string(sr["findings"]), "findings must be [] not null")
	assert.Equal(t, "[]", string(summary["passed_checks"]), "passed_checks must be [] not null")
	assert.Equal(t, "[]", string(summary["top_risks"]), "top_risks must be [] not null")
	assert.Equal(t, "[]", string(summary["check_aggregates"]), "check_aggregates must be [] not null")
}
