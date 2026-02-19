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
	assert.Contains(t, out, `"severity": "Critical"`)
	assert.NotContains(t, out, `"severity": 4`)
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
	assert.Contains(t, out, `"duration": "42ms"`)
}

func TestJSONReporter_SchemaVersion(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	assert.Equal(t, `"1"`, string(parsed["version"]))
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
	assert.Contains(t, buf.String(), `"scan_mode": "Manifest"`)
}

func TestJSONReporter_CancelledContext(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}
