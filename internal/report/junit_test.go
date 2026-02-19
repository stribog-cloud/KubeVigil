package report

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestJUnitReporter_EmptyFindings(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, "<?xml version=")
	assert.Contains(t, out, "<testsuites")
	assert.Contains(t, out, `tests="0"`)
}

func TestJUnitReporter_WithFindings(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
				Container:   "nginx",
				Message:     "Container runs in privileged mode",
				Remediation: "Set securityContext.privileged to false",
			},
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "api",
				Kind:        "Pod",
				Message:     "Container runs in privileged mode",
				Remediation: "Set securityContext.privileged to false",
			},
		},
		ScanMeta: checker.ScanMeta{
			Duration: 42 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, `tests="2"`)
	assert.Contains(t, out, `<testsuite name="privileged"`)
	assert.Contains(t, out, `<testcase name="default/Deployment/nginx"`)
	assert.Contains(t, out, `<failure message="Container runs in privileged mode"`)
}

func TestJUnitReporter_MultipleCheckers(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "msg1"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "b", Kind: "Pod", Message: "msg2"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, `<testsuite name="privileged"`)
	assert.Contains(t, out, `<testsuite name="run-as-root"`)
}

func TestJUnitReporter_CancelledContext(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}

func TestJUnitReporter_PassedTestCases(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "msg"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 4,
			CheckNames: []string{
				"automount-token",
				"host-network",
				"privileged",
				"run-as-root",
			},
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Should have passed-checks suite.
	assert.Contains(t, out, `<testsuite name="passed-checks"`)
	assert.Contains(t, out, `<testcase name="automount-token"`)
	assert.Contains(t, out, `<testcase name="host-network"`)
	assert.Contains(t, out, `<testcase name="run-as-root"`)
	// Total tests = 1 finding + 3 passed.
	assert.Contains(t, out, `tests="4"`)
	assert.Contains(t, out, `failures="1"`)
}

func TestJUnitReporter_Timestamp(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			StartTime: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, `timestamp="2024-01-15T10:30:00Z"`)
}

func TestJUnitReporter_TimestampOmittedWhenZero(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	assert.NotContains(t, buf.String(), "timestamp=")
}

func TestJUnitReporter_TimeAttributes(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "msg"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode: checker.ScanModeManifest,
			Duration: 1500 * time.Millisecond,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Top-level time should be scan duration.
	assert.Contains(t, out, `time="1.50"`)
	// Test cases should have time="0".
	assert.Contains(t, out, `<testcase name="Pod/a" classname="privileged" time="0"`)
}

func TestJUnitReporter_SuiteName(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	assert.Contains(t, buf.String(), `name="KubeVigil Security Scan"`)
}

func TestJUnitReporter_CorrectPassFailRatio(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "msg1"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "b", Kind: "Pod", Message: "msg2"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 5,
			CheckNames: []string{
				"automount-token",
				"host-network",
				"privileged",
				"read-only-rootfs",
				"run-as-root",
			},
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// 2 findings + 3 passed = 5 total tests.
	assert.Contains(t, out, `tests="5"`)
	assert.Contains(t, out, `failures="2"`)
	// Passed suite should have 3 tests, 0 failures.
	assert.Contains(t, out, `<testsuite name="passed-checks" tests="3" failures="0"`)
}
