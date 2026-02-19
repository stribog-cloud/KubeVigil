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
