package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestCSVReporter_EmptyFindings(t *testing.T) {
	r := &CSVReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	// Should have header only.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1)
	assert.Contains(t, lines[0], "Severity")
}

func TestCSVReporter_WithFindings(t *testing.T) {
	r := &CSVReporter{}
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
				FieldPath:   ".spec.containers[0].securityContext.privileged",
			},
			{
				Checker:     "run-as-root",
				Severity:    checker.SeverityHigh,
				Resource:    "api",
				Kind:        "Pod",
				Message:     "Container runs as root",
				Remediation: "Set runAsNonRoot: true",
			},
		},
		ScanMeta: checker.ScanMeta{
			Duration: 42 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// Header + 2 findings.
	assert.Len(t, lines, 3)
	assert.Contains(t, lines[1], "Critical")
	assert.Contains(t, lines[1], "privileged")
}

func TestCSVReporter_CancelledContext(t *testing.T) {
	r := &CSVReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}
