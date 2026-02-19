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

// skipMetadata returns all lines after the metadata comment block.
func skipMetadata(out string) []string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var data []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") {
			data = append(data, l)
		}
	}
	return data
}

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
	data := skipMetadata(buf.String())
	// Should have CSV header only (no data rows).
	assert.Len(t, data, 1)
	assert.Contains(t, data[0], "Severity")
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
	data := skipMetadata(buf.String())
	// Header + 2 findings.
	assert.Len(t, data, 3)
	assert.Contains(t, data[1], "Critical")
	assert.Contains(t, data[1], "privileged")
}

func TestCSVReporter_CancelledContext(t *testing.T) {
	r := &CSVReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}

func TestCSVReporter_MetadataHeader(t *testing.T) {
	r := &CSVReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "msg"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			StartTime: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			ChecksRun: 5,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	assert.True(t, strings.HasPrefix(out, "# KubeVigil Scan Report\n"))
	assert.Contains(t, out, "# Scan Mode: Manifest")
	assert.Contains(t, out, "# Date: 2024-01-15T10:30:00Z")
	assert.Contains(t, out, "# Posture Score:")
	assert.Contains(t, out, "# Total Findings: 1")

	// Count metadata lines.
	metaCount := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "#") {
			metaCount++
		}
	}
	assert.Equal(t, 6, metaCount)
}

func TestCSVReporter_AutoFixableColumn(t *testing.T) {
	r := &CSVReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:  "privileged",
				Severity: checker.SeverityCritical,
				Resource: "a",
				Kind:     "Pod",
				Message:  "msg",
				FixHint:  &checker.FixHint{Safety: checker.FixSafe, Description: "Set privileged to false"},
			},
			{
				Checker:  "rbac-wildcard",
				Severity: checker.SeverityHigh,
				Resource: "b",
				Kind:     "ClusterRole",
				Message:  "msg2",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	data := skipMetadata(buf.String())

	// Header should contain Auto_Fixable.
	assert.Contains(t, data[0], "Auto_Fixable")
	// First finding (privileged) has FixHint -> true.
	assert.Contains(t, data[1], "true")
	// Second finding (rbac-wildcard) has no FixHint -> false.
	assert.Contains(t, data[2], "false")
}

func TestCSVReporter_CurrentValueDesiredValue(t *testing.T) {
	r := &CSVReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:      "privileged",
				Severity:     checker.SeverityCritical,
				Resource:     "a",
				Kind:         "Pod",
				Message:      "msg",
				CurrentValue: true,
				DesiredValue: false,
			},
			{
				Checker:  "rbac-wildcard",
				Severity: checker.SeverityHigh,
				Resource: "b",
				Kind:     "ClusterRole",
				Message:  "msg2",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	data := skipMetadata(buf.String())

	// Header should contain CurrentValue and DesiredValue.
	assert.Contains(t, data[0], "CurrentValue")
	assert.Contains(t, data[0], "DesiredValue")
	// First finding should have "true" and "false" values.
	assert.Contains(t, data[1], "true")
	assert.Contains(t, data[1], "false")
}

func TestCSVReporter_ColumnOrder(t *testing.T) {
	r := &CSVReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	data := skipMetadata(buf.String())

	expected := "Severity,Checker,Namespace,Namespace_Type,Kind,Resource,Container,Message,Remediation,FieldPath,Frameworks,Auto_Fixable,CurrentValue,DesiredValue"
	assert.Equal(t, expected, strings.TrimSpace(data[0]))
}
