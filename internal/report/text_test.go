package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func init() {
	// Disable colors in tests for deterministic output.
	color.NoColor = true
}

func TestTextReporter_EmptyFindings(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Findings (0 total)")
	assert.Contains(t, out, "Total: 0 findings")
}

func TestTextReporter_SingleFinding(t *testing.T) {
	r := &TextReporter{}
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
		},
		ScanMeta: checker.ScanMeta{
			Duration: 42 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "[Critical] privileged")
	assert.Contains(t, out, "Resource:    default/Deployment/nginx")
	assert.Contains(t, out, "Container:   nginx")
	assert.Contains(t, out, "Message:     Container runs in privileged mode")
	assert.Contains(t, out, "Remediation: Set securityContext.privileged to false")
	assert.Contains(t, out, "Field:       .spec.containers[0].securityContext.privileged")
	assert.Contains(t, out, "Findings (1 total)")
	assert.Contains(t, out, "Total: 1 findings")
	assert.Contains(t, out, "Critical: 1")
}

func TestTextReporter_MultipleSeverities(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:  "resource-limits-ratio",
				Severity: checker.SeverityLow,
				Resource: "web",
				Kind:     "Deployment",
				Message:  "Limits-to-requests ratio too high",
			},
			{
				Checker:  "privileged",
				Severity: checker.SeverityCritical,
				Resource: "nginx",
				Kind:     "Deployment",
				Message:  "Container runs in privileged mode",
			},
			{
				Checker:  "read-only-rootfs",
				Severity: checker.SeverityMedium,
				Resource: "api",
				Kind:     "Pod",
				Message:  "Root filesystem is not read-only",
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
	// Critical should appear before Medium, which should appear before Low.
	critIdx := strings.Index(out, "[Critical]")
	medIdx := strings.Index(out, "[Medium]")
	lowIdx := strings.Index(out, "[Low]")
	assert.Greater(t, medIdx, critIdx, "Medium should appear after Critical")
	assert.Greater(t, lowIdx, medIdx, "Low should appear after Medium")
}

func TestTextReporter_ContainerShown(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:   "privileged",
				Severity:  checker.SeverityCritical,
				Resource:  "nginx",
				Kind:      "Deployment",
				Container: "sidecar",
				Message:   "test",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Container:   sidecar")
}

func TestTextReporter_NoContainerOmitted(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:  "host-pid",
				Severity: checker.SeverityCritical,
				Resource: "nginx",
				Kind:     "Pod",
				Message:  "hostPID enabled",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "Container:")
}

func TestTextReporter_LiveModeClusterInfo(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			ScanMode: checker.ScanModeLive,
			Duration: 100 * time.Millisecond,
		},
		ClusterInfo: checker.ClusterInfo{
			ServerVersion: "v1.28.0",
			ContextName:   "prod-cluster",
			NodeCount:     5,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Server Version:  v1.28.0")
	assert.Contains(t, out, "Context:         prod-cluster")
	assert.Contains(t, out, "Node Count:      5")
	assert.Contains(t, out, "Scan Mode:       Live")
}

func TestTextReporter_ManifestModeNoClusterInfo(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			ScanMode: checker.ScanModeManifest,
			Duration: 10 * time.Millisecond,
		},
	}
	err := r.Generate(context.Background(), result, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.NotContains(t, out, "Server Version:")
	assert.NotContains(t, out, "Context:")
	assert.NotContains(t, out, "Node Count:")
}

func TestTextReporter_CancelledContext(t *testing.T) {
	r := &TextReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}
