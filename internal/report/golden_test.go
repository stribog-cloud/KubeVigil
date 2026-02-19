package report

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func goldenScanResult() *checker.ScanResult {
	return &checker.ScanResult{
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
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.1", Title: "Minimize the admission of privileged containers"},
					{Framework: "mitre", Version: "v14", ControlID: "T1611", Title: "Escape to Host"},
					{Framework: "nsa", Version: "1.2", ControlID: "3.1", Title: "Pod Security"},
				},
			},
			{
				Checker:     "run-as-root",
				Severity:    checker.SeverityHigh,
				Resource:    "api-server",
				Namespace:   "backend",
				Kind:        "Deployment",
				Container:   "api",
				Message:     "Container runs as root",
				Remediation: "Set runAsNonRoot: true",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.6", Title: "Minimize the admission of root containers"},
				},
			},
			{
				Checker:     "read-only-rootfs",
				Severity:    checker.SeverityMedium,
				Resource:    "worker",
				Namespace:   "default",
				Kind:        "StatefulSet",
				Container:   "worker",
				Message:     "Root filesystem is not read-only",
				Remediation: "Set readOnlyRootFilesystem: true",
				FieldPath:   ".spec.containers[0].securityContext.readOnlyRootFilesystem",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.4", Title: "Minimize the admission of containers with readOnlyRootFilesystem"},
					{Framework: "nsa", Version: "1.2", ControlID: "3.1", Title: "Pod Security"},
				},
			},
		},
		ClusterInfo: checker.ClusterInfo{
			ServerVersion:  "v1.28.0",
			NodeCount:      3,
			NamespaceCount: 8,
			ContextName:    "my-cluster",
		},
		ScanMeta: checker.ScanMeta{
			StartTime:     time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			Duration:      50 * time.Millisecond,
			ChecksRun:     25,
			ChecksSkipped: 2,
			ChecksErrored: 0,
			ScanMode:      checker.ScanModeManifest,
		},
	}
}

// goldenDir returns the path to the test/golden directory.
func goldenDir(t *testing.T) string {
	t.Helper()
	// Walk up from internal/report/ to project root, then into test/golden.
	dir, err := filepath.Abs(filepath.Join("..", "..", "test", "golden"))
	require.NoError(t, err)
	return dir
}

func TestGoldenTextReport(t *testing.T) {
	color.NoColor = true
	r := &TextReporter{}
	var buf bytes.Buffer
	result := goldenScanResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	goldenPath := filepath.Join(goldenDir(t), "text-report.txt")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0o644))
		t.Log("updated golden file:", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create")
	assert.Equal(t, string(expected), buf.String())
}

func TestGoldenJSONReport(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer
	result := goldenScanResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	goldenPath := filepath.Join(goldenDir(t), "json-report.json")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0o644))
		t.Log("updated golden file:", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create")
	assert.Equal(t, string(expected), buf.String())
}

func TestGoldenMarkdownReport(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := goldenScanResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	goldenPath := filepath.Join(goldenDir(t), "markdown-report.md")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0o644))
		t.Log("updated golden file:", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create")
	assert.Equal(t, string(expected), buf.String())
}

func TestGoldenSARIFReport(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := goldenScanResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	goldenPath := filepath.Join(goldenDir(t), "sarif-report.json")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0o644))
		t.Log("updated golden file:", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create")
	assert.Equal(t, string(expected), buf.String())
}

func TestGoldenCSVReport(t *testing.T) {
	r := &CSVReporter{}
	var buf bytes.Buffer
	result := goldenScanResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	goldenPath := filepath.Join(goldenDir(t), "csv-report.csv")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0o644))
		t.Log("updated golden file:", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create")
	assert.Equal(t, string(expected), buf.String())
}

func TestGoldenJUnitReport(t *testing.T) {
	r := &JUnitReporter{}
	var buf bytes.Buffer
	result := goldenScanResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	goldenPath := filepath.Join(goldenDir(t), "junit-report.xml")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0o644))
		t.Log("updated golden file:", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create")
	assert.Equal(t, string(expected), buf.String())
}

func TestGoldenYAMLReport(t *testing.T) {
	r := &YAMLReporter{}
	var buf bytes.Buffer
	result := goldenScanResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	goldenPath := filepath.Join(goldenDir(t), "yaml-report.yaml")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0o644))
		t.Log("updated golden file:", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create")
	assert.Equal(t, string(expected), buf.String())
}

func TestGoldenHTMLReport(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := goldenScanResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	goldenPath := filepath.Join(goldenDir(t), "html-report.html")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, buf.Bytes(), 0o644))
		t.Log("updated golden file:", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create")
	assert.Equal(t, string(expected), buf.String())
}
