package report

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

func TestCSVReporter_SetConfig(t *testing.T) {
	r := &CSVReporter{}
	assert.Nil(t, r.Config, "Config should be nil before SetConfig")

	cfg := config.Default()
	r.SetConfig(cfg)

	require.NotNil(t, r.Config, "Config should be set after SetConfig")
	assert.Equal(t, cfg, r.Config)
}

func TestHTMLReporter_SetConfig(t *testing.T) {
	r := &HTMLReporter{}
	assert.Nil(t, r.Config, "Config should be nil before SetConfig")

	cfg := config.Default()
	r.SetConfig(cfg)

	require.NotNil(t, r.Config, "Config should be set after SetConfig")
	assert.Equal(t, cfg, r.Config)
}

func TestMarkdownReporter_SetConfig(t *testing.T) {
	r := &MarkdownReporter{}
	assert.Nil(t, r.Config, "Config should be nil before SetConfig")

	cfg := config.Default()
	r.SetConfig(cfg)

	require.NotNil(t, r.Config, "Config should be set after SetConfig")
	assert.Equal(t, cfg, r.Config)
}

func TestConfigurable_Interface(t *testing.T) {
	tests := []struct {
		name     string
		reporter Reporter
	}{
		{"CSVReporter", &CSVReporter{}},
		{"HTMLReporter", &HTMLReporter{}},
		{"MarkdownReporter", &MarkdownReporter{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := tt.reporter.(Configurable)
			assert.True(t, ok, "%s should implement Configurable interface", tt.name)
		})
	}
}

func TestWriteMarkdownFlatTable_WithFindings(t *testing.T) {
	findings := []checker.Finding{
		{
			Severity:  checker.SeverityHigh,
			Checker:   "privileged-container",
			Resource:  "nginx",
			Namespace: "default",
			Kind:      "Deployment",
			Message:   "Container runs in privileged mode",
		},
		{
			Severity:  checker.SeverityMedium,
			Checker:   "cpu-limits-missing",
			Resource:  "api-server",
			Namespace: "production",
			Kind:      "StatefulSet",
			Message:   "No CPU limits set",
		},
		{
			Severity:  checker.SeverityCritical,
			Checker:   "host-network",
			Resource:  "monitor",
			Namespace: "",
			Kind:      "DaemonSet",
			Message:   "Pod uses host network namespace",
		},
	}

	var buf bytes.Buffer
	writeMarkdownFlatTable(&buf, findings)
	output := buf.String()

	// Verify header row.
	assert.Contains(t, output, "| Severity | Check | Resource | Message | Frameworks |")
	// Verify separator row.
	assert.Contains(t, output, "|----------|-------|----------|---------|-----------|\n")

	// Verify each finding's checker name and message appear in the output.
	assert.Contains(t, output, "privileged-container")
	assert.Contains(t, output, "Container runs in privileged mode")

	assert.Contains(t, output, "cpu-limits-missing")
	assert.Contains(t, output, "No CPU limits set")

	assert.Contains(t, output, "host-network")
	assert.Contains(t, output, "Pod uses host network namespace")
}

func TestWriteMarkdownFlatTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	writeMarkdownFlatTable(&buf, nil)
	output := buf.String()

	// Should have header and separator but no data rows.
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	assert.Len(t, lines, 2, "empty findings should produce only header and separator")
	assert.Contains(t, output, "| Severity | Check | Resource | Message | Frameworks |")
	assert.Contains(t, output, "|----------|-------|----------|---------|-----------|\n")
}
