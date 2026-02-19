package report

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestYAMLReporter_EmptyFindings(t *testing.T) {
	r := &YAMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, "version: \"1\"")
	assert.Contains(t, out, "findings: []")
}

func TestYAMLReporter_WithFindings(t *testing.T) {
	r := &YAMLReporter{}
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
		},
		ScanMeta: checker.ScanMeta{
			Duration: 42 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, "checker: privileged")
	assert.Contains(t, out, "resource: nginx")
	assert.Contains(t, out, "namespace: default")
}

func TestYAMLReporter_CancelledContext(t *testing.T) {
	r := &YAMLReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}

func TestYAMLReporter_CheckCoverage(t *testing.T) {
	r := &YAMLReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(buf.Bytes(), &parsed))

	sr, ok := parsed["scan_result"].(map[string]any)
	require.True(t, ok)

	summary, ok := sr["summary"].(map[string]any)
	require.True(t, ok)

	require.Contains(t, summary, "check_coverage")
	cov, ok := summary["check_coverage"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, cov, "total_run")
	assert.Contains(t, cov, "with_findings")
	assert.Contains(t, cov, "clean")
	assert.Contains(t, cov, "skipped")
	assert.Contains(t, cov, "errored")
}

func TestYAMLReporter_CheckAggregates(t *testing.T) {
	r := &YAMLReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(buf.Bytes(), &parsed))

	sr := parsed["scan_result"].(map[string]any)
	summary := sr["summary"].(map[string]any)

	require.Contains(t, summary, "check_aggregates")
	aggs, ok := summary["check_aggregates"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, aggs)

	first := aggs[0].(map[string]any)
	assert.Contains(t, first, "checker")
	assert.Contains(t, first, "severity")
	assert.Contains(t, first, "count")
	assert.Contains(t, first, "resources")
	assert.Contains(t, first, "namespaces")
	assert.Contains(t, first, "app_count")
	assert.Contains(t, first, "infra_count")
	assert.Contains(t, first, "cluster_count")
}

func TestYAMLReporter_PassedChecks(t *testing.T) {
	r := &YAMLReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(buf.Bytes(), &parsed))

	sr := parsed["scan_result"].(map[string]any)
	summary := sr["summary"].(map[string]any)

	require.Contains(t, summary, "passed_checks")
	passed, ok := summary["passed_checks"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, passed)

	var passedStrs []string
	for _, p := range passed {
		passedStrs = append(passedStrs, p.(string))
	}
	assert.Contains(t, passedStrs, "read-only-rootfs")
	assert.NotContains(t, passedStrs, "privileged")
}

func TestYAMLReporter_TopRisks(t *testing.T) {
	r := &YAMLReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(buf.Bytes(), &parsed))

	sr := parsed["scan_result"].(map[string]any)
	summary := sr["summary"].(map[string]any)

	require.Contains(t, summary, "top_risks")
	topRisks, ok := summary["top_risks"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, topRisks)

	first := topRisks[0].(map[string]any)
	assert.Contains(t, first, "checker")
	assert.Contains(t, first, "severity")
	assert.Contains(t, first, "resource")
}

func TestYAMLReporter_TierBreakdown(t *testing.T) {
	r := &YAMLReporter{}
	var buf bytes.Buffer
	result := richResult()
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(buf.Bytes(), &parsed))

	sr := parsed["scan_result"].(map[string]any)
	summary := sr["summary"].(map[string]any)

	require.Contains(t, summary, "tier_breakdown")
	tier, ok := summary["tier_breakdown"].(map[string]any)
	require.True(t, ok)

	assert.Contains(t, tier, "app")
	assert.Contains(t, tier, "infra")
	assert.Contains(t, tier, "cluster")

	app, ok := tier["app"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, app, "namespaces")
	assert.Contains(t, app, "critical")
	assert.Contains(t, app, "high")
	assert.Contains(t, app, "medium")
	assert.Contains(t, app, "low")
	assert.Contains(t, app, "info")
}

func TestYAMLReporter_StructuralParity(t *testing.T) {
	result := richResult()

	jr := &JSONReporter{}
	var jsonBuf bytes.Buffer
	require.NoError(t, jr.Generate(context.Background(), result, &jsonBuf))

	yr := &YAMLReporter{}
	var yamlBuf bytes.Buffer
	require.NoError(t, yr.Generate(context.Background(), result, &yamlBuf))

	var jsonParsed map[string]any
	require.NoError(t, json.Unmarshal(jsonBuf.Bytes(), &jsonParsed))

	var yamlParsed map[string]any
	require.NoError(t, yaml.Unmarshal(yamlBuf.Bytes(), &yamlParsed))

	jsonSR := jsonParsed["scan_result"].(map[string]any)
	jsonSummary := jsonSR["summary"].(map[string]any)

	yamlSR := yamlParsed["scan_result"].(map[string]any)
	yamlSummary := yamlSR["summary"].(map[string]any)

	jsonKeys := sortedKeys(jsonSummary)
	yamlKeys := sortedKeys(yamlSummary)

	assert.True(t, reflect.DeepEqual(jsonKeys, yamlKeys),
		"JSON summary keys %v must match YAML summary keys %v", jsonKeys, yamlKeys)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
