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

func TestSARIFReporter_EmptyFindings(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, `"version": "2.1.0"`)
	assert.Contains(t, out, `"$schema"`)
	assert.Contains(t, out, `"kubevigil"`)
}

func TestSARIFReporter_ValidJSON(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
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
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	// Parse as JSON to validate.
	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	assert.Equal(t, "2.1.0", parsed.Version)
	require.Len(t, parsed.Runs, 1)
	assert.Equal(t, "kubevigil", parsed.Runs[0].Tool.Driver.Name)
	require.Len(t, parsed.Runs[0].Results, 1)
	assert.Equal(t, "privileged", parsed.Runs[0].Results[0].RuleID)
	assert.Equal(t, "error", parsed.Runs[0].Results[0].Level)
}

func TestSARIFReporter_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity checker.Severity
		level    string
	}{
		{checker.SeverityCritical, "error"},
		{checker.SeverityHigh, "error"},
		{checker.SeverityMedium, "warning"},
		{checker.SeverityLow, "note"},
		{checker.SeverityInfo, "note"},
	}
	for _, tc := range tests {
		t.Run(tc.severity.String(), func(t *testing.T) {
			assert.Equal(t, tc.level, sarifLevel(tc.severity))
		})
	}
}

func TestSARIFReporter_UniqueRules(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "msg1"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "b", Kind: "Pod", Message: "msg2"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "c", Kind: "Pod", Message: "msg3"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	// 2 unique rules despite 3 findings.
	require.Len(t, parsed.Runs[0].Tool.Driver.Rules, 2)
	assert.Len(t, parsed.Runs[0].Results, 3)
}

func TestSarifLevel_AllSeverities(t *testing.T) {
	testCases := []struct {
		name     string
		severity checker.Severity
		want     string
	}{
		{name: "critical maps to error", severity: checker.SeverityCritical, want: "error"},
		{name: "high maps to error", severity: checker.SeverityHigh, want: "error"},
		{name: "medium maps to warning", severity: checker.SeverityMedium, want: "warning"},
		{name: "low maps to note", severity: checker.SeverityLow, want: "note"},
		{name: "info maps to note", severity: checker.SeverityInfo, want: "note"},
		{name: "unknown severity maps to none", severity: checker.Severity(99), want: "none"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := sarifLevel(tc.severity)
			assert.Equal(t, tc.want, got, "sarifLevel(%v)", tc.severity)
		})
	}
}

func TestSARIFReporter_CancelledContext(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}

func TestSARIFReporter_RuleDescriptions(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "Container runs in privileged mode", Remediation: "Set privileged to false"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "b", Kind: "Pod", Message: "Container runs in privileged mode", Remediation: "Set privileged to false"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "c", Kind: "Pod", Message: "Container runs as root", Remediation: "Set runAsNonRoot: true"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	rules := parsed.Runs[0].Tool.Driver.Rules
	require.Len(t, rules, 2)

	// shortDescription should be the finding message, not the checker ID.
	assert.Equal(t, "Container runs in privileged mode", rules[0].ShortDescription.Text)
	assert.Equal(t, "Container runs as root", rules[1].ShortDescription.Text)

	// fullDescription should be the remediation.
	require.NotNil(t, rules[0].FullDescription)
	assert.Equal(t, "Set privileged to false", rules[0].FullDescription.Text)
	require.NotNil(t, rules[1].FullDescription)
	assert.Equal(t, "Set runAsNonRoot: true", rules[1].FullDescription.Text)
}

func TestSARIFReporter_RuleHelpURI(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "msg", Remediation: "fix"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	rule := parsed.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, "https://github.com/stribog-cloud/kubevigil", rule.HelpURI)
}

func TestSARIFReporter_RuleHelp(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "msg", Remediation: "Set privileged to false"},
			{Checker: "no-remediation", Severity: checker.SeverityLow, Resource: "b", Kind: "Pod", Message: "info only"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	rules := parsed.Runs[0].Tool.Driver.Rules

	// Rule with remediation should have help.
	ruleWith := rules[0]
	require.NotNil(t, ruleWith.Help)
	assert.Equal(t, "Set privileged to false", ruleWith.Help.Text)

	// Rule without remediation should have nil help and fullDescription.
	ruleWithout := rules[1]
	assert.Nil(t, ruleWithout.Help)
	assert.Nil(t, ruleWithout.FullDescription)
}

func TestSARIFReporter_ResultRemediation(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Kind: "Pod", Message: "Container runs in privileged mode", Remediation: "Set privileged to false"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	res := parsed.Runs[0].Results[0]
	assert.Contains(t, res.Message.Markdown, "**Remediation:**")
	assert.Contains(t, res.Message.Markdown, "Set privileged to false")
}

func TestSARIFReporter_ResultWithoutRemediation(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "info-check", Severity: checker.SeverityInfo, Resource: "a", Kind: "Pod", Message: "informational"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))

	var parsed sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	res := parsed.Runs[0].Results[0]
	assert.Empty(t, res.Message.Markdown)
}
