package report

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestMarkdownReporter_EmptyFindings(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, "# KubeVigil Scan Report")
	assert.Contains(t, out, "Findings (0 total)")
}

func TestMarkdownReporter_WithFindings(t *testing.T) {
	r := &MarkdownReporter{}
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
	assert.Contains(t, out, "Critical | privileged |")
	assert.Contains(t, out, "default/Deployment/nginx")
	assert.Contains(t, out, "Findings (1 total)")
	assert.Contains(t, out, "Critical | 1 |")
}

func TestMarkdownReporter_SortedBySeverity(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "low-check", Severity: checker.SeverityLow, Resource: "a", Kind: "Pod", Message: "low"},
			{Checker: "crit-check", Severity: checker.SeverityCritical, Resource: "b", Kind: "Pod", Message: "critical"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	critIdx := strings.Index(out, "crit-check")
	lowIdx := strings.Index(out, "low-check")
	assert.Greater(t, lowIdx, critIdx)
}

func TestMarkdownReporter_GroupedByNamespace(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged mode"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "runs as root"},
			{Checker: "read-only-rootfs", Severity: checker.SeverityMedium, Resource: "worker", Namespace: "default", Kind: "StatefulSet", Message: "not read-only"},
			{Checker: "rbac-wildcard", Severity: checker.SeverityCritical, Resource: "admin", Kind: "ClusterRole", Message: "wildcard"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Should have application namespace heading.
	assert.Contains(t, out, "## Application Namespaces")

	// Should have namespace sections.
	assert.Contains(t, out, "### backend")
	assert.Contains(t, out, "### default")

	// Cluster-scoped findings should be in a separate section.
	assert.Contains(t, out, "### Cluster-Scoped")

	// Namespace sections should appear before the cluster section.
	backendIdx := strings.Index(out, "### backend")
	defaultIdx := strings.Index(out, "### default")
	clusterIdx := strings.Index(out, "### Cluster-Scoped")
	assert.Greater(t, defaultIdx, backendIdx, "namespaces should be sorted alphabetically")
	assert.Greater(t, clusterIdx, defaultIdx, "cluster-scoped should come after namespaces")
}

func TestMarkdownReporter_Remediation(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
				Message:     "privileged mode",
				Remediation: "Set privileged to false:\n\n```yaml\nsecurityContext:\n  privileged: false\n```",
			},
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "redis",
				Namespace:   "default",
				Kind:        "Deployment",
				Message:     "privileged mode",
				Remediation: "Set privileged to false:\n\n```yaml\nsecurityContext:\n  privileged: false\n```",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Should have collapsible remediation grouped by check.
	assert.Contains(t, out, "<details>")
	assert.Contains(t, out, "Remediation: privileged (2 resources affected)")
	assert.Contains(t, out, "privileged: false")
	assert.Contains(t, out, "**Affected resources:**")
	assert.Contains(t, out, "default/Deployment/nginx")
	assert.Contains(t, out, "default/Deployment/redis")
}

func TestMarkdownReporter_Aggregation(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Container: "nginx", Message: "Container runs in privileged mode"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "redis", Namespace: "default", Kind: "Deployment", Container: "redis", Message: "Container runs in privileged mode"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "worker", Namespace: "default", Kind: "StatefulSet", Container: "worker", Message: "Container runs in privileged mode"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Aggregated: shows "3 resources" in bold.
	assert.Contains(t, out, "**3 resources**")

	// Expandable details block with resource list.
	assert.Contains(t, out, "privileged: 3 affected resources")
	assert.Contains(t, out, "`default/Deployment/nginx (nginx)`")
	assert.Contains(t, out, "`default/Deployment/redis (redis)`")
	assert.Contains(t, out, "`default/StatefulSet/worker (worker)`")
}

func TestMarkdownReporter_ChecksPassed(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged mode"},
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

	assert.Contains(t, out, "Checks Passed (3)")
	assert.Contains(t, out, "3 checks ran with zero findings")
	assert.Contains(t, out, "`automount-token`")
	assert.Contains(t, out, "`host-network`")
	assert.Contains(t, out, "`run-as-root`")
	// The failing check should NOT be in the passed list.
	assert.NotContains(t, out, "`privileged`")
}

func TestMarkdownReporter_AggregationSingleResource(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Container: "nginx", Message: "Container runs in privileged mode"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Single resource: shows resource name inline, no "N resources".
	assert.Contains(t, out, "default/Deployment/nginx")
	assert.NotContains(t, out, "**1 resources**")
	assert.NotContains(t, out, "affected resources")
}

func TestMarkdownReporter_FindingsByCheckCollapsible(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer

	// Create 12 findings with different checkers to trigger collapsible behavior.
	var findings []checker.Finding
	for i := 0; i < 12; i++ {
		findings = append(findings, checker.Finding{
			Checker:   fmt.Sprintf("check-%02d", i),
			Severity:  checker.SeverityMedium,
			Resource:  fmt.Sprintf("res-%d", i),
			Namespace: "default",
			Kind:      "Deployment",
			Message:   fmt.Sprintf("issue %d", i),
		})
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 12,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// With > 10 check aggregates, the table should be in a collapsible details block.
	assert.Contains(t, out, "<details>")
	assert.Contains(t, out, "Findings by Check (12)")
	assert.Contains(t, out, "</details>")
}

func TestMarkdownReporter_FindingsByCheckFlatWhenSmall(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "default", Kind: "Deployment", Message: "root"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 5,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// With <= 10 check aggregates, it should be a plain heading, not collapsible.
	assert.Contains(t, out, "### Findings by Check")
}

func TestMarkdownReporter_CategoryBreakdown(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "root"},
			{Checker: "rbac-wildcard", Severity: checker.SeverityCritical, Resource: "admin", Kind: "ClusterRole", Message: "wildcard"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Should have category breakdown table.
	assert.Contains(t, out, "Category Breakdown")
	assert.Contains(t, out, "Application")
	assert.Contains(t, out, "Cluster-Scoped")
}

func TestMarkdownReporter_NamespaceHeaderCounts(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "default", Kind: "Deployment", Message: "root"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Namespace header should include finding count.
	assert.Contains(t, out, "default (2 findings")
}

func TestMarkdownReporter_ComplianceSummary(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker: "privileged", Severity: checker.SeverityCritical,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Message: "priv",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.1", Title: "Minimize privileged"},
					{Framework: "nsa", Version: "1.2", ControlID: "3.1", Title: "Pod Security"},
				},
			},
			{
				Checker: "run-as-root", Severity: checker.SeverityHigh,
				Resource: "api", Namespace: "backend", Kind: "Deployment",
				Message: "root",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.6", Title: "Minimize root"},
					{Framework: "mitre", Version: "v14", ControlID: "T1611", Title: "Escape to Host"},
				},
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Should have compliance summary section.
	assert.Contains(t, out, "Compliance Summary")
	assert.Contains(t, out, "CIS")
	assert.Contains(t, out, "5.2.1")
	assert.Contains(t, out, "MITRE")
	assert.Contains(t, out, "T1611")
	assert.Contains(t, out, "NSA")
}

func TestMarkdownReporter_CancelledContext(t *testing.T) {
	r := &MarkdownReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}
