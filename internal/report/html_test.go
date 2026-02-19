package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

func TestHTMLReporter_EmptyFindings(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 10 * time.Millisecond,
			ScanMode: checker.ScanModeManifest,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	assert.Contains(t, out, "<!DOCTYPE html>")
	assert.Contains(t, out, "KubeVigil Scan Report")
	assert.Contains(t, out, "Vulnerability Explorer")
	assert.Contains(t, out, "No findings detected.")
}

func TestHTMLReporter_WithFindings(t *testing.T) {
	r := &HTMLReporter{}
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
	assert.Contains(t, out, "privileged")
	assert.Contains(t, out, "Deployment/nginx")
	assert.Contains(t, out, "Vulnerability Explorer")
	assert.Contains(t, out, "Critical")
	assert.Contains(t, out, "hero-card")
}

func TestHTMLReporter_SelfContained(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	// Should have inline CSS, no external links.
	assert.Contains(t, out, "<style>")
	assert.NotContains(t, out, `<link rel="stylesheet"`)
	assert.NotContains(t, out, `<script src=`)
}

func TestHTMLReporter_InteractiveFeatures(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged mode"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "runs as root"},
			{Checker: "rbac-wildcard", Severity: checker.SeverityCritical, Resource: "admin", Kind: "ClusterRole", Message: "wildcard"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Should have search input.
	assert.Contains(t, out, `id="search"`)

	// Should have severity filter buttons.
	assert.Contains(t, out, "filter-btn")

	// Should have collapsible namespace sections.
	assert.Contains(t, out, "<details")
	assert.Contains(t, out, "<summary")

	// Should group by namespace.
	assert.Contains(t, out, "backend")
	assert.Contains(t, out, "default")
	assert.Contains(t, out, "Cluster-Scoped")

	// Should have inline JavaScript (self-contained).
	assert.Contains(t, out, "<script>")
	assert.NotContains(t, out, `<script src=`)
}

func TestHTMLReporter_ChecksPassed(t *testing.T) {
	r := &HTMLReporter{}
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
	assert.Contains(t, out, "automount-token")
	assert.Contains(t, out, "host-network")
	assert.Contains(t, out, "run-as-root")
	assert.Contains(t, out, "passed-list")
}

func TestHTMLReporter_Aggregation(t *testing.T) {
	r := &HTMLReporter{}
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

	// Namespace sections use lazy loading — finding cards rendered by JS.
	assert.Contains(t, out, `data-ns="default"`)
	assert.Contains(t, out, "loadNsFindings")
	assert.Contains(t, out, `ontoggle="if(this.open)loadNsFindings(this)"`)
	// AGGREGATE variable should be true (default).
	assert.Contains(t, out, "var AGGREGATE=true;")
	// Findings are in columnar JSON for JS to consume.
	assert.Contains(t, out, `id="findings-json"`)
	assert.Contains(t, out, `id="checker-meta"`)
}

func TestHTMLReporter_AggregationSingleResource(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Container: "nginx", Message: "Container runs in privileged mode"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// With lazy rendering, finding cards are rendered by JS, not in server HTML.
	// The namespace section has a lazy-load stub with empty finding-cards div.
	assert.Contains(t, out, `data-ns="default"`)
	assert.Contains(t, out, `<div class="finding-cards"></div>`)
	// Finding data is still in the JSON blob for JS rendering.
	assert.Contains(t, out, "privileged")
}

func TestHTMLReporter_NoAggregation(t *testing.T) {
	r := &HTMLReporter{Config: &config.Config{
		Version: "1",
		Settings: config.Settings{
			SeverityThreshold: "info",
			FailOn:            "high",
			Concurrency:       10,
			Timeout:           "5m",
			NoAggregate:       true,
		},
	}}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Container: "nginx", Message: "Container runs in privileged mode"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "redis", Namespace: "default", Kind: "Deployment", Container: "redis", Message: "Container runs in privileged mode"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// With NoAggregate, AGGREGATE should be false in the JS.
	assert.Contains(t, out, "var AGGREGATE=false;")
	// Lazy rendering: cards rendered by JS, not server-side.
	assert.Contains(t, out, `data-ns="default"`)
	assert.Contains(t, out, `<div class="finding-cards"></div>`)
}

func TestHTMLReporter_ClusterScopedSeparateTier(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "privileged"},
			{Checker: "rbac-wildcard", Severity: checker.SeverityCritical, Resource: "admin", Kind: "ClusterRole", Message: "wildcard"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Cluster-scoped should be its own tier, NOT inside Application.
	assert.Contains(t, out, "Cluster-Scoped Resources")
	assert.Contains(t, out, "Application Namespaces")
	// All three tiers should be details/summary blocks (consistent structure).
	assert.Contains(t, out, `class="tier-section"`)
}

func TestHTMLReporter_DurationFormatted(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			Duration: 5*time.Second + 866*time.Millisecond + 899250*time.Nanosecond,
			ScanMode: checker.ScanModeLive,
		},
		ClusterInfo: checker.ClusterInfo{
			ContextName: "acme-staging",
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()
	// Duration should be rounded, not raw nanoseconds.
	assert.Contains(t, out, "5.87s")
	assert.NotContains(t, out, "5.866899")
	// Context name should appear in header.
	assert.Contains(t, out, "acme-staging")
}

func TestHTMLReporter_TabbedInterface(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker: "privileged", Severity: checker.SeverityCritical,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Message: "privileged mode",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.1", Title: "Minimize privileged"},
				},
			},
			{
				Checker: "run-as-root", Severity: checker.SeverityHigh,
				Resource: "api", Namespace: "backend", Kind: "Deployment",
				Message: "runs as root",
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

	// Tab navigation should use pill tabs — All Findings is the default active tab.
	assert.Contains(t, out, `class="pill-tabs"`)
	assert.Contains(t, out, `data-tab="all-findings"`)
	assert.Contains(t, out, `data-tab="by-namespace"`)
	assert.Contains(t, out, `data-tab="by-check"`)
	assert.Contains(t, out, `data-tab="compliance"`)

	// Tab panels should exist.
	assert.Contains(t, out, `id="tab-all-findings"`)
	assert.Contains(t, out, `id="tab-by-namespace"`)
	assert.Contains(t, out, `id="tab-by-check"`)
	assert.Contains(t, out, `id="tab-compliance"`)

	// By Namespace tab should contain namespace sections.
	assert.Contains(t, out, "default")
	assert.Contains(t, out, "backend")

	// Compliance tab should group by framework.
	assert.Contains(t, out, "CIS")
	assert.Contains(t, out, "5.2.1")
	assert.Contains(t, out, "MITRE")

	// Tab switching JS should exist.
	assert.Contains(t, out, "switchTab")
}

func TestHTMLReporter_NamespaceBarChart(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "default", Kind: "Deployment", Message: "root"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "worker", Namespace: "backend", Kind: "Deployment", Message: "root"},
			{Checker: "read-only-rootfs", Severity: checker.SeverityMedium, Resource: "cache", Namespace: "infra", Kind: "StatefulSet", Message: "rootfs"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Hero grid dashboard should be present.
	assert.Contains(t, out, "hero-grid")
	assert.Contains(t, out, "hero-card")

	// Namespace names should appear in the By Namespace tab.
	assert.Contains(t, out, "default")
	assert.Contains(t, out, "backend")
}

func TestHTMLReporter_StickyNav(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Should have sticky nav bar.
	assert.Contains(t, out, "sticky-nav")
	// Dashboard and Findings quick-jump links should NOT be in the nav.
	assert.NotContains(t, out, `href="#dashboard"`)
	assert.NotContains(t, out, `href="#findings"`)
}

func TestHTMLReporter_PrintCSS(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Print CSS should hide interactive elements and show only By Check + Compliance tabs.
	assert.Contains(t, out, "@media print")
	assert.Contains(t, out, ",.pill-tabs,")
	assert.Contains(t, out, "#tab-by-check,#tab-compliance{display:block!important")
	assert.Contains(t, out, "break-inside:avoid")

	// Print-only section styles.
	assert.Contains(t, out, ".print-section-title{")
	assert.Contains(t, out, "page-break-before:always")
	assert.Contains(t, out, ".print-table{")
	assert.Contains(t, out, ".print-exec-text{")
	assert.Contains(t, out, ".print-rem-entry{")
}

func TestHTMLReporter_OverviewTab(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "root"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:   checker.ScanModeManifest,
			ChecksRun:  5,
			CheckNames: []string{"automount-token", "host-network", "privileged", "read-only-rootfs", "run-as-root"},
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// All Findings tab should be the default active tab.
	assert.Contains(t, out, `id="tab-all-findings" class="tab-panel active"`)

	// All Findings tab should contain paginated table.
	assert.Contains(t, out, "findings-table")
	assert.Contains(t, out, "findings-tbody")
	assert.Contains(t, out, "pagination")

	// Checks Passed should be in the By Check tab.
	assert.Contains(t, out, "Checks Passed (3)")

	// By Namespace tab should NOT be active.
	assert.Contains(t, out, `id="tab-by-namespace" class="tab-panel"`)
	assert.NotContains(t, out, `id="tab-by-namespace" class="tab-panel active"`)
}

func TestHTMLReporter_DashboardEqualHeight(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Dashboard should use hero-grid with 4 hero cards.
	assert.Contains(t, out, `class="hero-grid"`)
	assert.Contains(t, out, `class="hero-card hero-card-score"`)
	assert.Contains(t, out, `class="hero-card"`)
	assert.Contains(t, out, `class="hero-card hero-card-detail"`)
	// Hero grid should use CSS grid for equal columns.
	assert.Contains(t, out, "hero-grid{")
	assert.Contains(t, out, "grid-template-columns")
}

func TestHTMLReporter_TierScoreCards(t *testing.T) {
	r := &HTMLReporter{Config: &config.Config{
		Version: "1",
		Settings: config.Settings{
			SeverityThreshold: "info",
			FailOn:            "high",
			Concurrency:       10,
			Timeout:           "5m",
		},
	}}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "monitoring", Kind: "Deployment", Message: "root"},
			{Checker: "rbac-wildcard", Severity: checker.SeverityCritical, Resource: "admin", Kind: "ClusterRole", Message: "wildcard"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Tier breakdown should appear in the By Namespace tab with tier-section elements.
	assert.Contains(t, out, `class="tier-section"`)
	assert.Contains(t, out, "Application Namespaces")
	assert.Contains(t, out, "Cluster-Scoped Resources")

	// Old tier card and bar elements should NOT be present.
	assert.NotContains(t, out, "tier-bar-section")
	assert.NotContains(t, out, `class="tier-cards"`)
}

func TestHTMLReporter_AllTiersCollapsible(t *testing.T) {
	r := &HTMLReporter{Config: &config.Config{
		Version: "1",
		Settings: config.Settings{
			SeverityThreshold: "info",
			FailOn:            "high",
			Concurrency:       10,
			Timeout:           "5m",
		},
	}}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "monitoring", Kind: "Deployment", Message: "root"},
			{Checker: "rbac-wildcard", Severity: checker.SeverityCritical, Resource: "admin", Kind: "ClusterRole", Message: "wildcard"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Application tier should be a collapsible details element, open by default.
	assert.Contains(t, out, `Application Namespaces (1)`)
	// All three tiers should be tier-section details elements.
	// Count the tier-section occurrences — should be at least 3.
	tierCount := strings.Count(out, `class="tier-section"`)
	assert.GreaterOrEqual(t, tierCount, 3, "all three tiers should be collapsible tier-section elements")
}

func TestHTMLReporter_ScoreColorContextual(t *testing.T) {
	tests := []struct {
		name      string
		score     int
		wantColor string
	}{
		{"high score is green", 85, "#10b981"},
		{"mid-high score is lime", 65, "#65a30d"},
		{"mid score is amber", 50, "#f9a825"},
		{"low score is orange", 25, "#ea580c"},
		{"very low score is red", 10, "#dc2626"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreToColor(tt.score)
			assert.Equal(t, tt.wantColor, got)
		})
	}
}

func TestHTMLReporter_ByCheckTierColumns(t *testing.T) {
	r := &HTMLReporter{Config: &config.Config{
		Version: "1",
		Settings: config.Settings{
			SeverityThreshold: "info",
			FailOn:            "high",
			Concurrency:       10,
			Timeout:           "5m",
		},
	}}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "prometheus", Namespace: "monitoring", Kind: "Deployment", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest, ChecksRun: 2},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// By Check tab should show App/Infra/Cluster columns (now sortable).
	assert.Contains(t, out, ">App</th>")
	assert.Contains(t, out, ">Infra</th>")
	assert.Contains(t, out, ">Cluster</th>")
}

func TestHTMLReporter_RemediationDedup(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Remediation: "Set privileged to false"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "redis", Namespace: "default", Kind: "Deployment", Remediation: "Set privileged to false"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "api", Namespace: "backend", Kind: "Deployment", Remediation: "Set privileged to false"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Remediation body should appear once in the store, not inline.
	assert.Contains(t, out, `<div id="rem-store"`)
	assert.Contains(t, out, `<div id="rem-privileged">`)
	// Deduplicated: 1 in rem-store + 1 in print-rem + 1 in checker-meta JSON = 3 total.
	// (Findings JSON no longer contains remediation — it's in checker-meta only.)
	assert.Equal(t, 3, strings.Count(out, "Set privileged to false"),
		"remediation text: 1 in store + 1 in print-rem + 1 in checker-meta")

	// Checker-meta should contain the remediation for the checker.
	assert.Contains(t, out, `id="checker-meta"`)

	// Drawer JS and store should be present.
	assert.Contains(t, out, "rem-drawer-body")
	assert.Contains(t, out, "rem-store")
}

func TestHTMLReporter_SortToggle(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Sort buttons present.
	assert.Contains(t, out, "sort-group")
	assert.Contains(t, out, `data-sort="severity"`)
	assert.Contains(t, out, `data-sort="alpha"`)
	assert.Contains(t, out, `data-sort="count"`)
	assert.Contains(t, out, "sortNamespaces")

	// Namespace sections have sort data attributes.
	assert.Contains(t, out, "data-label=")
	assert.Contains(t, out, "data-count=")
	assert.Contains(t, out, "data-sev=")
}

func TestHTMLReporter_ExportButtons(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Print button present in nav.
	assert.Contains(t, out, "window.print()")
	assert.Contains(t, out, "Print")

	// CSV and JSON export buttons present.
	assert.Contains(t, out, "exportCSV()")
	assert.Contains(t, out, "exportJSON()")

	// Summary data div present with key metrics.
	assert.Contains(t, out, `id="summary-data"`)
	assert.Contains(t, out, "Posture Score:")
	assert.Contains(t, out, "Total Findings:")
}

func TestHTMLReporter_DarkMode(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Dark mode CSS — design token overrides present.
	assert.Contains(t, out, ".dark{")
	assert.Contains(t, out, "--surface-1")
	assert.Contains(t, out, "prefers-color-scheme:dark")

	// Toggle button present.
	assert.Contains(t, out, `id="theme-toggle"`)
	assert.Contains(t, out, "toggleDarkMode()")
}

func TestHTMLReporter_CancelledContext(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Generate(ctx, &checker.ScanResult{}, &buf)
	require.Error(t, err)
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A"},
		{80, "A"},
		{79, "B"},
		{60, "B"},
		{59, "C"},
		{40, "C"},
		{39, "D"},
		{20, "D"},
		{19, "F"},
		{0, "F"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("score_%d", tt.score), func(t *testing.T) {
			got := scoreToGrade(tt.score)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHTMLReporter_LetterGradeInGauge(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 10,
			CheckNames: []string{
				"check-1", "check-2", "check-3", "check-4", "check-5",
				"check-6", "check-7", "check-8", "check-9", "check-10",
			},
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Perfect score (0 findings, 10 checks) = 100 → grade A in hero card badge.
	assert.Contains(t, out, "Grade A")
	assert.Contains(t, out, "hero-number")
}

func TestHTMLReporter_KPICards(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest, ChecksRun: 5},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Hero cards should present KPI data.
	assert.Contains(t, out, "hero-grid")
	assert.Contains(t, out, "hero-card")
	assert.Contains(t, out, "hero-number")

	// Hero card labels should be present.
	assert.Contains(t, out, "Total Findings")
	assert.Contains(t, out, "Posture Score")
	assert.Contains(t, out, "Compliance Pass")

	// Old KPI/metrics grid should NOT be present in the HTML template.
	assert.NotContains(t, out, `class="kpi-grid`)
	assert.NotContains(t, out, `class="metrics"`)
}

func TestHTMLReporter_HeaderClusterInfo(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeLive},
		ClusterInfo: checker.ClusterInfo{
			ContextName:   "prod-cluster",
			ServerVersion: "v1.29.1",
			NodeCount:     5,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Header should show K8s version and node count.
	assert.Contains(t, out, "K8s v1.29.1")
	assert.Contains(t, out, "5 nodes")
}

func TestHTMLReporter_CopySummaryWithGrades(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 5,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Copy-summary should include the letter grade after the score.
	assert.Contains(t, out, "Posture Score:")
	// Score with grade in parentheses (e.g., "80/100 (A)").
	assert.Regexp(t, `Posture Score: \d+/100 \([A-F]\)`, out)
}

func TestHTMLReporter_PaginatedFindings(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "Container runs in privileged mode"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "Container runs as root user"},
			{Checker: "read-only-rootfs", Severity: checker.SeverityMedium, Resource: "cache", Namespace: "infra", Kind: "StatefulSet", Message: "Root filesystem is writable"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 10,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Vulnerability Explorer with paginated findings table should be present.
	assert.Contains(t, out, "Vulnerability Explorer")
	assert.Contains(t, out, "findings-table")
	assert.Contains(t, out, "pagination")

	// Findings should be embedded as JSON for client-side rendering.
	assert.Contains(t, out, "privileged")
	assert.Contains(t, out, "Container runs in privileged mode")
}

func TestHTMLReporter_EmptyPrintSections(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 5,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// No findings → no triage or workload sections.
	assert.NotContains(t, out, `class="print-triage"`)
	assert.NotContains(t, out, `class="print-workloads"`)
}

func TestHTMLReporter_CategoryBreakdown(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "default", Kind: "Deployment", Message: "root"},
			{Checker: "image-tag-latest", Severity: checker.SeverityMedium, Resource: "web", Namespace: "default", Kind: "Deployment", Message: "uses latest tag"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 5,
			CheckCategories: map[string]string{
				"privileged":       "Workload",
				"run-as-root":      "Workload",
				"image-tag-latest": "Image",
			},
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Check names should appear in the By Check tab aggregates table.
	assert.Contains(t, out, "privileged")
	assert.Contains(t, out, "run-as-root")
	assert.Contains(t, out, "image-tag-latest")
}

func TestHTMLReporter_CategoryBreakdownEmpty(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode: checker.ScanModeManifest,
			// No CheckCategories → no category breakdown.
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Without CheckCategories, no category breakdown should appear.
	assert.NotContains(t, out, "By Category")
}

func TestHTMLReporter_ComplianceSummary(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker: "privileged", Severity: checker.SeverityCritical,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Message: "priv",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", ControlID: "5.2.1", Title: "Minimize privileged"},
				},
			},
			{
				Checker: "run-as-root", Severity: checker.SeverityHigh,
				Resource: "api", Namespace: "default", Kind: "Deployment",
				Message: "root",
				Frameworks: []checker.FrameworkRef{
					{Framework: "mitre", ControlID: "T1611", Title: "Escape to Host"},
				},
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Compliance detail should appear in the hero card and compliance tab.
	assert.Contains(t, out, "compliance-row")
	assert.Contains(t, out, "compliance-name")
	assert.Contains(t, out, "CIS")
	assert.Contains(t, out, "MITRE")
	// Compliance tab should show pass/fail details.
	assert.Contains(t, out, "passing (")
}

func TestHTMLReporter_ComplianceSummaryEmpty(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// No framework refs → no compliance summary cards rendered.
	assert.NotContains(t, out, "controls with findings")
}

func TestHTMLReporter_ColumnSorting(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "default", Kind: "Deployment", Message: "root"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest, ChecksRun: 3},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Sortable table classes and data attributes should be present.
	assert.Contains(t, out, `class="data-table sortable"`)
	assert.Contains(t, out, "sortable-th")
	assert.Contains(t, out, `data-sort="severity"`)
	assert.Contains(t, out, `data-sort="num"`)
	assert.Contains(t, out, `data-sort="text"`)

	// Sort indicator CSS should be present.
	assert.Contains(t, out, "sort-asc")
	assert.Contains(t, out, "sort-desc")

	// JS sort function should be present.
	assert.Contains(t, out, "sevWeight")
}

func TestHTMLReporter_URLHashState(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Hash state JS should update location.hash on tab switch.
	assert.Contains(t, out, "replaceState")
	assert.Contains(t, out, "location.hash")
	assert.Contains(t, out, "hashchange")
}

func TestHTMLReporter_KeyboardShortcuts(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Help overlay should exist.
	assert.Contains(t, out, "help-overlay")
	assert.Contains(t, out, "help-dialog")
	assert.Contains(t, out, "Keyboard Shortcuts")

	// Help button in nav.
	assert.Contains(t, out, "toggleHelp()")

	// Keyboard event listener and shortcut keys.
	assert.Contains(t, out, "keydown")
	assert.Contains(t, out, "<kbd>")

	// Key descriptions.
	assert.Contains(t, out, "All Findings tab")
	assert.Contains(t, out, "Focus search")
	assert.Contains(t, out, "Toggle dark mode")
}

func TestHTMLReporter_CSSVariables(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Design token system should be present.
	assert.Contains(t, out, ":root{")
	assert.Contains(t, out, "--color-critical")
	assert.Contains(t, out, "--surface-0")
	assert.Contains(t, out, "--text-primary")
	assert.Contains(t, out, "--glass-bg")
	assert.Contains(t, out, "var(--surface-0)")
}

func TestHTMLReporter_GlassNav(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Glassmorphic navigation should have backdrop-filter and glass vars.
	assert.Contains(t, out, "backdrop-filter")
	assert.Contains(t, out, "var(--glass-bg)")
}

func TestHTMLReporter_AmbientBackground(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Ambient gradient blobs should be present.
	assert.Contains(t, out, "var(--ambient-1)")
	assert.Contains(t, out, "radial-gradient")
}

func TestHTMLReporter_SideDrawer(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv", Remediation: "Set privileged to false"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Side-drawer HTML and JS should be present.
	assert.Contains(t, out, `id="rem-drawer"`)
	assert.Contains(t, out, "rem-drawer-panel")
	assert.Contains(t, out, "rem-drawer-body")
	assert.Contains(t, out, "openDrawer")
	assert.Contains(t, out, "closeDrawer")
	assert.Contains(t, out, "rem-trigger")
}

func TestHTMLReporter_SeverityVarsInCSS(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Severity classes should use CSS variables.
	assert.Contains(t, out, ".Critical{background:var(--color-critical);")
}

func TestHTMLReporter_PrintSections(t *testing.T) {
	r := &HTMLReporter{Config: &config.Config{
		Version: "1",
		Settings: config.Settings{
			SeverityThreshold: "info",
			FailOn:            "high",
			Concurrency:       10,
			Timeout:           "5m",
		},
	}}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker: "privileged", Severity: checker.SeverityCritical,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Container: "nginx", Message: "Container runs in privileged mode",
				Remediation: "Set securityContext.privileged to false",
			},
			{
				Checker: "run-as-root", Severity: checker.SeverityHigh,
				Resource: "api", Namespace: "backend", Kind: "Deployment",
				Container: "app", Message: "Container runs as root user",
				Remediation: "Set runAsNonRoot: true",
			},
			{
				Checker: "read-only-rootfs", Severity: checker.SeverityMedium,
				Resource: "cache", Namespace: "infra", Kind: "StatefulSet",
				Container: "redis", Message: "Root filesystem is writable",
			},
			{
				Checker: "rbac-wildcard", Severity: checker.SeverityCritical,
				Resource: "admin-role", Kind: "ClusterRole",
				Message: "Wildcard verb access",
			},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeLive,
			ChecksRun: 10,
			CheckNames: []string{
				"check-1", "check-2", "check-3", "check-4", "check-5",
				"check-6", "privileged", "run-as-root", "read-only-rootfs", "rbac-wildcard",
			},
			CheckCategories: map[string]string{
				"privileged":       "Workload",
				"run-as-root":      "Workload",
				"read-only-rootfs": "Workload",
				"rbac-wildcard":    "RBAC",
			},
		},
		ClusterInfo: checker.ClusterInfo{
			ContextName:   "test-cluster",
			ServerVersion: "v1.29.2",
			NodeCount:     3,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Section 1: Scan Metadata — always present.
	assert.Contains(t, out, `class="print-meta"`)
	assert.Contains(t, out, "Scan Metadata")
	assert.Contains(t, out, "test-cluster")
	assert.Contains(t, out, "v1.29.2")

	// Section 2: Executive Summary with action items.
	assert.Contains(t, out, `class="print-exec"`)
	assert.Contains(t, out, "Executive Summary")
	assert.Contains(t, out, "print-exec-text")
	assert.Contains(t, out, "print-exec-actions")

	// Section 3: Namespace Triage.
	assert.Contains(t, out, `class="print-triage"`)
	assert.Contains(t, out, "Namespace Triage")
	assert.Contains(t, out, "default")

	// Section 4: Category Breakdown.
	assert.Contains(t, out, `class="print-cats"`)
	assert.Contains(t, out, "Findings by Category")

	// Section 5: Namespace Summary with Top Workloads column.
	assert.Contains(t, out, `class="print-ns"`)
	assert.Contains(t, out, "Findings by Namespace")
	assert.Contains(t, out, "Application Namespaces")
	assert.Contains(t, out, "Cluster-Scoped")
	assert.Contains(t, out, "Top Workloads")

	// Section 6: Workload Drilldown (Critical & High).
	assert.Contains(t, out, `class="print-workloads"`)
	assert.Contains(t, out, "Critical &amp; High Findings by Workload")
	assert.Contains(t, out, "Container runs in privileged mode")
	assert.Contains(t, out, "Container runs as root user")
	assert.Contains(t, out, "Wildcard verb access")

	// Section 7: Remediation Reference (sorted by severity).
	assert.Contains(t, out, `class="print-rem"`)
	assert.Contains(t, out, "Remediation Reference")
	assert.Contains(t, out, "Set securityContext.privileged to false")
	assert.Contains(t, out, "Set runAsNonRoot: true")

	// Screen-hide CSS.
	assert.Contains(t, out, ".print-meta,.print-exec,.print-triage,.print-cats,.print-ns,.print-compliance,.print-workloads,.print-rem{display:none}")

	// Print-show CSS.
	assert.Contains(t, out, ".print-meta,.print-exec,.print-triage,.print-cats,.print-ns,.print-compliance,.print-workloads,.print-rem{display:block!important}")
}

func TestHTMLReporter_PrintSectionsEmpty(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{
			ScanMode:  checker.ScanModeManifest,
			ChecksRun: 5,
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// With zero findings: Scan Metadata always present.
	assert.Contains(t, out, `class="print-meta"`)
	assert.Contains(t, out, "Scan Metadata")

	// Conditional sections should be absent with no findings.
	assert.NotContains(t, out, `class="print-triage"`)
	assert.NotContains(t, out, `class="print-workloads"`)
	assert.NotContains(t, out, `class="print-rem"`)
}

func TestBuildPrintTriage(t *testing.T) {
	app := []htmlSection{
		{
			Label: "default", Count: 3, Critical: 2, High: 1,
			Findings: []htmlFinding{
				{Severity: "Critical", Checker: "privileged", Resource: "Deployment/nginx"},
				{Severity: "Critical", Checker: "privileged", Resource: "Deployment/redis"},
				{Severity: "High", Checker: "run-as-root", Resource: "Deployment/nginx"},
			},
		},
		{
			Label: "backend", Count: 1, High: 1,
			Findings: []htmlFinding{
				{Severity: "High", Checker: "run-as-root", Resource: "Deployment/api"},
			},
		},
	}
	cluster := []htmlSection{
		{
			Label: "Cluster-Scoped", Count: 1, Critical: 1,
			Findings: []htmlFinding{
				{Severity: "Critical", Checker: "rbac-wildcard", Resource: "ClusterRole/admin"},
			},
		},
	}
	got := buildPrintTriage(app, nil, cluster)

	require.Len(t, got, 3)
	// default has highest severity weight (2 crit + 1 high).
	assert.Equal(t, 1, got[0].Rank)
	assert.Equal(t, "default", got[0].Namespace)
	assert.Equal(t, "App", got[0].Tier)
	assert.Equal(t, 2, got[0].Critical)
	assert.Equal(t, 2, got[0].Workloads, "should count unique resources")
	assert.Equal(t, "privileged", got[0].TopIssue)

	// Cluster-Scoped has 1 crit.
	assert.Equal(t, 2, got[1].Rank)
	assert.Equal(t, "Cluster-Scoped", got[1].Namespace)
	assert.Equal(t, "Cluster", got[1].Tier)

	// backend has only 1 high.
	assert.Equal(t, 3, got[2].Rank)
	assert.Equal(t, "backend", got[2].Namespace)
}

func TestBuildPrintNamespaceDetails(t *testing.T) {
	app := []htmlSection{
		{
			Label: "default", Count: 3,
			Findings: []htmlFinding{
				{Severity: "Critical", Checker: "privileged", Resource: "Deployment/nginx", Container: "nginx", FieldPath: "spec.containers[0].securityContext.privileged", Message: "privileged mode"},
				{Severity: "High", Checker: "run-as-root", Resource: "Deployment/nginx", Container: "nginx", Message: "runs as root"},
				{Severity: "Medium", Checker: "read-only-rootfs", Resource: "Deployment/nginx", Container: "nginx", Message: "writable rootfs"},
			},
		},
	}
	got, truncated := buildPrintNamespaceDetails(app, nil, nil)

	require.Len(t, got, 1)
	assert.Equal(t, 0, truncated)
	assert.Equal(t, "default", got[0].Namespace)
	assert.Equal(t, 2, got[0].Total, "only crit+high")
	assert.Equal(t, 1, got[0].Critical)
	assert.Equal(t, 1, got[0].High)
	require.Len(t, got[0].Workloads, 1)
	assert.Equal(t, "Deployment/nginx", got[0].Workloads[0].Resource)
	assert.Equal(t, 2, got[0].Workloads[0].Total)
	require.Len(t, got[0].Workloads[0].Findings, 2)
	assert.Equal(t, "nginx", got[0].Workloads[0].Findings[0].Container)
	assert.Equal(t, "spec.containers[0].securityContext.privileged", got[0].Workloads[0].Findings[0].FieldPath)
}

func TestBuildPrintNamespaceRows(t *testing.T) {
	sections := []htmlSection{
		{
			Label: "default", Count: 3, Critical: 1, High: 1, Medium: 1,
			Findings: []htmlFinding{
				{Severity: "Critical", Checker: "privileged", Resource: "Deployment/nginx"},
				{Severity: "High", Checker: "run-as-root", Resource: "Deployment/api"},
				{Severity: "Medium", Checker: "read-only-rootfs", Resource: "StatefulSet/cache"},
			},
		},
	}
	rows := buildPrintNamespaceRows(sections, 2)

	require.Len(t, rows, 1)
	assert.Equal(t, "default", rows[0].Label)
	assert.Equal(t, 3, rows[0].Total)
	assert.Equal(t, 1, rows[0].Critical)
	// Top 2 workloads should be listed, sorted by severity.
	assert.Contains(t, rows[0].TopWorkloads, "Deployment/nginx")
}

func TestBuildExecActions(t *testing.T) {
	topAggs := []htmlAggregate{
		{Severity: "Critical", Checker: "privileged", Resources: 3},
		{Severity: "High", Checker: "run-as-root", Resources: 2},
		{Severity: "Medium", Checker: "read-only-rootfs", Resources: 5},
	}
	app := []htmlSection{
		{
			Label: "default",
			Findings: []htmlFinding{
				{Checker: "privileged"},
				{Checker: "privileged"},
				{Checker: "run-as-root"},
			},
		},
		{
			Label: "backend",
			Findings: []htmlFinding{
				{Checker: "privileged"},
			},
		},
	}
	actions := buildExecActions(topAggs, app, nil, nil)

	// Should have 2 actions (only Critical and High, not Medium).
	require.Len(t, actions, 2)
	assert.Contains(t, actions[0], "privileged")
	assert.Contains(t, actions[0], "3 workloads")
	assert.Contains(t, actions[0], "default")
	assert.Contains(t, actions[1], "run-as-root")
}

func TestHTMLReporter_PrintRemediationSortedBySeverity(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "read-only-rootfs", Severity: checker.SeverityMedium, Resource: "cache", Namespace: "default", Kind: "StatefulSet", Remediation: "Set readOnlyRootFilesystem: true"},
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Remediation: "Set privileged to false"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "default", Kind: "Deployment", Remediation: "Set runAsNonRoot: true"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// In the print-rem section, privileged (Critical) should appear before run-as-root (High)
	// which should appear before read-only-rootfs (Medium).
	privIdx := strings.Index(out, `<div class="print-rem-entry"><h4 class="mono"><span class="sev Critical">Critical</span> privileged`)
	rootIdx := strings.Index(out, `<div class="print-rem-entry"><h4 class="mono"><span class="sev High">High</span> run-as-root`)
	roIdx := strings.Index(out, `<div class="print-rem-entry"><h4 class="mono"><span class="sev Medium">Medium</span> read-only-rootfs`)
	assert.Greater(t, privIdx, -1, "privileged should be in print-rem")
	assert.Greater(t, rootIdx, -1, "run-as-root should be in print-rem")
	assert.Greater(t, roIdx, -1, "read-only-rootfs should be in print-rem")
	assert.Less(t, privIdx, rootIdx, "Critical should appear before High")
	assert.Less(t, rootIdx, roIdx, "High should appear before Medium")
}

func TestHTMLReporter_PrintCompliancePosture(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker: "privileged", Severity: checker.SeverityCritical,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Message: "priv",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", ControlID: "5.2.1", Title: "Minimize privileged"},
				},
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	assert.Contains(t, out, `class="print-compliance"`)
	assert.Contains(t, out, "Compliance Posture")
	assert.Contains(t, out, "CIS")
	assert.Contains(t, out, "Pass Rate")
}

func TestHTMLReporter_PrintWorkloadGrouping(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker: "privileged", Severity: checker.SeverityCritical,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Container: "nginx", FieldPath: "spec.containers[0].securityContext.privileged",
				Message: "Container runs in privileged mode",
			},
			{
				Checker: "run-as-root", Severity: checker.SeverityHigh,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Container: "nginx", Message: "Container runs as root user",
			},
			{
				Checker: "read-only-rootfs", Severity: checker.SeverityMedium,
				Resource: "cache", Namespace: "default", Kind: "StatefulSet",
				Container: "redis", Message: "Root filesystem is writable",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Workload drilldown should group by namespace > workload.
	assert.Contains(t, out, `class="print-workloads"`)
	assert.Contains(t, out, "print-ns-group")
	assert.Contains(t, out, "print-wl-header")
	// Container and FieldPath should be visible in the workload drilldown.
	assert.Contains(t, out, "spec.containers[0].securityContext.privileged")

	// Extract just the print-workloads section to verify Medium is excluded.
	wlStart := strings.Index(out, `class="print-workloads"`)
	wlEnd := strings.Index(out[wlStart:], "</div>\n\n")
	wlSection := out[wlStart : wlStart+wlEnd]
	assert.Contains(t, wlSection, "Container runs in privileged mode")
	assert.Contains(t, wlSection, "Container runs as root user")
	assert.NotContains(t, wlSection, "Root filesystem is writable",
		"Medium findings should NOT appear in workload drilldown")
}

func TestHTMLReporter_DrawerHeaderStyles(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker: "privileged", Severity: checker.SeverityCritical,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Message:     "priv",
				Remediation: "## Why This Matters\n\nRunning privileged is risky.\n\n### How to Fix\n\nDisable it:\n\n```yaml\nprivileged: false\n```\n\n## Learn More\n\nSee CIS 5.2.1.",
			},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Drawer width should be 560px.
	assert.Contains(t, out, "width:min(560px,90vw)")

	// CSS rules for header classes should be present.
	assert.Contains(t, out, ".rem-h3{")
	assert.Contains(t, out, ".rem-h4{")

	// Print CSS for remediation headers.
	assert.Contains(t, out, ".print-rem-entry .rem-h3{")
	assert.Contains(t, out, ".print-rem-entry .rem-h4{")

	// Generated HTML should contain rendered headers.
	assert.Contains(t, out, `<h3 class="rem-h3">Why This Matters</h3>`)
	assert.Contains(t, out, `<h4 class="rem-h4">How to Fix</h4>`)
	assert.Contains(t, out, `<h3 class="rem-h3">Learn More</h3>`)
}

func TestFindingsColor(t *testing.T) {
	tests := []struct {
		name  string
		crit  int
		high  int
		med   int
		low   int
		info  int
		color string
	}{
		{"critical present", 5, 10, 20, 5, 1, "#dc2626"},
		{"high only", 0, 10, 20, 5, 1, "#ea580c"},
		{"medium only", 0, 0, 20, 5, 1, "#d97706"},
		{"low only", 0, 0, 0, 5, 1, "#0284c7"},
		{"info only", 0, 0, 0, 0, 3, "#6b7280"},
		{"no findings", 0, 0, 0, 0, 0, "#10b981"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findingsColor(tt.crit, tt.high, tt.med, tt.low, tt.info)
			assert.Equal(t, tt.color, got)
		})
	}
}

func TestHTMLReporter_DynamicHeroCardColors(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "host-pid", Severity: checker.SeverityHigh, Resource: "redis", Namespace: "default", Kind: "Deployment", Message: "pid"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest, ChecksRun: 10},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Card 1 (Posture Score): already dynamic — verify ScoreColor inline style present.
	assert.Contains(t, out, `hero-card hero-card-score" style="border-top-color:`)

	// Card 2 (Total Findings): number and border should have dynamic color.
	// With critical findings present, color should be critical red.
	assert.Contains(t, out, `hero-card" style="border-top-color:#dc2626"`)
	assert.Contains(t, out, `hero-number" style="color:#dc2626"`)

	// Card 3 (Compliance Pass): border should be dynamic (not hardcoded --color-success).
	assert.NotContains(t, out, `nth-child(3){border-top-color:var(--color-success)}`)

	// Card 4 (Compliance Detail): border should be dynamic.
	assert.Contains(t, out, `hero-card hero-card-detail" style="border-top-color:`)
}

func TestHTMLReporter_PrintSpacingValues(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Print-only section containers should have 24px top margin for breathing room.
	assert.Contains(t, out,
		".print-meta,.print-exec,.print-triage,.print-cats,.print-ns,.print-compliance{margin-top:24px}",
		"print section containers need 24px top margin")

	// Section titles should have 28px top margin (not 16px) to separate major headings.
	assert.Contains(t, out,
		".print-section-title{font-size:14px;font-weight:800;margin:28px 0 10px;",
		"print section title needs margin:28px 0 10px")

	// Remediation entries should have 20px bottom margin + 16px padding + visible separator.
	assert.Contains(t, out,
		".print-rem-entry{break-inside:avoid;page-break-inside:avoid;margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid #ddd}",
		"print remediation entries need margin-bottom:20px, padding-bottom:16px, and border separator")

	// Remediation entry headings should have 16px top margin (not 8px).
	assert.Contains(t, out,
		".print-rem-entry h4{font-size:12px;margin:16px 0 8px;color:#333}",
		"print remediation headings need margin:16px 0 8px")

	// Executive summary text should have 8px bottom margin.
	assert.Contains(t, out,
		".print-exec-text{border-left:3px solid #4f46e5;background:#f8fafc;padding:8px 12px;font-size:11px;line-height:1.6;margin:0 0 8px}",
		"print exec text needs margin:0 0 8px")

	// Namespace sub-headings should have 20px top margin (not 12px).
	assert.Contains(t, out,
		".print-ns h4{font-size:12px;font-weight:700;margin:20px 0 8px;color:#333}",
		"print namespace headings need margin:20px 0 8px")
}

func TestBuildFindingsJSON_Columnar(t *testing.T) {
	findings := []checker.Finding{
		{
			Checker:   "checker-a",
			Severity:  checker.SeverityCritical,
			Resource:  "nginx",
			Namespace: "default",
			Kind:      "Deployment",
			Message:   "priv mode",
			Frameworks: []checker.FrameworkRef{
				{Framework: "cis", Version: "1.8", ControlID: "5.2.1", Title: "Minimize privileged"},
			},
		},
		{
			Checker:  "checker-b",
			Severity: checker.SeverityLow,
			Resource: "redis",
			Kind:     "Deployment",
			Message:  "low finding",
		},
	}

	js := buildFindingsJSON(findings, nil)

	// Columnar format: {c:[...],s:[...],r:[...],...}
	var data map[string][]string
	require.NoError(t, json.Unmarshal([]byte(js), &data))

	// Should have 8 column arrays with 2 elements each.
	assert.Len(t, data["c"], 2, "checker column")
	assert.Len(t, data["s"], 2, "severity column")
	assert.Len(t, data["r"], 2, "resource column")
	assert.Len(t, data["n"], 2, "namespace column")
	assert.Len(t, data["k"], 2, "kind column")
	assert.Len(t, data["t"], 2, "container column")
	assert.Len(t, data["m"], 2, "message column")
	assert.Len(t, data["f"], 2, "field_path column")

	// Verify values.
	assert.Equal(t, "checker-a", data["c"][0])
	assert.Equal(t, "Critical", data["s"][0])
	assert.Equal(t, "nginx", data["r"][0])
	assert.Equal(t, "default", data["n"][0])
	assert.Equal(t, "Deployment", data["k"][0])
	assert.Equal(t, "priv mode", data["m"][0])

	assert.Equal(t, "checker-b", data["c"][1])
	assert.Equal(t, "Low", data["s"][1])

	// Per-checker fields (remediation, frameworks, category) should NOT be in columnar data.
	_, hasRem := data["remediation"]
	_, hasFw := data["frameworks"]
	assert.False(t, hasRem, "remediation should not be in columnar findings")
	assert.False(t, hasFw, "frameworks should not be in columnar findings")
}

func TestBuildCheckerMetaJSON_FrameworkGrouping(t *testing.T) {
	findings := []checker.Finding{
		{
			Checker:  "rbac-escalation-verbs",
			Severity: checker.SeverityCritical,
			Resource: "admin",
			Kind:     "ClusterRole",
			Message:  "escalation verbs",
			Frameworks: []checker.FrameworkRef{
				{Framework: "cis", Version: "1.8", ControlID: "5.1.1", Title: "Limit cluster-admin"},
				{Framework: "cis", Version: "1.8", ControlID: "5.1.8", Title: "Limit escalation"},
				{Framework: "mitre", Version: "v14", ControlID: "T1078", Title: "Valid Accounts"},
				{Framework: "mitre", Version: "v14", ControlID: "T1068", Title: "Exploitation"},
				{Framework: "nsa", Version: "1.2", ControlID: "3.1", Title: "RBAC policies"},
			},
		},
		{
			Checker:  "privileged",
			Severity: checker.SeverityCritical,
			Resource: "nginx",
			Kind:     "Deployment",
			Message:  "priv",
			Frameworks: []checker.FrameworkRef{
				{Framework: "cis", Version: "1.8", ControlID: "5.2.5", Title: "Minimize privileged"},
				{Framework: "mitre", Version: "v14", ControlID: "T1611", Title: "Escape to Host"},
				{Framework: "mitre", Version: "v14", ControlID: "T1610", Title: "Deploy Container"},
				{Framework: "nsa", Version: "1.2", ControlID: "1.3", Title: "Pod security"},
			},
		},
	}
	categories := map[string]string{
		"rbac-escalation-verbs": "RBAC",
		"privileged":            "Workload",
	}

	js := buildCheckerMetaJSON(findings, categories)

	var meta map[string]map[string]string
	require.NoError(t, json.Unmarshal([]byte(js), &meta))
	require.Len(t, meta, 2)

	// rbac-escalation-verbs: CIS has 2 controls, MITRE has 2, NSA has 1.
	rbac := meta["rbac-escalation-verbs"]
	assert.Equal(t, "CIS | MITRE | NSA", rbac["fw"],
		"each framework name should appear exactly once")
	assert.Equal(t, "5.1.1, 5.1.8 | T1078, T1068 | 3.1", rbac["ci"],
		"control IDs should be comma-grouped by framework")
	assert.Equal(t, "RBAC", rbac["ca"])

	// privileged: CIS has 1, MITRE has 2, NSA has 1.
	priv := meta["privileged"]
	assert.Equal(t, "CIS | MITRE | NSA", priv["fw"])
	assert.Equal(t, "5.2.5 | T1611, T1610 | 1.3", priv["ci"])
	assert.Equal(t, "Workload", priv["ca"])
}

func TestBuildCheckerMetaJSON_Dedup(t *testing.T) {
	findings := []checker.Finding{
		{
			Checker:     "privileged",
			Severity:    checker.SeverityCritical,
			Resource:    "nginx",
			Namespace:   "default",
			Kind:        "Deployment",
			Message:     "priv",
			Remediation: "Set privileged to false",
			Frameworks: []checker.FrameworkRef{
				{Framework: "cis", ControlID: "5.2.1"},
			},
		},
		{
			Checker:     "privileged",
			Severity:    checker.SeverityCritical,
			Resource:    "redis",
			Namespace:   "default",
			Kind:        "Deployment",
			Message:     "priv",
			Remediation: "Set privileged to false",
			Frameworks: []checker.FrameworkRef{
				{Framework: "cis", ControlID: "5.2.1"},
			},
		},
		{
			Checker:  "run-as-root",
			Severity: checker.SeverityHigh,
			Resource: "api",
			Kind:     "Deployment",
			Message:  "root",
		},
	}

	js := buildCheckerMetaJSON(findings, nil)

	var meta map[string]map[string]string
	require.NoError(t, json.Unmarshal([]byte(js), &meta))

	// Should have 2 unique checkers, not 3 (privileged is deduped).
	require.Len(t, meta, 2)
	assert.Contains(t, meta, "privileged")
	assert.Contains(t, meta, "run-as-root")

	// Privileged should have remediation and framework data.
	assert.Equal(t, "Set privileged to false", meta["privileged"]["r"])
	assert.Equal(t, "CIS", meta["privileged"]["fw"])
	assert.Equal(t, "5.2.1", meta["privileged"]["ci"])

	// run-as-root has no remediation or frameworks.
	_, hasRem := meta["run-as-root"]["r"]
	assert.False(t, hasRem)
}

func TestHTMLReporter_ExportCSVColumns(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:  "privileged",
				Severity: checker.SeverityCritical,
				Resource: "nginx", Namespace: "default", Kind: "Deployment",
				Message: "priv",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", Version: "1.8", ControlID: "5.2.1", Title: "Minimize privileged"},
					{Framework: "nsa", Version: "1.2", ControlID: "2.3", Title: "Pod security"},
				},
			},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode: checker.ScanModeManifest,
			CheckCategories: map[string]string{
				"privileged": "Workload Security",
			},
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// JS exportCSV should include all 12 columns via checker-meta enrichment.
	assert.Contains(t, out, "'frameworks'")
	assert.Contains(t, out, "'control_ids'")
	assert.Contains(t, out, "'category'")
	assert.Contains(t, out, "'remediation'")

	// Framework/control/category data is now in checker-meta JSON (not findings JSON).
	assert.Contains(t, out, `id="checker-meta"`)
	// Checker-meta should contain the framework and category data.
	assert.Contains(t, out, `CIS | NSA`)
	assert.Contains(t, out, `5.2.1 | 2.3`)
	assert.Contains(t, out, `Workload Security`)
}

func TestHTMLReporter_CompanyBranding(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Page title should include the company name.
	assert.Contains(t, out, "<title>KubeVigil Scan Report — Stribog IT Solutions</title>")

	// Nav brand subtitle should be "Cluster Security Intelligence" (NOT company name).
	assert.Contains(t, out, `<span class="brand-subtitle">Cluster Security Intelligence</span>`)
	// Company name should NOT appear in the nav brand area.
	navEnd := strings.Index(out, "</nav>")
	require.Greater(t, navEnd, 0)
	navSection := out[:navEnd]
	assert.NotContains(t, navSection, "Stribog IT Solutions Pvt. Ltd.",
		"company name should not appear in the nav — only in footer")

	// Footer tagline should credit the company.
	assert.Contains(t, out, "Stribog IT Solutions Pvt. Ltd.")

	// Copy-summary (hidden div) should include company in header line.
	assert.Contains(t, out, "KubeVigil Scan Report — Stribog IT Solutions")
}

func TestHTMLReporter_PrintWhiteBackground(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Print CSS should force white body background to avoid grey box on last page.
	assert.Contains(t, out, "body{background:#fff!important}")
}

func TestHTMLReporter_PrintForcesLightTheme(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Extract the @media print block content.
	printIdx := strings.Index(out, "@media print{")
	require.Greater(t, printIdx, 0, "should have @media print block")

	// The print block must override CSS variables to light-theme values
	// so that dark mode never leaks into PDF output.
	// We check for key light-mode variable values that differ from dark mode.
	printBlock := out[printIdx:]

	// Surface variables must be forced to light values (not dark #020617/#0f172a).
	assert.Contains(t, printBlock, "--surface-0:#f0f2f5",
		"print CSS must force light --surface-0")
	assert.Contains(t, printBlock, "--surface-1:#ffffff",
		"print CSS must force light --surface-1")
	assert.Contains(t, printBlock, "--text-primary:#0f172a",
		"print CSS must force light --text-primary")
	assert.Contains(t, printBlock, "--text-secondary:#475569",
		"print CSS must force light --text-secondary")
	assert.Contains(t, printBlock, "--border-default:#e2e8f0",
		"print CSS must force light --border-default")
	assert.Contains(t, printBlock, "--status-fail-bg:#fef2f2",
		"print CSS must force light --status-fail-bg")
	assert.Contains(t, printBlock, "--status-pass-bg:#f0fdf4",
		"print CSS must force light --status-pass-bg")
	assert.Contains(t, printBlock, "--glass-bg:rgba(255,255,255,0.72)",
		"print CSS must force light --glass-bg")
}

func TestHTMLReporter_CheckerMetaScript(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{
				Checker:     "privileged",
				Severity:    checker.SeverityCritical,
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
				Message:     "priv",
				Remediation: "Set privileged to false",
				Frameworks: []checker.FrameworkRef{
					{Framework: "cis", ControlID: "5.2.1"},
				},
			},
			{
				Checker:  "run-as-root",
				Severity: checker.SeverityHigh,
				Resource: "api",
				Namespace: "default",
				Kind:     "Deployment",
				Message:  "root",
			},
		},
		ScanMeta: checker.ScanMeta{
			ScanMode: checker.ScanModeManifest,
			CheckCategories: map[string]string{
				"privileged": "Workload",
			},
		},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// checker-meta script tag should exist with correct data.
	assert.Contains(t, out, `<script id="checker-meta" type="application/json">`)

	// Extract and parse the checker-meta JSON.
	metaStart := strings.Index(out, `<script id="checker-meta" type="application/json">`)
	require.Greater(t, metaStart, 0)
	jsonStart := metaStart + len(`<script id="checker-meta" type="application/json">`)
	jsonEnd := strings.Index(out[jsonStart:], "</script>")
	require.Greater(t, jsonEnd, 0)
	metaJSON := out[jsonStart : jsonStart+jsonEnd]

	var meta map[string]map[string]string
	require.NoError(t, json.Unmarshal([]byte(metaJSON), &meta))

	// privileged checker should have remediation, frameworks, and category.
	assert.Equal(t, "Set privileged to false", meta["privileged"]["r"])
	assert.Equal(t, "CIS", meta["privileged"]["fw"])
	assert.Equal(t, "5.2.1", meta["privileged"]["ci"])
	assert.Equal(t, "Workload", meta["privileged"]["ca"])

	// run-as-root has no remediation or frameworks (empty entries).
	_, hasRem := meta["run-as-root"]["r"]
	assert.False(t, hasRem, "run-as-root should have no remediation in checker-meta")
}

func TestHTMLReporter_LazyNamespaceSections(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "priv"},
			{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "backend", Kind: "Deployment", Message: "root"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Namespace sections should have data-ns attribute for JS lookup.
	assert.Contains(t, out, `data-ns="default"`)
	assert.Contains(t, out, `data-ns="backend"`)

	// Sections should have ontoggle handler for lazy loading.
	assert.Contains(t, out, `ontoggle="if(this.open)loadNsFindings(this)"`)

	// Finding cards div should be empty (lazy-loaded by JS).
	assert.Contains(t, out, `<div class="finding-cards"></div>`)

	// JS functions for lazy loading should exist.
	assert.Contains(t, out, "loadNsFindings")
	assert.Contains(t, out, "findingsByNs")
	assert.Contains(t, out, "getCheckerMeta")
	assert.Contains(t, out, "fwBadges")

	// Server-side finding card markup should NOT appear in ns-sections.
	// (finding cards are rendered client-side by loadNsFindings)
	byNsStart := strings.Index(out, `id="tab-by-namespace"`)
	byNsEnd := strings.Index(out[byNsStart:], `id="tab-by-check"`)
	byNsSection := out[byNsStart : byNsStart+byNsEnd]
	assert.NotContains(t, byNsSection, `class="finding-card"`,
		"finding cards should not be server-rendered in By Namespace tab")
}

func TestHTMLReporter_ColumnarFindingsJSON(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Container: "nginx", Message: "priv"},
		},
		ScanMeta: checker.ScanMeta{ScanMode: checker.ScanModeManifest},
	}
	require.NoError(t, r.Generate(context.Background(), result, &buf))
	out := buf.String()

	// Extract findings JSON.
	jsonStart := strings.Index(out, `<script id="findings-json" type="application/json">`)
	require.Greater(t, jsonStart, 0)
	start := jsonStart + len(`<script id="findings-json" type="application/json">`)
	end := strings.Index(out[start:], "</script>")
	require.Greater(t, end, 0)
	findingsJSON := out[start : start+end]

	// Should be columnar format with short keys.
	var data map[string][]string
	require.NoError(t, json.Unmarshal([]byte(findingsJSON), &data))
	assert.Equal(t, []string{"privileged"}, data["c"])
	assert.Equal(t, []string{"Critical"}, data["s"])
	assert.Equal(t, []string{"nginx"}, data["r"])
	assert.Equal(t, []string{"default"}, data["n"])
	assert.Equal(t, []string{"Deployment"}, data["k"])
	assert.Equal(t, []string{"nginx"}, data["t"])
	assert.Equal(t, []string{"priv"}, data["m"])
}
