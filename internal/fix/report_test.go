package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// testPlan builds a Plan with representative results for testing.
func testPlan() *Plan {
	return &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml": {Path: "/app/deploy.yaml"},
		},
		Diffs: map[string]string{},
		Summary: Summary{
			FilesScanned:  2,
			FilesModified: 1,
			FilesFailed:   0,
			TotalFindings: 3,
			Applied:       2,
			Skipped:       1,
			ByRisk: map[checker.FixSafety]int{
				checker.FixSafe:       1,
				checker.FixLikelySafe: 1,
			},
			SkipReasons: map[string]int{"risk_level": 1},
			Results: []Result{
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "privileged", Safety: checker.FixSafe, Description: "Disables privileged mode.", Applied: true},
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "read-only-rootfs", Safety: checker.FixLikelySafe, Description: "Sets readOnlyRootFilesystem to true.", Impact: "Apps writing to container filesystem need emptyDir volumes.", Applied: true},
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "resource-limits-missing", Safety: checker.FixPotentiallyBreaking, Description: "Adds default resource limits.", Impact: "Apps exceeding limits will be OOMKilled.", Applied: false, SkipReason: "risk_level"},
			},
			BackupDir: "/tmp/kubevigil-backup-123",
		},
	}
}

func TestGenerateFixReport_Basic(t *testing.T) {
	plan := testPlan()
	opts := ReportOptions{
		Timestamp:  time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
		RiskLevel:  RiskLevelSafe,
		Applied:    false,
		BackupDir:  "/tmp/kubevigil-backup-123",
		SourcePath: "/app",
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	// Header must be present.
	if !strings.Contains(content, "# KubeVigil Fix Report") {
		t.Error("report missing header '# KubeVigil Fix Report'")
	}

	// Summary section must exist.
	if !strings.Contains(content, "## Summary") {
		t.Error("report missing '## Summary' section")
	}

	// Changes section must exist.
	if !strings.Contains(content, "## Changes by File") {
		t.Error("report missing '## Changes by File' section")
	}

	// Timestamp must appear.
	if !strings.Contains(content, "2025-06-15") {
		t.Error("report missing timestamp")
	}

	// Files scanned count.
	if !strings.Contains(content, "2") {
		t.Error("report missing files scanned count")
	}
}

func TestGenerateFixReport_EmptyPlan(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{},
		Diffs: map[string]string{},
		Summary: Summary{
			ByRisk:      map[checker.FixSafety]int{},
			SkipReasons: map[string]int{},
		},
	}
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	// Should still be valid markdown with a header.
	if !strings.Contains(content, "# KubeVigil Fix Report") {
		t.Error("empty plan report missing header")
	}
	if !strings.Contains(content, "## Summary") {
		t.Error("empty plan report missing summary section")
	}
}

func TestGenerateFixReport_WhatCouldBreak(t *testing.T) {
	plan := testPlan()
	// Make the likely_safe fix appear as applied — it already is in testPlan().
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelModerate,
		Applied:   true,
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	// The "What Could Break" section should be present because we have
	// an applied likely_safe fix with an Impact string.
	if !strings.Contains(content, "## What Could Break") {
		t.Error("report missing 'What Could Break' section when likely_safe fix is applied")
	}

	// Impact text should appear.
	if !strings.Contains(content, "Apps writing to container filesystem need emptyDir volumes.") {
		t.Error("report missing impact text for likely_safe fix")
	}
}

func TestGenerateFixReport_NoWhatCouldBreak(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml": {Path: "/app/deploy.yaml"},
		},
		Diffs: map[string]string{},
		Summary: Summary{
			FilesScanned:  1,
			FilesModified: 1,
			TotalFindings: 1,
			Applied:       1,
			ByRisk: map[checker.FixSafety]int{
				checker.FixSafe: 1,
			},
			SkipReasons: map[string]int{},
			Results: []Result{
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "privileged", Safety: checker.FixSafe, Description: "Disables privileged mode.", Applied: true},
			},
		},
	}
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
		Applied:   true,
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	// "What Could Break" should NOT be present with only safe fixes.
	if strings.Contains(content, "## What Could Break") {
		t.Error("report should not contain 'What Could Break' section when only safe fixes are applied")
	}
}

func TestGenerateFixReport_SkippedSection(t *testing.T) {
	plan := testPlan()
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	if !strings.Contains(content, "## Skipped Findings") {
		t.Error("report missing 'Skipped Findings' section")
	}

	// Should show the human-readable label for risk_level.
	if !strings.Contains(content, "Risk level exceeded") {
		t.Error("report missing human-readable skip reason label 'Risk level exceeded'")
	}
}

func TestGenerateFixReport_RestoreWithBackup(t *testing.T) {
	plan := testPlan()
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
		Applied:   true,
		BackupDir: "/tmp/kubevigil-backup-123",
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	if !strings.Contains(content, "## Restore Instructions") {
		t.Error("report missing 'Restore Instructions' section")
	}
	if !strings.Contains(content, "/tmp/kubevigil-backup-123") {
		t.Error("report missing backup directory path in restore instructions")
	}
}

func TestGenerateFixReport_RestoreWithoutBackup(t *testing.T) {
	plan := testPlan()
	plan.Summary.BackupDir = ""
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
		Applied:   false,
		BackupDir: "",
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	if !strings.Contains(content, "## Restore Instructions") {
		t.Error("report missing 'Restore Instructions' section")
	}
	if !strings.Contains(content, "dry-run") {
		t.Error("report missing 'dry-run' note when no backup directory is set")
	}
}

func TestGenerateFixReport_FileGrouping(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml":  {Path: "/app/deploy.yaml"},
			"/app/service.yaml": {Path: "/app/service.yaml"},
		},
		Diffs: map[string]string{},
		Summary: Summary{
			FilesScanned:  3,
			FilesModified: 2,
			TotalFindings: 3,
			Applied:       3,
			ByRisk: map[checker.FixSafety]int{
				checker.FixSafe: 3,
			},
			SkipReasons: map[string]int{},
			Results: []Result{
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "privileged", Safety: checker.FixSafe, Description: "Disables privileged mode.", Applied: true},
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "read-only-rootfs", Safety: checker.FixSafe, Description: "Sets readOnlyRootFilesystem.", Applied: true},
				{FilePath: "/app/service.yaml", Resource: "web-svc", Namespace: "default", Kind: "Service", CheckID: "service-type", Safety: checker.FixSafe, Description: "Changes service type.", Applied: true},
			},
		},
	}
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	// Both file paths should appear as subheadings.
	if !strings.Contains(content, "/app/deploy.yaml") {
		t.Error("report missing file path /app/deploy.yaml")
	}
	if !strings.Contains(content, "/app/service.yaml") {
		t.Error("report missing file path /app/service.yaml")
	}

	// deploy.yaml should have 2 fix entries.
	if strings.Count(content, "privileged") < 1 {
		t.Error("report missing privileged check entry for deploy.yaml")
	}
	if strings.Count(content, "read-only-rootfs") < 1 {
		t.Error("report missing read-only-rootfs check entry for deploy.yaml")
	}
}

func TestGenerateFixReport_DeterministicOrder(t *testing.T) {
	plan := testPlan()
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
	}

	report1, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() first call error = %v", err)
	}

	report2, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() second call error = %v", err)
	}

	if string(report1) != string(report2) {
		t.Errorf("two calls with same input produced different output:\n--- first ---\n%s\n--- second ---\n%s", string(report1), string(report2))
	}
}

func TestGenerateFixReport_TimestampInjection(t *testing.T) {
	plan := testPlan()
	ts := time.Date(2024, 12, 25, 14, 30, 45, 0, time.UTC)
	opts := ReportOptions{
		Timestamp: ts,
		RiskLevel: RiskLevelSafe,
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	if !strings.Contains(content, "2024-12-25") {
		t.Error("report does not contain custom timestamp date")
	}
	if !strings.Contains(content, "14:30:45") {
		t.Error("report does not contain custom timestamp time")
	}
}

func TestWriteFixReport(t *testing.T) {
	plan := testPlan()
	opts := ReportOptions{
		Timestamp:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel:  RiskLevelSafe,
		SourcePath: "/app",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "FIX-REPORT.md")

	if err := WriteFixReport(plan, opts, path); err != nil {
		t.Fatalf("WriteFixReport() error = %v", err)
	}

	// Verify file exists and has content.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "# KubeVigil Fix Report") {
		t.Error("written report missing header")
	}

	// Verify file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat written report: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("written report permissions = %o, want 0644", info.Mode().Perm())
	}
}

func TestGenerateFixReport_RiskLevelDisplay(t *testing.T) {
	tests := []struct {
		name      string
		riskLevel RiskLevel
		wantText  string
	}{
		{"safe", RiskLevelSafe, "safe"},
		{"moderate", RiskLevelModerate, "moderate"},
		{"aggressive", RiskLevelAggressive, "aggressive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := testPlan()
			opts := ReportOptions{
				Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				RiskLevel: tt.riskLevel,
			}

			report, err := GenerateFixReport(plan, opts)
			if err != nil {
				t.Fatalf("GenerateFixReport() error = %v", err)
			}
			content := string(report)

			if !strings.Contains(content, tt.wantText) {
				t.Errorf("report does not contain risk level %q", tt.wantText)
			}
		})
	}
}

func TestGenerateFixReport_ManualRemediation(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{},
		Diffs: map[string]string{},
		Summary: Summary{
			FilesScanned:  1,
			TotalFindings: 1,
			Skipped:       1,
			ByRisk:        map[checker.FixSafety]int{},
			SkipReasons:   map[string]int{"manual_only": 1},
			Results: []Result{
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "rbac-wildcard", Safety: checker.FixManualOnly, Description: "Restructure RBAC bindings.", Applied: false, SkipReason: "manual_only"},
			},
		},
	}
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
	}

	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	content := string(report)

	if !strings.Contains(content, "## Manual Remediation") {
		t.Error("report missing 'Manual Remediation' section for manual_only findings")
	}

	if !strings.Contains(content, "rbac-wildcard") {
		t.Error("report missing manual_only check ID")
	}
}

func TestGenerateFixReport_TimestampDefaultsToNow(t *testing.T) {
	plan := testPlan()
	opts := ReportOptions{
		RiskLevel: RiskLevelSafe,
		// Timestamp is zero value — should default to time.Now().
	}

	before := time.Now()
	report, err := GenerateFixReport(plan, opts)
	if err != nil {
		t.Fatalf("GenerateFixReport() error = %v", err)
	}
	after := time.Now()
	content := string(report)

	// The report should contain a date string from today.
	dateStr := before.Format("2006-01-02")
	if !strings.Contains(content, dateStr) {
		// In the unlikely case the test runs at midnight, also check after.
		afterDateStr := after.Format("2006-01-02")
		if !strings.Contains(content, afterDateStr) {
			t.Errorf("report with zero timestamp does not contain today's date (%s or %s)", dateStr, afterDateStr)
		}
	}
}

func TestReportSkipReasonLabel_AllCases(t *testing.T) {
	tests := []struct {
		reason string
		want   string
	}{
		{"system_namespace", "System namespace"},
		{"risk_level", "Risk level exceeded"},
		{"check_not_selected", "Check filtered"},
		{"severity_not_selected", "Severity filtered"},
		{"namespace_not_selected", "Namespace filtered"},
		{"namespace_excluded", "Namespace excluded"},
		{"known_workload", "Known system workload"},
		{"manual_only", "Manual only"},
		{"some_unknown_reason", "some_unknown_reason"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			got := reportSkipReasonLabel(tt.reason)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWriteFixReport_InvalidPath(t *testing.T) {
	plan := testPlan()
	opts := ReportOptions{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
	}

	err := WriteFixReport(plan, opts, "/nonexistent/dir/subdir/FIX-REPORT.md")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "writing fix report")
}

func TestWriteFixReport_EmptyResult(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{},
		Diffs: map[string]string{},
		Summary: Summary{
			ByRisk:      map[checker.FixSafety]int{},
			SkipReasons: map[string]int{},
		},
	}
	opts := ReportOptions{
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel: RiskLevelSafe,
		Applied:   false,
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "FIX-REPORT.md")

	err := WriteFixReport(plan, opts, path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "# KubeVigil Fix Report")
	assert.Contains(t, content, "No changes were applied")
}

func TestWriteFixReport_MixedSafeAndModerate(t *testing.T) {
	plan := &Plan{
		Files: map[string]*FilePlan{
			"/app/deploy.yaml": {Path: "/app/deploy.yaml"},
		},
		Diffs: map[string]string{},
		Summary: Summary{
			FilesScanned:  1,
			FilesModified: 1,
			TotalFindings: 3,
			Applied:       2,
			Skipped:       1,
			ByRisk: map[checker.FixSafety]int{
				checker.FixSafe:       1,
				checker.FixLikelySafe: 1,
			},
			SkipReasons: map[string]int{"risk_level": 1},
			Results: []Result{
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "privileged", Safety: checker.FixSafe, Description: "Disables privileged mode.", Applied: true},
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "read-only-rootfs", Safety: checker.FixLikelySafe, Description: "Sets readOnlyRootFilesystem.", Impact: "May break apps writing to filesystem.", Applied: true},
				{FilePath: "/app/deploy.yaml", Resource: "web-app", Namespace: "default", Kind: "Deployment", CheckID: "resource-limits-missing", Safety: checker.FixPotentiallyBreaking, Description: "Adds resource limits.", Applied: false, SkipReason: "risk_level"},
			},
		},
	}
	opts := ReportOptions{
		Timestamp:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		RiskLevel:  RiskLevelModerate,
		Applied:    true,
		BackupDir:  "/tmp/backup-test",
		SourcePath: "/app",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "FIX-REPORT.md")

	err := WriteFixReport(plan, opts, path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	content := string(data)
	// Header present.
	assert.Contains(t, content, "# KubeVigil Fix Report")
	assert.Contains(t, content, "Applied")
	assert.Contains(t, content, "moderate")
	assert.Contains(t, content, "/app")

	// Changes section.
	assert.Contains(t, content, "privileged")
	assert.Contains(t, content, "read-only-rootfs")

	// What could break section (applied likely_safe with impact).
	assert.Contains(t, content, "## What Could Break")
	assert.Contains(t, content, "May break apps writing to filesystem.")

	// Skipped section.
	assert.Contains(t, content, "## Skipped Findings")
	assert.Contains(t, content, "Risk level exceeded")

	// Restore instructions.
	assert.Contains(t, content, "## Restore Instructions")
	assert.Contains(t, content, "/tmp/backup-test")

	// Risk breakdown.
	assert.Contains(t, content, "safe")
	assert.Contains(t, content, "likely_safe")
}
