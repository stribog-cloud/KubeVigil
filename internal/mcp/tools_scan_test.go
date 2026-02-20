package mcp

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

func TestBuildSummary(t *testing.T) {
	findings := sampleFindings()
	result := testResult(findings)
	summary := buildSummary(result)

	if summary.TotalFindings != len(findings) {
		t.Errorf("TotalFindings = %d, want %d", summary.TotalFindings, len(findings))
	}
	if summary.ChecksRun != 110 {
		t.Errorf("ChecksRun = %d, want 110", summary.ChecksRun)
	}
	if summary.Cluster != "test-cluster" {
		t.Errorf("Cluster = %q, want %q", summary.Cluster, "test-cluster")
	}
	if summary.ServerVersion != "v1.30.2" {
		t.Errorf("ServerVersion = %q, want %q", summary.ServerVersion, "v1.30.2")
	}
	if summary.NodeCount != 3 {
		t.Errorf("NodeCount = %d, want 3", summary.NodeCount)
	}

	// Severity counts.
	if got := summary.SeverityCounts["Critical"]; got != 3 {
		t.Errorf("Critical count = %d, want 3", got)
	}
	if got := summary.SeverityCounts["High"]; got != 5 {
		t.Errorf("High count = %d, want 5", got)
	}
	if got := summary.SeverityCounts["Medium"]; got != 2 {
		t.Errorf("Medium count = %d, want 2", got)
	}
	if got := summary.SeverityCounts["Low"]; got != 1 {
		t.Errorf("Low count = %d, want 1", got)
	}

	// Top issues should be sorted by count descending.
	if len(summary.TopIssues) == 0 {
		t.Fatal("TopIssues is empty")
	}
	if summary.TopIssues[0].Checker != "run-as-root" && summary.TopIssues[0].Checker != "privileged" {
		t.Errorf("TopIssues[0].Checker = %q, want run-as-root or privileged", summary.TopIssues[0].Checker)
	}
}

func TestBuildSummaryEmptyFindings(t *testing.T) {
	result := testResult(nil)
	summary := buildSummary(result)

	if summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", summary.TotalFindings)
	}
	if len(summary.TopIssues) != 0 {
		t.Errorf("TopIssues should be empty, got %d", len(summary.TopIssues))
	}
	if summary.ComplianceStats != nil {
		t.Error("ComplianceStats should be nil for empty findings")
	}
}

func TestBuildSummaryComplianceStats(t *testing.T) {
	findings := []checker.Finding{
		testFindingWithFrameworks("privileged", "Critical", "deploy-a", "default",
			[]checker.FrameworkRef{
				{Framework: "cis", ControlID: "5.2.1"},
				{Framework: "cis", ControlID: "5.2.2"},
				{Framework: "mitre", ControlID: "T1611"},
			}),
		testFindingWithFrameworks("run-as-root", "High", "deploy-a", "default",
			[]checker.FrameworkRef{
				{Framework: "cis", ControlID: "5.2.1"}, // duplicate — should be counted once
				{Framework: "nsa", ControlID: "NS-1"},
			}),
	}
	result := testResult(findings)
	summary := buildSummary(result)

	if summary.ComplianceStats == nil {
		t.Fatal("ComplianceStats should not be nil")
	}
	if got := summary.ComplianceStats["cis"]; got != 2 {
		t.Errorf("CIS controls = %d, want 2 (5.2.1 + 5.2.2)", got)
	}
	if got := summary.ComplianceStats["mitre"]; got != 1 {
		t.Errorf("MITRE techniques = %d, want 1", got)
	}
	if got := summary.ComplianceStats["nsa"]; got != 1 {
		t.Errorf("NSA sections = %d, want 1", got)
	}
}

func TestApplyFiltersSeverity(t *testing.T) {
	findings := sampleFindings()
	cfg := config.Default()
	cfg.Settings.IncludeSystemNamespaces = true // don't filter system ns

	filtered := applyFilters(findings, cfg, "", "high", "")
	for _, f := range filtered {
		if f.Severity < checker.SeverityHigh {
			t.Errorf("finding %q has severity %s, want >= High", f.Checker, f.Severity)
		}
	}
}

func TestApplyFiltersNamespace(t *testing.T) {
	findings := sampleFindings()
	cfg := config.Default()
	cfg.Settings.IncludeSystemNamespaces = true

	filtered := applyFilters(findings, cfg, "payments", "", "")
	for _, f := range filtered {
		if f.Namespace != "payments" {
			t.Errorf("finding %q in namespace %q, want payments", f.Checker, f.Namespace)
		}
	}
	if len(filtered) == 0 {
		t.Error("expected at least one finding in payments namespace")
	}
}

func TestApplyFiltersFramework(t *testing.T) {
	findings := sampleFindings()
	cfg := config.Default()
	cfg.Settings.IncludeSystemNamespaces = true

	filtered := applyFilters(findings, cfg, "", "", "cis")
	if len(filtered) == 0 {
		t.Error("expected at least one CIS finding")
	}
	for _, f := range filtered {
		hasCIS := false
		for _, ref := range f.Frameworks {
			if ref.Framework == "cis" {
				hasCIS = true
				break
			}
		}
		if !hasCIS {
			t.Errorf("finding %q has no CIS framework reference", f.Checker)
		}
	}
}

func TestApplyFiltersExcludeSystemNamespaces(t *testing.T) {
	findings := []checker.Finding{
		testFinding("privileged", "Critical", "coredns", "kube-system", "Workload"),
		testFinding("privileged", "Critical", "app", "default", "Workload"),
	}
	cfg := config.Default()
	// Default: IncludeSystemNamespaces is false.

	filtered := applyFilters(findings, cfg, "", "", "")
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding after system NS filter, got %d", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Namespace != "default" {
		t.Errorf("expected default namespace finding, got %q", filtered[0].Namespace)
	}
}

func TestApplyFiltersExcludeInfra(t *testing.T) {
	findings := []checker.Finding{
		testFinding("privileged", "Critical", "app", "default", "Workload"),
		testFinding("privileged", "Critical", "prometheus", "monitoring", "Workload"),
		testFinding("privileged", "Critical", "calico", "calico-system", "Workload"),
	}
	cfg := config.Default()
	cfg.Settings.IncludeSystemNamespaces = true
	cfg.Settings.ExcludeInfra = true

	filtered := applyFilters(findings, cfg, "", "", "")
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding after infra filter, got %d", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Namespace != "default" {
		t.Errorf("expected default namespace finding, got %q", filtered[0].Namespace)
	}
}

func TestApplyFiltersInvalidSeverity(t *testing.T) {
	findings := sampleFindings()
	cfg := config.Default()
	cfg.Settings.IncludeSystemNamespaces = true

	// Invalid severity string should be ignored (no filtering).
	filtered := applyFilters(findings, cfg, "", "bogus", "")
	if len(filtered) != len(findings) {
		t.Errorf("invalid severity should not filter: got %d, want %d", len(filtered), len(findings))
	}
}

func TestApplyFiltersCombined(t *testing.T) {
	findings := sampleFindings()
	cfg := config.Default()
	cfg.Settings.IncludeSystemNamespaces = true

	// Combine severity + namespace + framework.
	filtered := applyFilters(findings, cfg, "default", "critical", "cis")
	for _, f := range filtered {
		if f.Severity != checker.SeverityCritical {
			t.Errorf("severity %s, want Critical", f.Severity)
		}
		if f.Namespace != "default" {
			t.Errorf("namespace %q, want default", f.Namespace)
		}
	}
}

func TestConfigWithOverrides(t *testing.T) {
	kv := testKVEmpty()

	cfg := kv.configWithOverrides("high", "cis", true, "payments")
	if cfg.Settings.SeverityThreshold != "high" {
		t.Errorf("SeverityThreshold = %q, want high", cfg.Settings.SeverityThreshold)
	}
	if !cfg.Settings.ExcludeInfra {
		t.Error("ExcludeInfra should be true")
	}

	// Verify original config is not modified.
	if kv.config.Settings.SeverityThreshold != "info" {
		t.Error("original config was mutated")
	}
}

func TestHandleScanManifestsEmptyPath(t *testing.T) {
	kv := testKVEmpty()
	_, _, err := kv.handleScanManifests(context.Background(), nil, ScanManifestsInput{})
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestHandleScanManifestsInvalidPath(t *testing.T) {
	kv := testKVEmpty()
	_, _, err := kv.handleScanManifests(context.Background(), nil, ScanManifestsInput{
		Path: "/nonexistent/path/that/does/not/exist",
	})
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestValidateManifestPath(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, "manifest-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	tmpFile.Close()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid file path", tmpFile.Name(), false},
		{"valid directory path", tmpDir, false},
		{"relative path to existing dir", ".", false},
		{"too long", string(make([]byte, maxInputPathLen+1)), true},
		{"nonexistent path", "/nonexistent/path/that/does/not/exist", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateManifestPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateManifestPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateManifestPath_RejectsNonRegularNonDir(t *testing.T) {
	_, err := validateManifestPath("/dev/null")
	if err == nil {
		t.Error("expected error for device file /dev/null, got nil")
	}
}

func TestValidateManifestPath_ErrorContainsPath(t *testing.T) {
	const wantPath = "/nonexistent/foo/bar"
	_, err := validateManifestPath(wantPath)
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
	if !strings.Contains(err.Error(), wantPath) {
		t.Errorf("error should contain the path %q, got: %v", wantPath, err)
	}
}

func TestValidateKubeconfig(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty (default)", "", false},
		{"too long", string(make([]byte, maxInputPathLen+1)), true},
		{"nonexistent", "/nonexistent/kubeconfig", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKubeconfig(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKubeconfig(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}

	// Test with a directory (should fail - not a regular file).
	t.Run("directory rejected", func(t *testing.T) {
		err := validateKubeconfig(t.TempDir())
		if err == nil {
			t.Error("expected error for directory path")
		}
	})

	// Test with a valid regular file.
	t.Run("regular file accepted", func(t *testing.T) {
		f, _ := os.CreateTemp(t.TempDir(), "kubeconfig")
		f.Close()
		err := validateKubeconfig(f.Name())
		if err != nil {
			t.Errorf("unexpected error for regular file: %v", err)
		}
	})
}
