package mcp

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cloud"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cluster"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/crd"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/image"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/network"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/psa"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/rbac"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/scheduling"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/secrets"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/storage"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/supply_chain"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

// fixturesDir returns the absolute path to the test fixtures directory.
func fixturesDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "test", "fixtures")
}

// TestIntegrationScanManifestsThenSummary tests the full scan_manifests →
// get_summary chain with real engine, real checkers, and real fixture files.
func TestIntegrationScanManifestsThenSummary(t *testing.T) {
	kv := NewKubeVigilMCP(config.Default(), checker.DefaultRegistry())

	// Scan a fixture directory with known failing manifests.
	fixtureDir := filepath.Join(fixturesDir(), "privileged")
	_, scanSummary, err := kv.handleScanManifests(context.Background(), nil, ScanManifestsInput{
		Path: fixtureDir,
	})
	if err != nil {
		t.Fatalf("scan_manifests failed: %v", err)
	}
	if scanSummary.TotalFindings == 0 {
		t.Fatal("expected findings from privileged fixtures")
	}
	if scanSummary.ChecksRun == 0 {
		t.Fatal("expected checks to have run")
	}

	// Verify get_summary returns consistent counts.
	_, getSummary, err := kv.handleGetSummary(context.Background(), nil, GetSummaryInput{})
	if err != nil {
		t.Fatalf("get_summary failed: %v", err)
	}
	if getSummary.TotalFindings != scanSummary.TotalFindings {
		t.Errorf("get_summary TotalFindings (%d) != scan TotalFindings (%d)",
			getSummary.TotalFindings, scanSummary.TotalFindings)
	}
}

// TestIntegrationScanManifestsThenFindings tests the full scan_manifests →
// get_findings chain with severity filtering on real data.
func TestIntegrationScanManifestsThenFindings(t *testing.T) {
	kv := NewKubeVigilMCP(config.Default(), checker.DefaultRegistry())

	fixtureDir := filepath.Join(fixturesDir(), "privileged")
	_, _, err := kv.handleScanManifests(context.Background(), nil, ScanManifestsInput{
		Path: fixtureDir,
	})
	if err != nil {
		t.Fatalf("scan_manifests failed: %v", err)
	}

	// Get all findings.
	_, allOutput, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("get_findings failed: %v", err)
	}
	if allOutput.Total == 0 {
		t.Fatal("expected findings")
	}

	// Get only critical findings.
	_, critOutput, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Severity: "critical",
		Limit:    100,
	})
	if err != nil {
		t.Fatalf("get_findings with severity filter failed: %v", err)
	}
	for _, f := range critOutput.Findings {
		if f.Severity != "Critical" {
			t.Errorf("finding %q has severity %s, want Critical", f.Checker, f.Severity)
		}
	}
	if critOutput.Total > allOutput.Total {
		t.Errorf("critical findings (%d) > all findings (%d)", critOutput.Total, allOutput.Total)
	}
}

// TestIntegrationListChecksMatchesRegistry verifies that list_checks returns
// the same count as the real checker registry.
func TestIntegrationListChecksMatchesRegistry(t *testing.T) {
	kv := NewKubeVigilMCP(config.Default(), checker.DefaultRegistry())

	_, output, err := kv.handleListChecks(context.Background(), nil, ListChecksInput{})
	if err != nil {
		t.Fatalf("list_checks failed: %v", err)
	}

	registryCount := checker.DefaultRegistry().Len()
	if output.Total != registryCount {
		t.Errorf("list_checks Total (%d) != registry count (%d)", output.Total, registryCount)
	}
}

// TestIntegrationGetRemediationWithFindings tests get_remediation when a
// matching finding exists from a previous scan.
func TestIntegrationGetRemediationWithFindings(t *testing.T) {
	kv := NewKubeVigilMCP(config.Default(), checker.DefaultRegistry())

	fixtureDir := filepath.Join(fixturesDir(), "privileged")
	_, _, err := kv.handleScanManifests(context.Background(), nil, ScanManifestsInput{
		Path: fixtureDir,
	})
	if err != nil {
		t.Fatalf("scan_manifests failed: %v", err)
	}

	_, output, err := kv.handleGetRemediation(context.Background(), nil, GetRemediationInput{
		Checker: "privileged",
	})
	if err != nil {
		t.Fatalf("get_remediation failed: %v", err)
	}
	if output.Remediation == "" {
		t.Error("expected non-empty remediation text")
	}
	if output.Description == "" {
		t.Error("expected non-empty description")
	}
}

// TestIntegrationGetRemediationNoScan tests get_remediation without a scan —
// should still return generic remediation for a valid checker.
func TestIntegrationGetRemediationNoScan(t *testing.T) {
	kv := NewKubeVigilMCP(config.Default(), checker.DefaultRegistry())

	_, output, err := kv.handleGetRemediation(context.Background(), nil, GetRemediationInput{
		Checker: "privileged",
	})
	if err != nil {
		t.Fatalf("get_remediation failed: %v", err)
	}
	if output.Remediation == "" {
		t.Error("expected generic remediation text")
	}
}
