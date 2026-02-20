package mcp

import (
	"context"
	"strings"
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
)

func TestHandleListChecksAll(t *testing.T) {
	kv := testKVEmpty()

	_, output, err := kv.handleListChecks(context.Background(), nil, ListChecksInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The default registry should have many checks registered.
	if output.Total == 0 {
		t.Error("expected at least some checks")
	}
	if output.Total != len(output.Checks) {
		t.Errorf("Total (%d) != len(Checks) (%d)", output.Total, len(output.Checks))
	}

	// Verify structure of each check.
	for _, check := range output.Checks {
		if check.ID == "" {
			t.Error("check ID is empty")
		}
		if check.Description == "" {
			t.Errorf("check %q has empty description", check.ID)
		}
		if len(check.Modes) == 0 {
			t.Errorf("check %q has no modes", check.ID)
		}
	}
}

func TestHandleListChecksCategoryFilter(t *testing.T) {
	kv := testKVEmpty()

	_, output, err := kv.handleListChecks(context.Background(), nil, ListChecksInput{
		Category: "Workload",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Total == 0 {
		t.Error("expected at least some Workload checks")
	}
	for _, check := range output.Checks {
		if !strings.EqualFold(check.Category, "workload") {
			t.Errorf("check %q has category %q, want Workload", check.ID, check.Category)
		}
	}
}

func TestHandleListChecksModeFilter(t *testing.T) {
	kv := testKVEmpty()

	_, output, err := kv.handleListChecks(context.Background(), nil, ListChecksInput{
		Mode: "manifest",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Total == 0 {
		t.Error("expected at least some manifest-mode checks")
	}
	for _, check := range output.Checks {
		hasManifest := false
		for _, mode := range check.Modes {
			if mode == "Manifest" {
				hasManifest = true
				break
			}
		}
		if !hasManifest {
			t.Errorf("check %q does not support manifest mode, modes: %v", check.ID, check.Modes)
		}
	}
}

func TestHandleListChecksInvalidMode(t *testing.T) {
	kv := testKVEmpty()

	_, _, err := kv.handleListChecks(context.Background(), nil, ListChecksInput{
		Mode: "invalid",
	})
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestHandleGetRemediationValid(t *testing.T) {
	findings := []checker.Finding{
		testFindingWithFixHint("privileged", "Critical", "deploy-a", "default"),
	}
	kv := testKV(findings)

	_, output, err := kv.handleGetRemediation(context.Background(), nil, GetRemediationInput{
		Checker: "privileged",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Checker != "privileged" {
		t.Errorf("Checker = %q, want privileged", output.Checker)
	}
	if output.Remediation == "" {
		t.Error("Remediation should not be empty")
	}
	if output.Description == "" {
		t.Error("Description should not be empty")
	}
}

func TestHandleGetRemediationSpecificResource(t *testing.T) {
	findings := []checker.Finding{
		testFindingWithFixHint("privileged", "Critical", "deploy-a", "default"),
		testFindingWithFixHint("privileged", "Critical", "deploy-b", "payments"),
	}
	kv := testKV(findings)

	_, output, err := kv.handleGetRemediation(context.Background(), nil, GetRemediationInput{
		Checker:   "privileged",
		Resource:  "deploy-b",
		Namespace: "payments",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Resource != "deploy-b" {
		t.Errorf("Resource = %q, want deploy-b", output.Resource)
	}
	if output.Namespace != "payments" {
		t.Errorf("Namespace = %q, want payments", output.Namespace)
	}
	if output.FixHint == nil {
		t.Error("FixHint should not be nil for targeted finding")
	}
}

func TestHandleGetRemediationUnknownChecker(t *testing.T) {
	kv := testKVEmpty()

	_, _, err := kv.handleGetRemediation(context.Background(), nil, GetRemediationInput{
		Checker: "nonexistent-checker-xyz",
	})
	if err == nil {
		t.Error("expected error for unknown checker")
	}
}

func TestHandleGetRemediationEmptyChecker(t *testing.T) {
	kv := testKVEmpty()

	_, _, err := kv.handleGetRemediation(context.Background(), nil, GetRemediationInput{})
	if err == nil {
		t.Error("expected error for empty checker ID")
	}
}

func TestHandleGetRemediationNoScanGeneric(t *testing.T) {
	kv := testKVEmpty()

	_, output, err := kv.handleGetRemediation(context.Background(), nil, GetRemediationInput{
		Checker: "privileged",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return generic remediation even without a scan result.
	if output.Remediation == "" {
		t.Error("should return generic remediation when no scan exists")
	}
	if output.Checker != "privileged" {
		t.Errorf("Checker = %q, want privileged", output.Checker)
	}
}

func TestHandleGetRemediationFrameworks(t *testing.T) {
	kv := testKVEmpty()

	_, output, err := kv.handleGetRemediation(context.Background(), nil, GetRemediationInput{
		Checker: "privileged",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Privileged should have framework mappings.
	if len(output.Frameworks) == 0 {
		t.Error("expected framework references for privileged check")
	}
}

func TestFindMatchingFindingEmptyResource(t *testing.T) {
	result := testResult(sampleFindings())
	// With empty resource, should return nil.
	got := findMatchingFinding(result, GetRemediationInput{
		Checker: "privileged",
	})
	if got != nil {
		t.Error("expected nil when resource is empty")
	}
}

func TestFindMatchingFindingNamespaceMismatch(t *testing.T) {
	findings := []checker.Finding{
		testFinding("privileged", "Critical", "deploy-a", "default", "Workload"),
	}
	result := testResult(findings)

	// Matching resource but wrong namespace.
	got := findMatchingFinding(result, GetRemediationInput{
		Checker:   "privileged",
		Resource:  "deploy-a",
		Namespace: "wrong-namespace",
	})
	if got != nil {
		t.Error("expected nil when namespace doesn't match")
	}
}

func TestCheckerDefaultSeverity(t *testing.T) {
	tests := []struct {
		checkerID string
		wantSev   string
	}{
		{"privileged", "Critical"},
		{"host-pid", "Critical"},
		{"host-ipc", "Critical"},
		{"host-network", "Critical"},
		{"image-tag-latest", "Medium"},
		{"resource-limits-missing", "Medium"},
		{"run-as-root", "High"},
		{"capabilities-added", "High"},
		{"privilege-escalation", "High"},
		{"image-no-digest", "Low"},
		{"runtime-class", "Low"},
	}
	for _, tt := range tests {
		t.Run(tt.checkerID, func(t *testing.T) {
			c, ok := checker.Get(tt.checkerID)
			if !ok {
				t.Skipf("checker %q not registered", tt.checkerID)
			}
			got := checkerDefaultSeverity(c)
			if got != tt.wantSev {
				t.Errorf("checkerDefaultSeverity(%q) = %q, want %q", tt.checkerID, got, tt.wantSev)
			}
		})
	}
}

func TestCheckerDefaultSeverityAllRegistered(t *testing.T) {
	// Every registered checker must return a valid severity string.
	allCheckers := checker.DefaultRegistry().All()
	if len(allCheckers) == 0 {
		t.Skip("no checkers registered")
	}
	validSeverities := map[string]bool{
		"Info": true, "Low": true, "Medium": true, "High": true, "Critical": true,
	}
	for _, c := range allCheckers {
		sev := checkerDefaultSeverity(c)
		if !validSeverities[sev] {
			t.Errorf("checker %q returned invalid severity %q", c.Name(), sev)
		}
	}
}

func TestCheckerDefaultSeverityMapCoverage(t *testing.T) {
	// Verify the severity map covers ALL registered checkers (not relying
	// on the fallback). This will catch missing entries when new checkers
	// are added.
	allCheckers := checker.DefaultRegistry().All()
	if len(allCheckers) == 0 {
		t.Skip("no checkers registered")
	}
	for _, c := range allCheckers {
		if _, ok := defaultSeverities[c.Name()]; !ok {
			t.Errorf("checker %q is not in defaultSeverities map", c.Name())
		}
	}
}

func TestModeStrings(t *testing.T) {
	c, ok := checker.Get("privileged")
	if !ok {
		t.Skip("privileged checker not registered")
	}
	modes := modeStrings(c)
	if len(modes) == 0 {
		t.Error("expected at least one mode")
	}
	for _, m := range modes {
		if m != "Live" && m != "Manifest" {
			t.Errorf("unexpected mode %q", m)
		}
	}
}

func TestCheckerSupportsMode(t *testing.T) {
	c, ok := checker.Get("privileged")
	if !ok {
		t.Skip("privileged checker not registered")
	}
	// Privileged should support manifest mode.
	if !checkerSupportsMode(c, checker.ScanModeManifest) {
		t.Error("expected privileged to support manifest mode")
	}
}

func TestFindMatchingFindingCheckerMismatch(t *testing.T) {
	findings := []checker.Finding{
		testFinding("privileged", "Critical", "deploy-a", "default", "Workload"),
	}
	result := testResult(findings)
	got := findMatchingFinding(result, GetRemediationInput{
		Checker:  "run-as-root", // different checker
		Resource: "deploy-a",
	})
	if got != nil {
		t.Error("expected nil when checker doesn't match")
	}
}

func TestFindMatchingFindingResourceMismatch(t *testing.T) {
	findings := []checker.Finding{
		testFinding("privileged", "Critical", "deploy-a", "default", "Workload"),
	}
	result := testResult(findings)
	got := findMatchingFinding(result, GetRemediationInput{
		Checker:  "privileged",
		Resource: "deploy-b", // different resource
	})
	if got != nil {
		t.Error("expected nil when resource doesn't match")
	}
}

func TestFindMatchingFindingNamespaceOptional(t *testing.T) {
	findings := []checker.Finding{
		testFinding("privileged", "Critical", "deploy-a", "default", "Workload"),
	}
	result := testResult(findings)
	// When namespace is empty in input, any namespace matches.
	got := findMatchingFinding(result, GetRemediationInput{
		Checker:  "privileged",
		Resource: "deploy-a",
	})
	if got == nil {
		t.Error("expected finding when namespace is not specified")
	}
}

func TestCheckerHasCategory(t *testing.T) {
	c, ok := checker.Get("privileged")
	if !ok {
		t.Skip("privileged checker not registered")
	}
	if !checkerHasCategory(c, "Workload") {
		t.Error("expected privileged to have Workload category")
	}
	if checkerHasCategory(c, "NonexistentCategory") {
		t.Error("expected false for nonexistent category")
	}
}
