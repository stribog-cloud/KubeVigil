package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestHandleGetFindingsNoScan(t *testing.T) {
	kv := testKVEmpty()
	_, _, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{})
	if err == nil {
		t.Fatal("expected error when no scan has run")
	}
	if !strings.Contains(err.Error(), "no scan results") {
		t.Errorf("error should mention no scan results, got: %v", err)
	}
}

func TestHandleGetFindingsNoFilter(t *testing.T) {
	findings := sampleFindings()
	kv := testKV(findings)

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Total != len(findings) {
		t.Errorf("Total = %d, want %d", output.Total, len(findings))
	}
	if output.Limit != defaultFindingsLimit {
		t.Errorf("Limit = %d, want %d", output.Limit, defaultFindingsLimit)
	}
	if output.Offset != 0 {
		t.Errorf("Offset = %d, want 0", output.Offset)
	}
}

func TestHandleGetFindingsSeverityFilter(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Severity: "critical",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range output.Findings {
		if f.Severity != "Critical" {
			t.Errorf("finding %q has severity %s, want Critical", f.Checker, f.Severity)
		}
	}
	if output.Total != 3 {
		t.Errorf("Total = %d, want 3 critical findings", output.Total)
	}
}

func TestHandleGetFindingsCategoryFilter(t *testing.T) {
	// This test uses the real checker registry — checkers must be registered.
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Category: "workload",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All findings with workload checkers should be returned.
	// The exact count depends on registered checkers. At minimum, no non-workload
	// checkers should be in the result.
	for _, f := range output.Findings {
		c, ok := checker.Get(f.Checker)
		if !ok {
			continue // checker not registered — can happen in tests with synthetic IDs
		}
		hasWorkload := false
		for _, cat := range c.Categories() {
			if strings.EqualFold(cat.String(), "workload") {
				hasWorkload = true
				break
			}
		}
		if !hasWorkload {
			t.Errorf("finding %q is not in Workload category", f.Checker)
		}
	}
}

func TestHandleGetFindingsNamespaceFilter(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Namespace: "payments",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range output.Findings {
		if f.Namespace != "payments" {
			t.Errorf("finding %q in namespace %q, want payments", f.Checker, f.Namespace)
		}
	}
	if output.Total == 0 {
		t.Error("expected at least one finding in payments")
	}
}

func TestHandleGetFindingsCheckerFilter(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Checker: "privileged",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range output.Findings {
		if f.Checker != "privileged" {
			t.Errorf("finding has checker %q, want privileged", f.Checker)
		}
	}
	if output.Total == 0 {
		t.Error("expected at least one privileged finding")
	}
}

func TestHandleGetFindingsFrameworkFilter(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Framework: "cis",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range output.Findings {
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

func TestHandleGetFindingsMultipleFilters(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Severity:  "critical",
		Namespace: "default",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range output.Findings {
		if f.Severity != "Critical" {
			t.Errorf("finding %q severity %s, want Critical", f.Checker, f.Severity)
		}
		if f.Namespace != "default" {
			t.Errorf("finding %q namespace %q, want default", f.Checker, f.Namespace)
		}
	}
}

func TestHandleGetFindingsPaginationFirstPage(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Limit:  3,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Findings) != 3 {
		t.Errorf("got %d findings, want 3", len(output.Findings))
	}
	if !output.HasMore {
		t.Error("HasMore should be true when more results exist")
	}
	if output.Offset != 0 {
		t.Errorf("Offset = %d, want 0", output.Offset)
	}
}

func TestHandleGetFindingsPaginationSecondPage(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Limit:  3,
		Offset: 3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Findings) != 3 {
		t.Errorf("got %d findings, want 3", len(output.Findings))
	}
	if output.Offset != 3 {
		t.Errorf("Offset = %d, want 3", output.Offset)
	}
}

func TestHandleGetFindingsPaginationLastPage(t *testing.T) {
	findings := sampleFindings()
	kv := testKV(findings)

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Limit:  100,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.HasMore {
		t.Error("HasMore should be false on last page")
	}
	if len(output.Findings) != len(findings) {
		t.Errorf("got %d findings, want %d", len(output.Findings), len(findings))
	}
}

func TestHandleGetFindingsPaginationBeyondEnd(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Limit:  10,
		Offset: 1000, // way past end
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Findings) != 0 {
		t.Errorf("got %d findings, want 0", len(output.Findings))
	}
	if output.HasMore {
		t.Error("HasMore should be false when offset is past end")
	}
}

func TestHandleGetFindingsLimitCap(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Limit: 999, // exceeds max
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Limit != maxFindingsLimit {
		t.Errorf("Limit = %d, want %d (capped)", output.Limit, maxFindingsLimit)
	}
}

func TestHandleGetFindingsEmptyResult(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Namespace: "nonexistent-namespace",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Findings) != 0 {
		t.Errorf("got %d findings, want 0", len(output.Findings))
	}
	if output.Total != 0 {
		t.Errorf("Total = %d, want 0", output.Total)
	}
}

func TestFilterFindingsNoFilters(t *testing.T) {
	findings := sampleFindings()
	filtered := filterFindings(findings, &GetFindingsInput{})
	if len(filtered) != len(findings) {
		t.Errorf("got %d findings, want %d (no filter should return all)", len(filtered), len(findings))
	}
}

func TestFilterFindingsInvalidSeverity(t *testing.T) {
	findings := sampleFindings()
	// Invalid severity filter should be skipped, returning all findings.
	filtered := filterFindings(findings, &GetFindingsInput{Severity: "bogus"})
	if len(filtered) != len(findings) {
		t.Errorf("got %d findings, want %d (invalid severity should skip)", len(filtered), len(findings))
	}
}

func TestHandleGetFindingsNegativeOffset(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Offset: -5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Offset != 0 {
		t.Errorf("Offset = %d, want 0 (negative should be clamped)", output.Offset)
	}
}

func TestHandleGetFindingsDefaultLimit(t *testing.T) {
	kv := testKV(sampleFindings())

	_, output, err := kv.handleGetFindings(context.Background(), nil, GetFindingsInput{
		Limit: 0, // should use default
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Limit != defaultFindingsLimit {
		t.Errorf("Limit = %d, want default %d", output.Limit, defaultFindingsLimit)
	}
}
