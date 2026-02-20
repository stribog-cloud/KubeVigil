package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestHandleGetSummaryNoScan(t *testing.T) {
	kv := testKVEmpty()
	_, _, err := kv.handleGetSummary(context.Background(), nil, GetSummaryInput{})
	if err == nil {
		t.Fatal("expected error when no scan has run")
	}
	if !strings.Contains(err.Error(), "no scan results") {
		t.Errorf("error should mention no scan results, got: %v", err)
	}
}

func TestHandleGetSummaryAfterScan(t *testing.T) {
	kv := testKV(sampleFindings())

	_, summary, err := kv.handleGetSummary(context.Background(), nil, GetSummaryInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.TotalFindings != len(sampleFindings()) {
		t.Errorf("TotalFindings = %d, want %d", summary.TotalFindings, len(sampleFindings()))
	}
	if summary.Cluster != "test-cluster" {
		t.Errorf("Cluster = %q, want test-cluster", summary.Cluster)
	}
}

func TestHandleGetSummarySeverityCounts(t *testing.T) {
	kv := testKV(sampleFindings())

	_, summary, err := kv.handleGetSummary(context.Background(), nil, GetSummaryInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify severity counts are accurate.
	total := 0
	for _, count := range summary.SeverityCounts {
		total += count
	}
	if total != summary.TotalFindings {
		t.Errorf("sum of severity counts (%d) != TotalFindings (%d)", total, summary.TotalFindings)
	}
}
