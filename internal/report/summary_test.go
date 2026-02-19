package report

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestComputeSummary_PostureScore(t *testing.T) {
	// New formula: weighted check pass rate.
	// Per-check: clean=100, Low/Info=60, Medium=30, High=10, Critical=0.
	// Score = sum(check_scores) / checksRun.
	tests := []struct {
		name      string
		findings  []checker.Finding
		checksRun int
		wantScore int
	}{
		{
			name:      "no findings gives 100",
			findings:  nil,
			checksRun: 25,
			wantScore: 100,
		},
		{
			name: "one critical check",
			findings: []checker.Finding{
				{Checker: "a", Severity: checker.SeverityCritical, Resource: "r1", Kind: "Deployment"},
			},
			checksRun: 25,
			wantScore: 96, // (24*100 + 0) / 25 = 96
		},
		{
			name: "one high check",
			findings: []checker.Finding{
				{Checker: "a", Severity: checker.SeverityHigh, Resource: "r1", Kind: "Deployment"},
			},
			checksRun: 25,
			wantScore: 96, // (24*100 + 10) / 25 = 96 (truncated)
		},
		{
			name: "one medium check",
			findings: []checker.Finding{
				{Checker: "a", Severity: checker.SeverityMedium, Resource: "r1", Kind: "Deployment"},
			},
			checksRun: 25,
			wantScore: 97, // (24*100 + 30) / 25 = 97
		},
		{
			name: "one low check",
			findings: []checker.Finding{
				{Checker: "a", Severity: checker.SeverityLow, Resource: "r1", Kind: "Deployment"},
			},
			checksRun: 25,
			wantScore: 98, // (24*100 + 60) / 25 = 98
		},
		{
			name: "info counted as low impact",
			findings: []checker.Finding{
				{Checker: "a", Severity: checker.SeverityInfo, Resource: "r1", Kind: "Deployment"},
			},
			checksRun: 25,
			wantScore: 98, // (24*100 + 60) / 25 = 98
		},
		{
			name: "mixed severities",
			findings: []checker.Finding{
				{Checker: "a", Severity: checker.SeverityCritical, Resource: "r1", Kind: "Deployment"},
				{Checker: "b", Severity: checker.SeverityHigh, Resource: "r2", Kind: "Pod"},
				{Checker: "c", Severity: checker.SeverityMedium, Resource: "r3", Kind: "Service"},
			},
			checksRun: 25,
			wantScore: 89, // (22*100 + 0 + 10 + 30) / 25 = 89
		},
		{
			name:      "all checks critical gives 0",
			checksRun: 5,
			wantScore: 0,
			findings: func() []checker.Finding {
				var f []checker.Finding
				for i := range 5 {
					f = append(f, checker.Finding{
						Checker:  fmt.Sprintf("check-%d", i),
						Severity: checker.SeverityCritical,
						Resource: "r",
						Kind:     "Pod",
					})
				}
				return f
			}(),
		},
		{
			name:      "zero checks run gives 0",
			findings:  nil,
			checksRun: 0,
			wantScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &checker.ScanResult{
				Findings: tt.findings,
				ScanMeta: checker.ScanMeta{ChecksRun: tt.checksRun},
			}
			summary := ComputeSummary(result)
			assert.Equal(t, tt.wantScore, summary.PostureScore)
		})
	}
}

func TestComputeSummary_TopRisks(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "a", Severity: checker.SeverityLow, Resource: "r1", Kind: "Pod"},
		{Checker: "b", Severity: checker.SeverityCritical, Resource: "r2", Kind: "Pod"},
		{Checker: "c", Severity: checker.SeverityHigh, Resource: "r3", Kind: "Pod"},
		{Checker: "d", Severity: checker.SeverityMedium, Resource: "r4", Kind: "Pod"},
		{Checker: "e", Severity: checker.SeverityInfo, Resource: "r5", Kind: "Pod"},
		{Checker: "f", Severity: checker.SeverityHigh, Resource: "r6", Kind: "Pod"},
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{ChecksRun: 10},
	}
	summary := ComputeSummary(result)

	assert.Len(t, summary.TopRisks, 5)
	// First should be critical, then high, etc.
	assert.Equal(t, checker.SeverityCritical, summary.TopRisks[0].Severity)
	assert.Equal(t, checker.SeverityHigh, summary.TopRisks[1].Severity)
	assert.Equal(t, checker.SeverityHigh, summary.TopRisks[2].Severity)
	assert.Equal(t, checker.SeverityMedium, summary.TopRisks[3].Severity)
}

func TestComputeSummary_TopRisksFewerThan5(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "a", Severity: checker.SeverityHigh, Resource: "r1", Kind: "Pod"},
		{Checker: "b", Severity: checker.SeverityMedium, Resource: "r2", Kind: "Pod"},
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{ChecksRun: 5},
	}
	summary := ComputeSummary(result)

	assert.Len(t, summary.TopRisks, 2)
}

func TestComputeSummary_UniqueResources(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "a", Severity: checker.SeverityHigh, Resource: "nginx", Namespace: "default", Kind: "Deployment"},
		{Checker: "b", Severity: checker.SeverityHigh, Resource: "nginx", Namespace: "default", Kind: "Deployment"},
		{Checker: "c", Severity: checker.SeverityMedium, Resource: "api", Namespace: "backend", Kind: "Deployment"},
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{ChecksRun: 10},
	}
	summary := ComputeSummary(result)

	assert.Equal(t, 2, summary.UniqueResources)
	assert.Equal(t, 2, summary.UniqueNamespaces)
}

func TestComputeSummary_CheckCoverage(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "r1", Kind: "Pod"},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "r2", Kind: "Pod"},
		{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "r3", Kind: "Pod"},
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{
			ChecksRun:     25,
			ChecksSkipped: 3,
			ChecksErrored: 1,
		},
	}
	summary := ComputeSummary(result)

	assert.Equal(t, 25, summary.CheckCoverage.TotalRun)
	assert.Equal(t, 3, summary.CheckCoverage.Skipped)
	assert.Equal(t, 1, summary.CheckCoverage.Errored)
	assert.Equal(t, 2, summary.CheckCoverage.WithFindings) // 2 unique checkers
	assert.Equal(t, 23, summary.CheckCoverage.Clean)       // 25 - 2
}

func TestComputeSummary_SeverityCounts(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "a", Severity: checker.SeverityCritical, Resource: "r1", Kind: "Pod"},
		{Checker: "b", Severity: checker.SeverityHigh, Resource: "r2", Kind: "Pod"},
		{Checker: "c", Severity: checker.SeverityHigh, Resource: "r3", Kind: "Pod"},
		{Checker: "d", Severity: checker.SeverityMedium, Resource: "r4", Kind: "Pod"},
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{
			StartTime: time.Now(),
			ChecksRun: 10,
		},
	}
	summary := ComputeSummary(result)

	assert.Equal(t, 1, summary.SeverityCounts[checker.SeverityCritical])
	assert.Equal(t, 2, summary.SeverityCounts[checker.SeverityHigh])
	assert.Equal(t, 1, summary.SeverityCounts[checker.SeverityMedium])
	assert.Equal(t, 0, summary.SeverityCounts[checker.SeverityLow])
}

func TestComputeSummary_CheckAggregates(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment"},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "api", Namespace: "backend", Kind: "Deployment"},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "worker", Namespace: "default", Kind: "StatefulSet"},
		{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "nginx", Namespace: "default", Kind: "Deployment"},
		{Checker: "read-only-rootfs", Severity: checker.SeverityMedium, Resource: "api", Namespace: "backend", Kind: "Deployment"},
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{ChecksRun: 25},
	}
	summary := ComputeSummary(result)

	assert.Len(t, summary.CheckAggregates, 3)

	// Should be sorted by severity desc, then count desc.
	assert.Equal(t, "privileged", summary.CheckAggregates[0].Checker)
	assert.Equal(t, checker.SeverityCritical, summary.CheckAggregates[0].Severity)
	assert.Equal(t, 3, summary.CheckAggregates[0].Count)
	assert.Equal(t, 3, summary.CheckAggregates[0].Resources)
	assert.Equal(t, 2, summary.CheckAggregates[0].Namespaces)

	assert.Equal(t, "run-as-root", summary.CheckAggregates[1].Checker)
	assert.Equal(t, 1, summary.CheckAggregates[1].Count)

	assert.Equal(t, "read-only-rootfs", summary.CheckAggregates[2].Checker)
	assert.Equal(t, 1, summary.CheckAggregates[2].Count)
}

func TestComputeSummary_PassedChecks(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment"},
		{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "api", Namespace: "default", Kind: "Deployment"},
	}

	result := &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{
			ChecksRun: 5,
			CheckNames: []string{
				"automount-token",
				"host-network",
				"privileged",
				"read-only-rootfs",
				"run-as-root",
			},
		},
	}
	summary := ComputeSummary(result)

	// Passed checks = checks that ran minus those with findings.
	assert.Equal(t, []string{"automount-token", "host-network", "read-only-rootfs"}, summary.PassedChecks)
}

func TestComputeSummary_PassedChecks_NoCheckNames(t *testing.T) {
	// When CheckNames is empty (old scanner), PassedChecks should be nil.
	result := &checker.ScanResult{
		Findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment"},
		},
		ScanMeta: checker.ScanMeta{ChecksRun: 5},
	}
	summary := ComputeSummary(result)
	assert.Nil(t, summary.PassedChecks)
}
