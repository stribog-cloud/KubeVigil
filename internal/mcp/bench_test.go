package mcp

import (
	"fmt"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// generateFindings creates n findings with varied checkers, severities,
// namespaces, and categories for benchmarking.
func generateFindings(n int) []checker.Finding {
	checkers := []string{"privileged", "run-as-root", "capabilities-added", "image-tag-latest", "no-resource-limits"}
	severities := []string{"Critical", "High", "Medium", "Low", "Info"}
	namespaces := []string{"default", "payments", "monitoring", "backend", "frontend"}

	findings := make([]checker.Finding, n)
	for i := range n {
		ci := i % len(checkers)
		si := i % len(severities)
		ni := i % len(namespaces)
		sev, _ := checker.ParseSeverity(severities[si])
		findings[i] = checker.Finding{
			Checker:   checkers[ci],
			Severity:  sev,
			Resource:  fmt.Sprintf("deploy-%d", i),
			Namespace: namespaces[ni],
			Kind:      "Deployment",
			Message:   fmt.Sprintf("Finding %d", i),
		}
		// Add framework refs to some findings.
		if i%3 == 0 {
			findings[i].Frameworks = []checker.FrameworkRef{
				{Framework: "cis", ControlID: fmt.Sprintf("5.2.%d", i%10)},
			}
		}
	}
	return findings
}

func BenchmarkBuildSummary(b *testing.B) {
	for _, size := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			findings := generateFindings(size)
			result := testResult(findings)
			b.ResetTimer()
			for range b.N {
				_ = buildSummary(result)
			}
		})
	}
}

func BenchmarkApplyFilters(b *testing.B) {
	findings := generateFindings(5000)
	cfg := testKVEmpty().config
	cfg.Settings.IncludeSystemNamespaces = true

	b.Run("5000_no_filter", func(b *testing.B) {
		for range b.N {
			_ = applyFilters(findings, cfg, "", "", "")
		}
	})

	b.Run("5000_severity", func(b *testing.B) {
		for range b.N {
			_ = applyFilters(findings, cfg, "", "high", "")
		}
	})

	b.Run("5000_multi_filter", func(b *testing.B) {
		for range b.N {
			_ = applyFilters(findings, cfg, "payments", "high", "cis")
		}
	})
}

func BenchmarkFilterFindings(b *testing.B) {
	findings := generateFindings(5000)

	b.Run("5000_no_filter", func(b *testing.B) {
		input := &GetFindingsInput{}
		for range b.N {
			_ = filterFindings(findings, input)
		}
	})

	b.Run("5000_severity", func(b *testing.B) {
		input := &GetFindingsInput{Severity: "high"}
		for range b.N {
			_ = filterFindings(findings, input)
		}
	})

	b.Run("5000_multi_filter", func(b *testing.B) {
		input := &GetFindingsInput{
			Severity:  "high",
			Namespace: "payments",
			Framework: "cis",
		}
		for range b.N {
			_ = filterFindings(findings, input)
		}
	})
}
