package report

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// benchScanResult builds a realistic ScanResult with ~100 findings spanning
// multiple severities, checker names, resource kinds, and namespaces. The
// result is suitable for benchmarking all reporter implementations.
func benchScanResult(b *testing.B) *checker.ScanResult {
	b.Helper()

	severities := []checker.Severity{
		checker.SeverityCritical,
		checker.SeverityHigh,
		checker.SeverityMedium,
		checker.SeverityLow,
		checker.SeverityInfo,
	}

	checkerNames := []string{
		"privileged", "capabilities-added", "capabilities-not-dropped",
		"run-as-root", "readonly-rootfs", "resource-limits-missing",
		"host-pid", "host-network", "privilege-escalation", "seccomp-profile",
	}

	kinds := []string{"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job"}
	namespaces := []string{"default", "production", "staging", "monitoring", "dev"}

	findings := make([]checker.Finding, 100)
	for i := range findings {
		findings[i] = checker.Finding{
			Checker:     checkerNames[i%len(checkerNames)],
			Severity:    severities[i%len(severities)],
			Resource:    fmt.Sprintf("workload-%d", i),
			Namespace:   namespaces[i%len(namespaces)],
			Kind:        kinds[i%len(kinds)],
			Container:   fmt.Sprintf("container-%d", i%3),
			Message:     fmt.Sprintf("Security issue #%d detected in container", i),
			Remediation: "Set securityContext.privileged to false.\n\n```yaml\nsecurityContext:\n  privileged: false\n```",
			FieldPath:   fmt.Sprintf(".spec.containers[%d].securityContext.privileged", i%3),
			Frameworks: []checker.FrameworkRef{
				{Framework: "cis", Version: "1.8", ControlID: fmt.Sprintf("5.2.%d", i%10), Title: "Pod Security"},
				{Framework: "mitre", Version: "v14", ControlID: "T1611", Title: "Escape to Host"},
			},
		}
	}

	checkNames := make([]string, len(checkerNames))
	copy(checkNames, checkerNames)

	descriptions := make(map[string]string, len(checkerNames))
	categories := make(map[string]string, len(checkerNames))
	for _, name := range checkerNames {
		descriptions[name] = "Detects " + name + " security issues"
		categories[name] = "workload"
	}

	return &checker.ScanResult{
		Findings: findings,
		ScanMeta: checker.ScanMeta{
			StartTime:         time.Now(),
			Duration:          2 * time.Second,
			ChecksRun:         110,
			ChecksSkipped:     0,
			ChecksErrored:     0,
			CheckNames:        checkNames,
			CheckDescriptions: descriptions,
			CheckCategories:   categories,
			ScanMode:          checker.ScanModeManifest,
		},
	}
}

// benchReporter is a generic benchmark helper that runs a named reporter
// against the standard benchmark scan result.
func benchReporter(b *testing.B, name string) {
	b.Helper()

	result := benchScanResult(b)
	r, err := Get(name)
	if err != nil {
		b.Fatalf("Get(%q): %v", name, err)
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := r.Generate(ctx, result, io.Discard); err != nil {
			b.Fatalf("Generate failed: %v", err)
		}
	}
}

func BenchmarkReportText(b *testing.B) {
	benchReporter(b, "text")
}

func BenchmarkReportJSON(b *testing.B) {
	benchReporter(b, "json")
}

func BenchmarkReportYAML(b *testing.B) {
	benchReporter(b, "yaml")
}

func BenchmarkReportHTML(b *testing.B) {
	benchReporter(b, "html")
}

func BenchmarkReportSARIF(b *testing.B) {
	benchReporter(b, "sarif")
}

func BenchmarkReportJUnit(b *testing.B) {
	benchReporter(b, "junit")
}

func BenchmarkReportCSV(b *testing.B) {
	benchReporter(b, "csv")
}

func BenchmarkReportMarkdown(b *testing.B) {
	benchReporter(b, "markdown")
}
