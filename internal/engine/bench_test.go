package engine

import (
	"context"
	"os"
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

// BenchmarkParseFile_Small benchmarks parsing a single-resource YAML file.
func BenchmarkParseFile_Small(b *testing.B) {
	path := "../../test/benchdata/small.yaml"
	if _, err := os.Stat(path); err != nil {
		b.Skipf("fixture not found: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache, errs := ParseFile(path)
		if len(errs) > 0 {
			b.Fatalf("parse errors: %v", errs)
		}
		_ = cache
	}
}

// BenchmarkParseFile_Medium benchmarks parsing a 10-resource multi-document YAML file.
func BenchmarkParseFile_Medium(b *testing.B) {
	path := "../../test/benchdata/medium.yaml"
	if _, err := os.Stat(path); err != nil {
		b.Skipf("fixture not found: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache, errs := ParseFile(path)
		if len(errs) > 0 {
			b.Fatalf("parse errors: %v", errs)
		}
		_ = cache
	}
}

// BenchmarkParseFile_Large benchmarks parsing a 55-resource multi-document YAML file.
func BenchmarkParseFile_Large(b *testing.B) {
	path := "../../test/benchdata/large.yaml"
	if _, err := os.Stat(path); err != nil {
		b.Skipf("fixture not found: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache, errs := ParseFile(path)
		if len(errs) > 0 {
			b.Fatalf("parse errors: %v", errs)
		}
		_ = cache
	}
}

// BenchmarkParseDir benchmarks parsing a directory containing 20 YAML files.
func BenchmarkParseDir(b *testing.B) {
	dir := "../../test/benchdata/dir/"
	if _, err := os.Stat(dir); err != nil {
		b.Skipf("fixture dir not found: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache, errs := ParseDir(dir)
		if len(errs) > 0 {
			b.Fatalf("parse errors: %v", errs)
		}
		_ = cache
	}
}

// BenchmarkParseBytes_MultiDoc benchmarks parsing raw YAML bytes from the large fixture.
// The file is read once before the benchmark loop to isolate parsing from I/O.
func BenchmarkParseBytes_MultiDoc(b *testing.B) {
	data, err := os.ReadFile("../../test/benchdata/large.yaml")
	if err != nil {
		b.Skipf("fixture not found: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache, errs := ParseBytes(data)
		if len(errs) > 0 {
			b.Fatalf("parse errors: %v", errs)
		}
		_ = cache
	}
}

// BenchmarkScanManifest_AllChecks benchmarks the full scan pipeline with all registered
// checkers (~110 checks) against the medium fixture (10 resources).
func BenchmarkScanManifest_AllChecks(b *testing.B) {
	path := "../../test/benchdata/medium.yaml"
	if _, err := os.Stat(path); err != nil {
		b.Skipf("fixture not found: %v", err)
	}
	cfg := config.Default()
	registry := checker.DefaultRegistry()
	scanner := NewScanner(registry, cfg)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := scanner.ScanManifest(ctx, path)
		if err != nil {
			b.Fatalf("scan error: %v", err)
		}
		_ = result
	}
}

// BenchmarkScanManifest_LargeAllChecks benchmarks the full scan pipeline with all
// registered checkers (~110 checks) against the large fixture (55 resources).
func BenchmarkScanManifest_LargeAllChecks(b *testing.B) {
	path := "../../test/benchdata/large.yaml"
	if _, err := os.Stat(path); err != nil {
		b.Skipf("fixture not found: %v", err)
	}
	cfg := config.Default()
	registry := checker.DefaultRegistry()
	scanner := NewScanner(registry, cfg)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := scanner.ScanManifest(ctx, path)
		if err != nil {
			b.Fatalf("scan error: %v", err)
		}
		_ = result
	}
}
