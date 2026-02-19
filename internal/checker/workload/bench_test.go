package workload

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/engine"
)

// benchWorkloadCache creates a ResourceCache from the medium benchmark fixture.
func benchWorkloadCache(b *testing.B) *checker.ResourceCache {
	b.Helper()
	cache, errs := engine.ParseFile("../../../test/benchdata/medium.yaml")
	if len(errs) > 0 {
		b.Skipf("parse errors: %v", errs)
	}
	return cache
}

func BenchmarkExtractPodSpecs(b *testing.B) {
	cache := benchWorkloadCache(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		specs := ExtractPodSpecs(cache)
		_ = specs
	}
}

func BenchmarkIterateContainers(b *testing.B) {
	cache := benchWorkloadCache(b)
	specs := ExtractPodSpecs(cache)
	if len(specs) == 0 {
		b.Skip("no pod specs extracted from fixture")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range specs {
			IterateContainers(&specs[j], func(c corev1.Container, ct ContainerType, idx int) {
				_ = c
			})
		}
	}
}

func BenchmarkCheckerRun_Privileged(b *testing.B) {
	cache := benchWorkloadCache(b)
	c := &PrivilegedChecker{}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings, err := c.Run(ctx, cache)
		if err != nil {
			b.Fatal(err)
		}
		_ = findings
	}
}

func BenchmarkAllWorkloadCheckers(b *testing.B) {
	cache := benchWorkloadCache(b)
	checkers := []checker.Checker{
		&PrivilegedChecker{},
		&CapabilitiesAddedChecker{},
		&CapabilitiesNotDroppedChecker{},
		&RunAsRootChecker{},
		&ReadOnlyRootfsChecker{},
		&ResourceLimitsMissingChecker{},
		&HostPIDChecker{},
		&HostNetworkChecker{},
		&PrivilegeEscalationChecker{},
		&SeccompProfileChecker{},
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range checkers {
			findings, err := c.Run(ctx, cache)
			if err != nil {
				b.Fatal(err)
			}
			_ = findings
		}
	}
}
