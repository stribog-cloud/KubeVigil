package scheduling

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestPriorityClassExcessiveValueChecker_Metadata(t *testing.T) {
	c := &PriorityClassExcessiveValueChecker{}
	assert.Equal(t, "priority-class-excessive-value", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryScheduling)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), PriorityClassGVR)
}

func TestPriorityClassExcessiveValueChecker_Run(t *testing.T) {
	c := &PriorityClassExcessiveValueChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
		},
		{
			name: "custom PriorityClass with excessive value triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("my-team-critical", 1_500_000_000))
				return cache
			},
			wantFindings: 1,
			wantResource: "my-team-critical",
		},
		{
			name: "custom PriorityClass with low value produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("my-team-medium", 100_000))
				return cache
			},
		},
		{
			name: "value exactly at threshold triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("edge-case", excessivePriorityThreshold))
				return cache
			},
			wantFindings: 1,
			wantResource: "edge-case",
		},
		{
			name: "value one below threshold produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("just-under", excessivePriorityThreshold-1))
				return cache
			},
		},
		{
			name: "system-cluster-critical builtin class is exempt",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("system-cluster-critical", 2_000_000_000))
				return cache
			},
		},
		{
			name: "system-node-critical builtin class is exempt",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("system-node-critical", 2_000_000_000))
				return cache
			},
		},
		{
			name: "value of zero produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("zero-value", 0))
				return cache
			},
		},
		{
			name: "negative value produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("negative", -1000))
				return cache
			},
		},
		{
			name: "multiple PriorityClasses, only excessive one triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("low", 1000))
				cache.Add(PriorityClassGVR, makePriorityClass("excessive", 1_200_000_000))
				return cache
			},
			wantFindings: 1,
			wantResource: "excessive",
		},
		{
			name: "two excessive PriorityClasses trigger two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("excessive-one", 1_100_000_000))
				cache.Add(PriorityClassGVR, makePriorityClass("excessive-two", 1_900_000_000))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "value at maximum system-cluster-critical threshold for custom name triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("almost-system", 1_999_999_999))
				return cache
			},
			wantFindings: 1,
			wantResource: "almost-system",
		},
		{
			name: "CurrentValue field reflects the excessive value",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("track-value", 1_234_567_890))
				return cache
			},
			wantFindings: 1,
			wantResource: "track-value",
		},
		{
			name: "no PriorityClass resources in cache produces no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
		},
		{
			name: "three PriorityClasses, mixed excessive and safe",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("safe-1", 5000))
				cache.Add(PriorityClassGVR, makePriorityClass("excessive-1", 1_050_000_000))
				cache.Add(PriorityClassGVR, makePriorityClass("safe-2", 10000))
				return cache
			},
			wantFindings: 1,
			wantResource: "excessive-1",
		},
		{
			name: "value well above system-cluster-critical still triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, makePriorityClass("above-system", 3_000_000_000))
				return cache
			},
			wantFindings: 1,
			wantResource: "above-system",
		},
		{
			name: "PriorityClass with no value field at all defaults to zero and produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PriorityClassGVR, unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "scheduling.k8s.io/v1",
					"kind":       "PriorityClass",
					"metadata":   map[string]any{"name": "no-value-field"},
				}})
				return cache
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)
			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				helpers.AssertAllFindingsHaveRequiredFields(t, findings)
				assert.Equal(t, "priority-class-excessive-value", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "PriorityClass", findings[0].Kind)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestPriorityClassExcessiveValueChecker_CancelledContext(t *testing.T) {
	c := &PriorityClassExcessiveValueChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestPriorityClassExcessiveValueChecker_Fixtures(t *testing.T) {
	c := &PriorityClassExcessiveValueChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "priority-class-excessive-value", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
		assert.Equal(t, "priority-class-excessive-value", findings[0].Checker)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "priority-class-excessive-value", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
