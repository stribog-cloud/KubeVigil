package scheduling

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestCronJobConcurrencyUnboundedChecker_Metadata(t *testing.T) {
	c := &CronJobConcurrencyUnboundedChecker{}
	assert.Equal(t, "cronjob-concurrency-unbounded", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryScheduling)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), CronJobGVR)
}

func TestCronJobConcurrencyUnboundedChecker_Run(t *testing.T) {
	c := &CronJobConcurrencyUnboundedChecker{}
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
			name: "CronJob with no concurrencyPolicy and no deadline triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "nightly-report",
		},
		{
			name: "CronJob with explicit Allow and no deadline triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "Allow", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "nightly-report",
		},
		{
			name: "CronJob with concurrencyPolicy Forbid produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "Forbid", nil))
				return cache
			},
		},
		{
			name: "CronJob with concurrencyPolicy Replace produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "Replace", nil))
				return cache
			},
		},
		{
			name: "CronJob with Allow and startingDeadlineSeconds bound produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "Allow", int64Ptr(300)))
				return cache
			},
		},
		{
			name: "CronJob with unset concurrencyPolicy but startingDeadlineSeconds bound produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "", int64Ptr(120)))
				return cache
			},
		},
		{
			name: "startingDeadlineSeconds set to zero still counts as present",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "", int64Ptr(0)))
				return cache
			},
		},
		{
			name: "multiple CronJobs, only unbounded one triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("safe", "default", "Forbid", nil))
				cache.Add(CronJobGVR, makeCronJob("unbounded", "default", "", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "unbounded",
		},
		{
			name: "two unbounded CronJobs trigger two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("cj-one", "default", "", nil))
				cache.Add(CronJobGVR, makeCronJob("cj-two", "default", "Allow", nil))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "CronJob in non-default namespace reports correct namespace",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "prod", "", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "nightly-report",
		},
		{
			name: "unrecognized concurrencyPolicy value treated as bound (not Allow)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("weird-policy", "default", "SomethingElse", nil))
				return cache
			},
		},
		{
			name: "no CronJob resources in cache produces no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
		},
		{
			name: "FixHint is populated on the finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "nightly-report",
		},
		{
			name: "three CronJobs mixed bounded and unbounded",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("bounded-1", "default", "Forbid", nil))
				cache.Add(CronJobGVR, makeCronJob("unbounded-1", "default", "Allow", nil))
				cache.Add(CronJobGVR, makeCronJob("bounded-2", "default", "Allow", int64Ptr(60)))
				return cache
			},
			wantFindings: 1,
			wantResource: "unbounded-1",
		},
		{
			name: "large startingDeadlineSeconds value still counts as bounded",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CronJobGVR, makeCronJob("nightly-report", "default", "Allow", int64Ptr(3600)))
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
				assert.Equal(t, "cronjob-concurrency-unbounded", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				assert.Equal(t, "CronJob", findings[0].Kind)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.name == "FixHint is populated on the finding" {
					require.NotNil(t, findings[0].FixHint)
					assert.Equal(t, checker.FixLikelySafe, findings[0].FixHint.Safety)
					assert.Equal(t, checker.FixOpSet, findings[0].FixHint.Operation)
				}
			}
		})
	}
}

func TestCronJobConcurrencyUnboundedChecker_CancelledContext(t *testing.T) {
	c := &CronJobConcurrencyUnboundedChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestCronJobConcurrencyUnboundedChecker_Fixtures(t *testing.T) {
	c := &CronJobConcurrencyUnboundedChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "cronjob-concurrency-unbounded", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
		assert.Equal(t, "cronjob-concurrency-unbounded", findings[0].Checker)
		assert.Equal(t, checker.SeverityLow, findings[0].Severity)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "cronjob-concurrency-unbounded", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
