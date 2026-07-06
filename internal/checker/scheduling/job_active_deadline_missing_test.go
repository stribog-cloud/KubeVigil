package scheduling

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestJobActiveDeadlineMissingChecker_Metadata(t *testing.T) {
	c := &JobActiveDeadlineMissingChecker{}
	assert.Equal(t, "job-active-deadline-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryScheduling)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), JobGVR)
}

func TestJobActiveDeadlineMissingChecker_Run(t *testing.T) {
	c := &JobActiveDeadlineMissingChecker{}
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
			name: "Job without activeDeadlineSeconds triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("batch-processor", "default", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "batch-processor",
		},
		{
			name: "Job with activeDeadlineSeconds produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("batch-processor", "default", int64Ptr(3600)))
				return cache
			},
		},
		{
			name: "Job with activeDeadlineSeconds set to zero produces no findings (field present)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("batch-processor", "default", int64Ptr(0)))
				return cache
			},
		},
		{
			name: "multiple Jobs, only one missing deadline triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("with-deadline", "default", int64Ptr(60)))
				cache.Add(JobGVR, makeJob("without-deadline", "default", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "without-deadline",
		},
		{
			name: "two Jobs without deadline trigger two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("job-one", "default", nil))
				cache.Add(JobGVR, makeJob("job-two", "default", nil))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "Job in non-default namespace reports correct namespace",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("batch-processor", "prod", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "batch-processor",
		},
		{
			name: "Job with large deadline value produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("long-running", "default", int64Ptr(86400)))
				return cache
			},
		},
		{
			name: "three Jobs all missing deadline trigger three findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("j1", "default", nil))
				cache.Add(JobGVR, makeJob("j2", "default", nil))
				cache.Add(JobGVR, makeJob("j3", "default", nil))
				return cache
			},
			wantFindings: 3,
		},
		{
			name: "all Jobs with deadlines produce no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("j1", "default", int64Ptr(100)))
				cache.Add(JobGVR, makeJob("j2", "default", int64Ptr(200)))
				return cache
			},
		},
		{
			name: "Job in kube-system namespace still evaluated",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("system-job", "kube-system", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "system-job",
		},
		{
			name: "Job with small positive deadline produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("quick-job", "default", int64Ptr(1)))
				return cache
			},
		},
		{
			name: "mixed namespaces, one missing deadline in each",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("job-a", "ns-a", nil))
				cache.Add(JobGVR, makeJob("job-b", "ns-b", nil))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "no Job resources in cache produces no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
		},
		{
			name: "Job name with special characters missing deadline still triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("nightly-cleanup-20260706", "default", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "nightly-cleanup-20260706",
		},
		{
			name: "one Job missing, one Job present in same namespace",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(JobGVR, makeJob("job-ok", "default", int64Ptr(300)))
				cache.Add(JobGVR, makeJob("job-missing", "default", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "job-missing",
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
				assert.Equal(t, "job-active-deadline-missing", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				assert.Equal(t, "Job", findings[0].Kind)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestJobActiveDeadlineMissingChecker_CancelledContext(t *testing.T) {
	c := &JobActiveDeadlineMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestJobActiveDeadlineMissingChecker_Fixtures(t *testing.T) {
	c := &JobActiveDeadlineMissingChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "job-active-deadline-missing", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
		assert.Equal(t, "job-active-deadline-missing", findings[0].Checker)
		assert.Equal(t, checker.SeverityLow, findings[0].Severity)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "job-active-deadline-missing", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
