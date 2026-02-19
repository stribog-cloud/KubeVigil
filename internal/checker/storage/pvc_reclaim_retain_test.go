package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestPVCReclaimRetainChecker_Metadata(t *testing.T) {
	c := &PVCReclaimRetainChecker{}
	assert.Equal(t, "pvc-reclaim-retain", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryStorage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestPVCReclaimRetainChecker_Run(t *testing.T) {
	c := &PVCReclaimRetainChecker{}
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
			name: "PV with Delete reclaim policy produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PersistentVolumeGVR, makePV("pv-1", "Delete", "Bound"))
				return cache
			},
		},
		{
			name: "PV with Retain and Bound produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PersistentVolumeGVR, makePV("pv-1", "Retain", "Bound"))
				return cache
			},
		},
		{
			name: "PV with Retain and Released triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PersistentVolumeGVR, makePV("pv-1", "Retain", "Released"))
				return cache
			},
			wantFindings: 1,
			wantResource: "pv-1",
		},
		{
			name: "PV with Retain and Available produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PersistentVolumeGVR, makePV("pv-1", "Retain", "Available"))
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
				assert.Equal(t, "pvc-reclaim-retain", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestPVCReclaimRetainChecker_CancelledContext(t *testing.T) {
	c := &PVCReclaimRetainChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestPVCReclaimRetainChecker_Fixtures(t *testing.T) {
	c := &PVCReclaimRetainChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "pvc-reclaim-retain", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "pvc-reclaim-retain", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
