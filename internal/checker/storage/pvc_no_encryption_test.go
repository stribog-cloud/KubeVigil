package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestPVCNoEncryptionChecker_Metadata(t *testing.T) {
	c := &PVCNoEncryptionChecker{}
	assert.Equal(t, "pvc-no-encryption", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryStorage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestPVCNoEncryptionChecker_Run(t *testing.T) {
	c := &PVCNoEncryptionChecker{}
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
			name: "PVC with encrypted StorageClass produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(StorageClassGVR, makeStorageClass("encrypted-gp3", map[string]string{"encrypted": "true"}))
				cache.Add(PersistentVolumeClaimGVR, makePVC("data", "default", "encrypted-gp3"))
				return cache
			},
		},
		{
			name: "PVC with non-encrypted StorageClass triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(StorageClassGVR, makeStorageClass("standard", map[string]string{"type": "gp2"}))
				cache.Add(PersistentVolumeClaimGVR, makePVC("data", "default", "standard"))
				return cache
			},
			wantFindings: 1,
			wantResource: "data",
		},
		{
			name: "PVC with unknown StorageClass triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PersistentVolumeClaimGVR, makePVC("data", "default", "unknown-sc"))
				return cache
			},
			wantFindings: 1,
			wantResource: "data",
		},
		{
			name: "PVC with no storageClassName is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PersistentVolumeClaimGVR, makePVC("data", "default", ""))
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
				assert.Equal(t, "pvc-no-encryption", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestPVCNoEncryptionChecker_CancelledContext(t *testing.T) {
	c := &PVCNoEncryptionChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestPVCNoEncryptionChecker_Fixtures(t *testing.T) {
	c := &PVCNoEncryptionChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "pvc-no-encryption", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "pvc-no-encryption", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
