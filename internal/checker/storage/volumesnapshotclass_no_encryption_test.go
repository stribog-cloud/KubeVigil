package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestVolumeSnapshotClassNoEncryptionChecker_Metadata(t *testing.T) {
	c := &VolumeSnapshotClassNoEncryptionChecker{}
	assert.Equal(t, "volumesnapshotclass-no-encryption", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryStorage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), VolumeSnapshotClassGVR)
}

func TestVolumeSnapshotClassNoEncryptionChecker_Run(t *testing.T) {
	c := &VolumeSnapshotClassNoEncryptionChecker{}
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
			name: "VolumeSnapshotClass with encrypted=true produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("encrypted-snaps", map[string]string{"encrypted": "true"}))
				return cache
			},
		},
		{
			name: "VolumeSnapshotClass with no parameters triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("default-snaps", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "default-snaps",
		},
		{
			name: "VolumeSnapshotClass with empty parameters map triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("default-snaps", map[string]string{}))
				return cache
			},
			wantFindings: 1,
			wantResource: "default-snaps",
		},
		{
			name: "VolumeSnapshotClass with unrelated parameters triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("default-snaps", map[string]string{"type": "gp3"}))
				return cache
			},
			wantFindings: 1,
			wantResource: "default-snaps",
		},
		{
			name: "VolumeSnapshotClass with encryption (alt key) parameter produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("encrypted-snaps", map[string]string{"encryption": "kms"}))
				return cache
			},
		},
		{
			name: "VolumeSnapshotClass with csi.storage.k8s.io/encrypt parameter produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("encrypted-snaps", map[string]string{"csi.storage.k8s.io/encrypt": "true"}))
				return cache
			},
		},
		{
			name: "VolumeSnapshotClass with disk-encryption-kms-key parameter produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("encrypted-snaps", map[string]string{"disk-encryption-kms-key": "projects/p/keyRings/r/cryptoKeys/k"}))
				return cache
			},
		},
		{
			name: "multiple VolumeSnapshotClasses, only unencrypted one triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("encrypted-snaps", map[string]string{"encrypted": "true"}))
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("plain-snaps", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "plain-snaps",
		},
		{
			name: "two unencrypted VolumeSnapshotClasses trigger two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("plain-one", nil))
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("plain-two", map[string]string{"type": "standard"}))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "encrypted parameter explicitly false triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("odd-snaps", map[string]string{"encrypted": "false"}))
				return cache
			},
			wantFindings: 1,
			wantResource: "odd-snaps",
		},
		{
			name: "VolumeSnapshotClass encrypted with 1 produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("encrypted-snaps", map[string]string{"encrypted": "1"}))
				return cache
			},
		},
		{
			name: "three VolumeSnapshotClasses mixed encrypted/unencrypted",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("enc-1", map[string]string{"encrypted": "true"}))
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("plain-1", nil))
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("enc-2", map[string]string{"encryption": "cmek"}))
				return cache
			},
			wantFindings: 1,
			wantResource: "plain-1",
		},
		{
			name: "VolumeSnapshotClass is cluster-scoped and has no namespace",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(VolumeSnapshotClassGVR, makeVolumeSnapshotClass("plain-snaps", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "plain-snaps",
		},
		{
			name: "no VolumeSnapshotClass resources in cache produces no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
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
				assert.Equal(t, "volumesnapshotclass-no-encryption", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "VolumeSnapshotClass", findings[0].Kind)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestVolumeSnapshotClassNoEncryptionChecker_CancelledContext(t *testing.T) {
	c := &VolumeSnapshotClassNoEncryptionChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestVolumeSnapshotClassNoEncryptionChecker_Fixtures(t *testing.T) {
	c := &VolumeSnapshotClassNoEncryptionChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "volumesnapshotclass-no-encryption", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
		assert.Equal(t, "volumesnapshotclass-no-encryption", findings[0].Checker)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "volumesnapshotclass-no-encryption", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
