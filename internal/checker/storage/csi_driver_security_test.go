package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestCSIDriverSecurityChecker_Metadata(t *testing.T) {
	c := &CSIDriverSecurityChecker{}
	assert.Equal(t, "csi-driver-security", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryStorage)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestCSIDriverSecurityChecker_Run(t *testing.T) {
	c := &CSIDriverSecurityChecker{}
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
			name: "CSI driver with podInfoOnMount true produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CSIDriverGVR, makeCSIDriver("ebs.csi.aws.com", boolPtr(true)))
				return cache
			},
		},
		{
			name: "CSI driver with podInfoOnMount false triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CSIDriverGVR, makeCSIDriver("ebs.csi.aws.com", boolPtr(false)))
				return cache
			},
			wantFindings: 1,
			wantResource: "ebs.csi.aws.com",
		},
		{
			name: "CSI driver without podInfoOnMount triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(CSIDriverGVR, makeCSIDriver("custom.csi.io", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "custom.csi.io",
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
				assert.Equal(t, "csi-driver-security", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestCSIDriverSecurityChecker_CancelledContext(t *testing.T) {
	c := &CSIDriverSecurityChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Run(ctx, checker.NewResourceCache())
	assert.Error(t, err)
}

func TestCSIDriverSecurityChecker_Fixtures(t *testing.T) {
	c := &CSIDriverSecurityChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "csi-driver-security", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "csi-driver-security", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
