package psa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestPSPStillPresentChecker_Metadata(t *testing.T) {
	c := &PSPStillPresentChecker{}

	assert.Equal(t, "psp-still-present", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryPSS)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), PodSecurityPolicyGVR)
}

func TestPSPStillPresentChecker_Run(t *testing.T) {
	c := &PSPStillPresentChecker{}
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
			wantFindings: 0,
		},
		{
			name: "single PSP triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				psp := makePSP("restrictive")
				cache.Add(PodSecurityPolicyGVR, psp)
				return cache
			},
			wantFindings: 1,
			wantResource: "restrictive",
		},
		{
			name: "multiple PSPs trigger multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PodSecurityPolicyGVR, makePSP("restrictive"))
				cache.Add(PodSecurityPolicyGVR, makePSP("permissive"))
				cache.Add(PodSecurityPolicyGVR, makePSP("custom"))
				return cache
			},
			wantFindings: 3,
		},
		{
			name: "PSP finding has correct severity",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PodSecurityPolicyGVR, makePSP("test-psp"))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-psp",
		},
		{
			name: "PSP finding has correct kind",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PodSecurityPolicyGVR, makePSP("check-kind"))
				return cache
			},
			wantFindings: 1,
			wantResource: "check-kind",
		},
		{
			name: "cache with non-PSP resources returns no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "test-ns", nil)
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "PSP with long name triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PodSecurityPolicyGVR, makePSP("legacy-pod-security-policy-from-old-cluster"))
				return cache
			},
			wantFindings: 1,
			wantResource: "legacy-pod-security-policy-from-old-cluster",
		},
		{
			name: "PSP message mentions removal in 1.25",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PodSecurityPolicyGVR, makePSP("msg-check"))
				return cache
			},
			wantFindings: 1,
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
				assert.Equal(t, "psp-still-present", findings[0].Checker)
				assert.Equal(t, checker.SeverityInfo, findings[0].Severity)
				assert.Equal(t, "PodSecurityPolicy", findings[0].Kind)
				assert.Contains(t, findings[0].Message, "1.25")

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestPSPStillPresentChecker_CancelledContext(t *testing.T) {
	c := &PSPStillPresentChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(PodSecurityPolicyGVR, makePSP("test-psp"))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestPSPStillPresentChecker_Fixtures(t *testing.T) {
	c := &PSPStillPresentChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psp-still-present", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "restrictive")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psp-still-present", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
