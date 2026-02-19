package scheduling

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestTolerationAllChecker_Metadata(t *testing.T) {
	c := &TolerationAllChecker{}

	assert.Equal(t, "toleration-all", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryScheduling)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestTolerationAllChecker_Run(t *testing.T) {
	c := &TolerationAllChecker{}
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
			name: "deployment without tolerations produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, nil)
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with specific toleration produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, []corev1.Toleration{
					{Key: "special", Operator: corev1.TolerationOpExists},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with catch-all toleration triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, []corev1.Toleration{
					{Operator: corev1.TolerationOpExists},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 1,
			wantResource: "web",
		},
		{
			name: "Equal operator with empty key does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, []corev1.Toleration{
					{Key: "", Operator: corev1.TolerationOpEqual, Value: "test"},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "mixed tolerations with one catch-all triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, []corev1.Toleration{
					{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists},
					{Operator: corev1.TolerationOpExists},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 1,
			wantResource: "web",
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
				assert.Equal(t, "toleration-all", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestTolerationAllChecker_CancelledContext(t *testing.T) {
	c := &TolerationAllChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestTolerationAllChecker_Fixtures(t *testing.T) {
	c := &TolerationAllChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "toleration-all", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "toleration-all", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
