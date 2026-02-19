package scheduling

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

var deployGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

func TestTolerationControlPlaneChecker_Metadata(t *testing.T) {
	c := &TolerationControlPlaneChecker{}

	assert.Equal(t, "toleration-control-plane", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryScheduling)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestTolerationControlPlaneChecker_Run(t *testing.T) {
	c := &TolerationControlPlaneChecker{}
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
			name: "deployment with non-control-plane toleration produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, []corev1.Toleration{
					{Key: "app", Operator: corev1.TolerationOpEqual, Value: "special", Effect: corev1.TaintEffectNoSchedule},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment tolerating control-plane taint triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, []corev1.Toleration{
					{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 1,
			wantResource: "web",
		},
		{
			name: "deployment tolerating master taint triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, []corev1.Toleration{
					{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 1,
			wantResource: "web",
		},
		{
			name: "multiple tolerations with one control-plane triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, []corev1.Toleration{
					{Key: "app", Operator: corev1.TolerationOpEqual, Value: "test"},
					{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists},
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
				assert.Equal(t, "toleration-control-plane", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestTolerationControlPlaneChecker_CancelledContext(t *testing.T) {
	c := &TolerationControlPlaneChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestTolerationControlPlaneChecker_Fixtures(t *testing.T) {
	c := &TolerationControlPlaneChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "toleration-control-plane", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "toleration-control-plane", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
