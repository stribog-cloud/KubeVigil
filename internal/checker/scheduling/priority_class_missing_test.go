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

func TestPriorityClassMissingChecker_Metadata(t *testing.T) {
	c := &PriorityClassMissingChecker{}

	assert.Equal(t, "priority-class-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryScheduling)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestPriorityClassMissingChecker_Run(t *testing.T) {
	c := &PriorityClassMissingChecker{}
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
			name: "deployment with priorityClassName produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeploymentWithSpec(t, "web", "default", 1, nil, corev1.PodSpec{
					Containers:        []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					PriorityClassName: "high-priority",
				})
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment without priorityClassName triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 1, nil, nil)
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 1,
			wantResource: "web",
		},
		{
			name: "multiple deployments all missing priority class",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(deployGVR, makeDeployment(t, "web", "default", 1, nil, nil))
				cache.Add(deployGVR, makeDeployment(t, "api", "default", 1, nil, nil))
				return cache
			},
			wantFindings: 2,
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
				assert.Equal(t, "priority-class-missing", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestPriorityClassMissingChecker_CancelledContext(t *testing.T) {
	c := &PriorityClassMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestPriorityClassMissingChecker_Fixtures(t *testing.T) {
	c := &PriorityClassMissingChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "priority-class-missing", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "priority-class-missing", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
