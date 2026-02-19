package scheduling

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestHPAWithoutRequestsChecker_Metadata(t *testing.T) {
	c := &HPAWithoutRequestsChecker{}

	assert.Equal(t, "hpa-without-requests", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryScheduling)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestHPAWithoutRequestsChecker_Run(t *testing.T) {
	c := &HPAWithoutRequestsChecker{}
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
			name: "HPA targeting deployment with requests produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeploymentWithSpec(t, "web", "default", 3, nil, corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "nginx:1.25",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
						},
					}},
				})
				cache.Add(deployGVR, dep)
				hpa := makeHPA(t, "web-hpa", "default", "Deployment", "web")
				cache.Add(HorizontalPodAutoscalerGVR, hpa)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "HPA targeting deployment without requests triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 3, nil, nil)
				cache.Add(deployGVR, dep)
				hpa := makeHPA(t, "web-hpa", "default", "Deployment", "web")
				cache.Add(HorizontalPodAutoscalerGVR, hpa)
				return cache
			},
			wantFindings: 1,
			wantResource: "web-hpa",
		},
		{
			name: "HPA targeting nonexistent deployment triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				hpa := makeHPA(t, "orphan-hpa", "default", "Deployment", "ghost")
				cache.Add(HorizontalPodAutoscalerGVR, hpa)
				return cache
			},
			wantFindings: 1,
			wantResource: "orphan-hpa",
		},
		{
			name: "no HPAs produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := makeDeployment(t, "web", "default", 3, nil, nil)
				cache.Add(deployGVR, dep)
				return cache
			},
			wantFindings: 0,
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
				assert.Equal(t, "hpa-without-requests", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestHPAWithoutRequestsChecker_CancelledContext(t *testing.T) {
	c := &HPAWithoutRequestsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestHPAWithoutRequestsChecker_Fixtures(t *testing.T) {
	c := &HPAWithoutRequestsChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "hpa-without-requests", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "hpa-without-requests", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
