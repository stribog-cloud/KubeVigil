package supply_chain

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestImageAgeChecker_Run(t *testing.T) {
	c := &ImageAgeChecker{}
	ctx := context.Background()

	assert.Equal(t, "image-age", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySupplyChain)

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("cancelled context", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := c.Run(cancelCtx, checker.NewResourceCache())
		assert.Error(t, err)
	})

	t.Run("old image annotation", func(t *testing.T) {
		cache := checker.NewResourceCache()
		oldDate := time.Now().AddDate(0, -7, 0).Format(time.RFC3339)
		dep := makeDeploymentWithAnnotations(t, "stale-app", "default",
			map[string]string{imageAgeAnnotation: oldDate},
			corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "old-image:1.0",
				}},
			},
		)
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityLow, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "days old")
	})

	t.Run("recent image annotation", func(t *testing.T) {
		cache := checker.NewResourceCache()
		recentDate := time.Now().AddDate(0, -1, 0).Format(time.RFC3339)
		dep := makeDeploymentWithAnnotations(t, "fresh-app", "default",
			map[string]string{imageAgeAnnotation: recentDate},
			corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "fresh-image:2.0",
				}},
			},
		)
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("no annotation", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "no-anno", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings, "no annotation means check is skipped")
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "image-age", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "image-age", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
