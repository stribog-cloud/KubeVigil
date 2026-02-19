package supply_chain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestLivenessReadinessProbesChecker_Run(t *testing.T) {
	c := &LivenessReadinessProbesChecker{}
	ctx := context.Background()

	assert.Equal(t, "liveness-readiness-probes", c.Name())
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

	httpProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8080),
			},
		},
	}

	t.Run("missing both probes", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "no-probes", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2, "should flag both missing liveness and readiness")
	})

	t.Run("has both probes", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "probed", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:           "app",
				Image:          "nginx:1.25",
				LivenessProbe:  httpProbe,
				ReadinessProbe: httpProbe,
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("missing readiness only", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "half-probed", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:          "app",
				Image:         "nginx:1.25",
				LivenessProbe: httpProbe,
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "readiness")
	})

	t.Run("init containers skipped", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "init-ok", "default", corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "init",
				Image: "busybox",
			}},
			Containers: []corev1.Container{{
				Name:           "app",
				Image:          "nginx:1.25",
				LivenessProbe:  httpProbe,
				ReadinessProbe: httpProbe,
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "liveness-readiness-probes", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "liveness-readiness-probes", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
