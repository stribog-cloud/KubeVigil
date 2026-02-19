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

func TestStartupProbesChecker_Run(t *testing.T) {
	c := &StartupProbesChecker{}
	ctx := context.Background()

	assert.Equal(t, "startup-probes", c.Name())
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

	t.Run("liveness without startup", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "slow-app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:          "app",
				Image:         "myapp:1.0",
				LivenessProbe: httpProbe,
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityInfo, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "startup probe")
	})

	t.Run("liveness with startup", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "safe-app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:          "app",
				Image:         "myapp:1.0",
				LivenessProbe: httpProbe,
				StartupProbe:  httpProbe,
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("no liveness probe at all", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "no-probes", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "busybox",
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings, "no liveness probe means startup probe is irrelevant")
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "startup-probes", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "startup-probes", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
