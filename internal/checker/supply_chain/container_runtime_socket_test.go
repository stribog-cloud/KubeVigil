package supply_chain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestContainerRuntimeSocketChecker_Run(t *testing.T) {
	c := &ContainerRuntimeSocketChecker{}
	ctx := context.Background()

	assert.Equal(t, "container-runtime-socket", c.Name())
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

	t.Run("docker socket mounted", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "runner", "ci", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "dind",
				Image: "docker:24",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "docker-sock", MountPath: "/var/run/docker.sock"},
				},
			}},
			Volumes: []corev1.Volume{{
				Name: "docker-sock",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"},
				},
			}},
		})
		cache.Add(workload.GVRs()[1], dep) // deployments
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityCritical, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "docker.sock")
	})

	t.Run("containerd socket mounted", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "runtime", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "busybox",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "containerd", MountPath: "/run/containerd/containerd.sock"},
				},
			}},
			Volumes: []corev1.Volume{{
				Name: "containerd",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/run/containerd/containerd.sock"},
				},
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "containerd.sock")
	})

	t.Run("non-runtime hostPath is safe", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "logger", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "busybox",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "logs", MountPath: "/var/log"},
				},
			}},
			Volumes: []corev1.Volume{{
				Name: "logs",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"},
				},
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("no hostPath volumes", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "safe", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "container-runtime-socket", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "container-runtime-socket", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
