package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestAPIServerAnonymousChecker_Run(t *testing.T) {
	c := &APIServerAnonymousChecker{}
	ctx := context.Background()

	assert.Equal(t, "api-server-anonymous", c.Name())
	assert.Contains(t, c.Categories(), checker.CategoryClusterConfig)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("config with anonymous auth true", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cm := makeConfigMap(t, "kubeadm-config", "kube-system", map[string]string{
			"ClusterConfiguration": "apiServer:\n  extraArgs:\n    --anonymous-auth=true\n",
		})
		cache.Add(ConfigMapGVR, cm)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertAllFindingsHaveRequiredFields(t, findings)
	})

	t.Run("config without anonymous auth", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cm := makeConfigMap(t, "kubeadm-config", "kube-system", map[string]string{
			"ClusterConfiguration": "apiServer:\n  extraArgs:\n    --anonymous-auth=false\n",
		})
		cache.Add(ConfigMapGVR, cm)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("cancelled context", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := c.Run(cancelCtx, checker.NewResourceCache())
		assert.Error(t, err)
	})
}
