package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestAdmissionControllersChecker_Run(t *testing.T) {
	c := &AdmissionControllersChecker{}
	ctx := context.Background()

	assert.Equal(t, "admission-controllers", c.Name())

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("config with disabled admission controller", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cm := makeConfigMap(t, "kubeadm-config", "kube-system", map[string]string{
			"ClusterConfiguration": "--disable-admission-plugins=PodSecurity,NodeRestriction",
		})
		cache.Add(ConfigMapGVR, cm)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 2) // NodeRestriction and PodSecurity
	})

	t.Run("cancelled context", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := c.Run(cancelCtx, checker.NewResourceCache())
		assert.Error(t, err)
	})
}
