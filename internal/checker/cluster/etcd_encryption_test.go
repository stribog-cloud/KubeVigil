package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestEtcdEncryptionChecker_Run(t *testing.T) {
	c := &EtcdEncryptionChecker{}
	ctx := context.Background()

	assert.Equal(t, "etcd-encryption", c.Name())

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("config with encryption provider", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cm := makeConfigMap(t, "kubeadm-config", "kube-system", map[string]string{
			"ClusterConfiguration": "--encryption-provider-config=/etc/kubernetes/enc.yaml",
		})
		cache.Add(ConfigMapGVR, cm)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("config without encryption triggers finding", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cm := makeConfigMap(t, "kubeadm-config", "kube-system", map[string]string{
			"ClusterConfiguration": "apiServer:\n  extraArgs: {}\n",
		})
		cache.Add(ConfigMapGVR, cm)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityCritical, findings[0].Severity)
	})

	t.Run("cancelled context", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := c.Run(cancelCtx, checker.NewResourceCache())
		assert.Error(t, err)
	})
}
