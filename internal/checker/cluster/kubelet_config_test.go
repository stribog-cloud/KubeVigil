package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestKubeletConfigChecker_Run(t *testing.T) {
	c := &KubeletConfigChecker{}
	ctx := context.Background()

	assert.Equal(t, "kubelet-config", c.Name())
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("node without issues", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(NodeGVR, makeNode("node-1", "v1.29.0"))
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
