package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestComponentVersionsChecker_Run(t *testing.T) {
	c := &ComponentVersionsChecker{}
	ctx := context.Background()

	assert.Equal(t, "component-versions", c.Name())

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("all nodes same version", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(NodeGVR, makeNode("node-1", "v1.29.0"))
		cache.Add(NodeGVR, makeNode("node-2", "v1.29.1"))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("node 3 versions behind triggers finding", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(NodeGVR, makeNode("node-1", "v1.29.0"))
		cache.Add(NodeGVR, makeNode("node-old", "v1.25.0"))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "node-old")
	})

	t.Run("node 2 versions behind is ok", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(NodeGVR, makeNode("node-1", "v1.29.0"))
		cache.Add(NodeGVR, makeNode("node-2", "v1.27.0"))
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
