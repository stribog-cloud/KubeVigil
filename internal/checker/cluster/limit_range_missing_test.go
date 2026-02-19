package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestLimitRangeMissingChecker_Run(t *testing.T) {
	c := &LimitRangeMissingChecker{}
	ctx := context.Background()

	assert.Equal(t, "limit-range-missing", c.Name())
	assert.Contains(t, c.Categories(), checker.CategoryClusterConfig)

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("namespace with LimitRange", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(NamespaceGVR, makeNamespace(t, "my-app", nil))
		lr := helpers.LoadFixture(t, "limit-range-missing", "passing.yaml")
		for _, gvr := range lr.GVRs() {
			for _, obj := range lr.List(gvr) {
				cache.Add(gvr, obj)
			}
		}
		cache.Add(NamespaceGVR, makeNamespace(t, "my-app", nil))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("namespace without LimitRange", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(NamespaceGVR, makeNamespace(t, "my-app", nil))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "my-app")
	})

	t.Run("system namespace skipped", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(NamespaceGVR, makeNamespace(t, "kube-system", nil))
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
