package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestResourceQuotaMissingChecker_Run(t *testing.T) {
	c := &ResourceQuotaMissingChecker{}
	ctx := context.Background()

	assert.Equal(t, "resource-quota-missing", c.Name())
	assert.Contains(t, c.Categories(), checker.CategoryClusterConfig)

	t.Run("empty cache", func(t *testing.T) {
		findings, err := c.Run(ctx, checker.NewResourceCache())
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("namespace without ResourceQuota", func(t *testing.T) {
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
