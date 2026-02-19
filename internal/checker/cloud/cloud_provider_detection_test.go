package cloud

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestProviderDetectionChecker_Run(t *testing.T) {
	c := &ProviderDetectionChecker{}
	ctx := context.Background()

	assert.Equal(t, "cloud-provider-detection", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryCloudProvider)

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

	t.Run("detects EKS", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "eks-node", map[string]string{"eks.amazonaws.com/nodegroup": "workers"})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityInfo, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "EKS")
	})

	t.Run("detects GKE", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "gke-node", map[string]string{"cloud.google.com/gke-nodepool": "default"})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "GKE")
	})

	t.Run("detects AKS", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "aks-node", map[string]string{"kubernetes.azure.com/cluster": "my-cluster"})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "AKS")
	})

	t.Run("unknown provider no finding", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "bare-metal", map[string]string{"kubernetes.io/os": "linux"})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
