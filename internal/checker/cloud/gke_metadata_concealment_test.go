package cloud

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestGKEMetadataConcealmentChecker_Run(t *testing.T) {
	c := &GKEMetadataConcealmentChecker{}
	ctx := context.Background()

	assert.Equal(t, "gke-metadata-concealment", c.Name())
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

	t.Run("non-GKE cluster skipped", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "node-1", map[string]string{"kubernetes.io/os": "linux"})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("GKE node without workload identity", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "gke-node", map[string]string{
			"cloud.google.com/gke-nodepool": "default-pool",
		})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "Workload Identity")
	})

	t.Run("GKE node with workload identity enabled", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "gke-node", map[string]string{
			"cloud.google.com/gke-nodepool":          "default-pool",
			"iam.gke.io/gke-metadata-server-enabled": "true",
		})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
