package cloud

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestAKSPodIdentityChecker_Run(t *testing.T) {
	c := &AKSPodIdentityChecker{}
	ctx := context.Background()

	assert.Equal(t, "aks-pod-identity", c.Name())
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

	t.Run("non-AKS cluster skipped", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "node-1", map[string]string{"kubernetes.io/os": "linux"})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("AKS with deprecated aad-pod-identity", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "aks-node", map[string]string{
			"kubernetes.azure.com/cluster": "my-aks-cluster",
		})
		cache.Add(NodeGVR, node)
		ds := makeDaemonSet(t, "nmi", "kube-system", []corev1.Container{
			{Name: "nmi", Image: "mcr.microsoft.com/oss-open-service-mesh/aad-pod-identity/nmi:v1.8"},
		})
		cache.Add(DaemonSetGVR, ds)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "aad-pod-identity")
	})

	t.Run("AKS without deprecated identity", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "aks-node", map[string]string{
			"kubernetes.azure.com/cluster": "my-aks-cluster",
		})
		cache.Add(NodeGVR, node)
		ds := makeDaemonSet(t, "kube-proxy", "kube-system", []corev1.Container{
			{Name: "kube-proxy", Image: "registry.k8s.io/kube-proxy:v1.29.0"},
		})
		cache.Add(DaemonSetGVR, ds)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
