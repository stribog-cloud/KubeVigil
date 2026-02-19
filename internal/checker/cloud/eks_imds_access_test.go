package cloud

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

func TestEKSIMDSAccessChecker_Run(t *testing.T) {
	c := &EKSIMDSAccessChecker{}
	ctx := context.Background()

	assert.Equal(t, "eks-imds-access", c.Name())
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

	t.Run("non-EKS cluster skipped", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "node-1", map[string]string{"kubernetes.io/os": "linux"})
		cache.Add(NodeGVR, node)
		dep := makeDeployment(t, "app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("EKS hostNetwork pod flagged", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "eks-node", map[string]string{"eks.amazonaws.com/nodegroup": "workers"})
		cache.Add(NodeGVR, node)
		dep := makeDeployment(t, "host-app", "default", corev1.PodSpec{
			HostNetwork: true,
			Containers:  []corev1.Container{{Name: "app", Image: "nginx"}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
		assert.Contains(t, findings[0].Message, "hostNetwork")
	})

	t.Run("EKS pod without IMDS block", func(t *testing.T) {
		cache := checker.NewResourceCache()
		node := makeNode(t, "eks-node", map[string]string{"eks.amazonaws.com/nodegroup": "workers"})
		cache.Add(NodeGVR, node)
		dep := makeDeployment(t, "app", "default", corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "NetworkPolicy")
	})
}
