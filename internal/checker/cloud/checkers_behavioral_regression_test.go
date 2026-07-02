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

// Behavioral regression tests call Run() and assert finding content (audit R5/F9).
func TestCloudCheckers_RunOnEmptyCache(t *testing.T) {
	ctx := context.Background()
	all := []checker.Checker{
		&EKSIMDSAccessChecker{},
		&GKEMetadataConcealmentChecker{},
		&AKSPodIdentityChecker{},
		&ProviderDetectionChecker{},
	}
	for _, c := range all {
		c := c
		t.Run(c.Name(), func(t *testing.T) {
			findings, err := c.Run(ctx, checker.NewResourceCache())
			require.NoError(t, err)
			assert.Empty(t, findings)
			assert.NotEmpty(t, c.Description())
			assert.NotEmpty(t, c.Categories())
			assert.NotEmpty(t, c.SupportedModes())
			assert.NotEmpty(t, c.RequiredResources())
		})
	}
}

func TestCloudCheckers_BehavioralRegression(t *testing.T) {
	ctx := context.Background()

	t.Run("gke-metadata-concealment flags nodes without workload identity", func(t *testing.T) {
		c := &GKEMetadataConcealmentChecker{}
		cache := checker.NewResourceCache()
		node := makeNode(t, "gke-node", map[string]string{
			"cloud.google.com/gke-nodepool": "default-pool",
		})
		cache.Add(NodeGVR, node)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "gke-metadata-concealment", findings[0].Checker)
		assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
	})

	t.Run("eks-imds-access flags hostNetwork pods on EKS", func(t *testing.T) {
		c := &EKSIMDSAccessChecker{}
		cache := checker.NewResourceCache()
		cache.Add(NodeGVR, makeNode(t, "eks-node", map[string]string{"eks.amazonaws.com/nodegroup": "workers"}))
		dep := makeDeployment(t, "host-app", "default", corev1.PodSpec{
			HostNetwork: true,
			Containers:  []corev1.Container{{Name: "app", Image: "nginx"}},
		})
		cache.Add(workload.GVRs()[1], dep)
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "eks-imds-access", findings[0].Checker)
	})

	t.Run("provider-detection identifies GKE from node labels", func(t *testing.T) {
		c := &ProviderDetectionChecker{}
		cache := checker.NewResourceCache()
		cache.Add(NodeGVR, makeNode(t, "gke-node", map[string]string{
			"cloud.google.com/gke-nodepool": "pool",
		}))
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		assert.Equal(t, "cloud-provider-detection", findings[0].Checker)
	})
}
