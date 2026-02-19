package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestPolicyMissingChecker_Metadata(t *testing.T) {
	c := &PolicyMissingChecker{}

	assert.Equal(t, "network-policy-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, NetworkPolicyGVR)
	assert.Contains(t, gvrs, NamespaceGVR)
}

func TestPolicyMissingChecker_RequiredGVRs(t *testing.T) {
	c := &PolicyMissingChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{NetworkPolicyGVR, NamespaceGVR}
	assert.Equal(t, expected, gvrs)
}

func TestPolicyMissingChecker_Run(t *testing.T) {
	c := &PolicyMissingChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantSeverity checker.Severity
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "namespace with no NetworkPolicy triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				return cache
			},
			wantFindings: 1,
			wantResource: "my-app",
			wantSeverity: checker.SeverityHigh,
		},
		{
			name: "namespace with NetworkPolicy produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-all", "my-app", "Ingress"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "system namespaces are skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("kube-system"))
				cache.Add(NamespaceGVR, makeNamespace("kube-public"))
				cache.Add(NamespaceGVR, makeNamespace("kube-node-lease"))
				cache.Add(NamespaceGVR, makeNamespace("default"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple namespaces mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("app-a"))
				cache.Add(NamespaceGVR, makeNamespace("app-b"))
				cache.Add(NamespaceGVR, makeNamespace("kube-system"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny", "app-a", "Ingress"))
				return cache
			},
			wantFindings: 1,
			wantResource: "app-b",
		},
		{
			name: "all custom namespaces with policies",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("ns1"))
				cache.Add(NamespaceGVR, makeNamespace("ns2"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny1", "ns1", "Ingress"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny2", "ns2", "Ingress"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple namespaces without policies",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("staging"))
				cache.Add(NamespaceGVR, makeNamespace("production"))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "only system namespaces in cache",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("kube-system"))
				return cache
			},
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)

			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				helpers.AssertAllFindingsHaveRequiredFields(t, findings)
				assert.Equal(t, "network-policy-missing", findings[0].Checker)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantSeverity != 0 {
					assert.Equal(t, tt.wantSeverity, findings[0].Severity)
				}
				// Kind should be Namespace for this check.
				assert.Equal(t, "Namespace", findings[0].Kind)
			}
		})
	}
}

func TestPolicyMissingChecker_CancelledContext(t *testing.T) {
	c := &PolicyMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(NamespaceGVR, makeNamespace("my-app"))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestPolicyMissingChecker_Fixtures(t *testing.T) {
	c := &PolicyMissingChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-missing", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "my-app")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-missing", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
