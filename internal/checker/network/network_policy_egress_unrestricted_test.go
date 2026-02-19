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

func TestEgressUnrestrictedChecker_Metadata(t *testing.T) {
	c := &EgressUnrestrictedChecker{}

	assert.Equal(t, "network-policy-egress-unrestricted", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, NetworkPolicyGVR)
	assert.Contains(t, gvrs, NamespaceGVR)
}

func TestEgressUnrestrictedChecker_RequiredGVRs(t *testing.T) {
	c := &EgressUnrestrictedChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{NetworkPolicyGVR, NamespaceGVR}
	assert.Equal(t, expected, gvrs)
}

func TestEgressUnrestrictedChecker_Run(t *testing.T) {
	c := &EgressUnrestrictedChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "namespace without any policies triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				return cache
			},
			wantFindings: 1,
			wantResource: "my-app",
		},
		{
			name: "namespace with only ingress policy triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-ingress", "my-app", "Ingress"))
				return cache
			},
			wantFindings: 1,
			wantResource: "my-app",
		},
		{
			name: "namespace with egress policy produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-egress", "my-app", "Egress"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace with ingress and egress policy produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-all", "my-app", "Ingress", "Egress"))
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
				cache.Add(NamespaceGVR, makeNamespace("default"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple namespaces mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("secure"))
				cache.Add(NamespaceGVR, makeNamespace("insecure"))
				cache.Add(NamespaceGVR, makeNamespace("kube-system"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-all", "secure", "Ingress", "Egress"))
				return cache
			},
			wantFindings: 1,
			wantResource: "insecure",
		},
		{
			name: "namespace with non-empty egress policy type in one of multiple policies",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("ingress-only", "my-app", "Ingress"))
				cache.Add(NetworkPolicyGVR, makeNetworkPolicy("egress-restrict", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{"app": "web"},
					},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"podSelector": map[string]interface{}{},
								},
							},
						},
					},
				}))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "all namespaces unrestricted",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("staging"))
				cache.Add(NamespaceGVR, makeNamespace("production"))
				return cache
			},
			wantFindings: 2,
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
				assert.Equal(t, "network-policy-egress-unrestricted", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "Namespace", findings[0].Kind)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestEgressUnrestrictedChecker_CancelledContext(t *testing.T) {
	c := &EgressUnrestrictedChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(NamespaceGVR, makeNamespace("my-app"))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestEgressUnrestrictedChecker_Fixtures(t *testing.T) {
	c := &EgressUnrestrictedChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-egress-unrestricted", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-egress-unrestricted", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
