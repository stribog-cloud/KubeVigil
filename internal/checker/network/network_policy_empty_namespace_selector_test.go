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

func TestEmptyNamespaceSelectorChecker_Metadata(t *testing.T) {
	c := &EmptyNamespaceSelectorChecker{}

	assert.Equal(t, "network-policy-empty-namespace-selector", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, NetworkPolicyGVR)
}

func TestEmptyNamespaceSelectorChecker_RequiredGVRs(t *testing.T) {
	c := &EmptyNamespaceSelectorChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{NetworkPolicyGVR}
	assert.Equal(t, expected, gvrs)
}

func TestEmptyNamespaceSelectorChecker_Run(t *testing.T) {
	c := &EmptyNamespaceSelectorChecker{}
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
			name: "scoped namespaceSelector on ingress passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("scoped", "default", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"namespaceSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{"team": "checkout"},
									},
								},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty namespaceSelector on ingress triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("empty-ingress", "default", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{"namespaceSelector": map[string]interface{}{}},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
			wantResource: "empty-ingress",
		},
		{
			name: "empty namespaceSelector on egress triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("empty-egress", "default", map[string]interface{}{
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{"namespaceSelector": map[string]interface{}{}},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
			wantResource: "empty-egress",
		},
		{
			name: "empty namespaceSelector on both ingress and egress triggers two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("both-empty", "default", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{"namespaceSelector": map[string]interface{}{}},
							},
						},
					},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{"namespaceSelector": map[string]interface{}{}},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 2,
			wantResource: "both-empty",
		},
		{
			name: "podSelector-only peer passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("pod-only", "default", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"podSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{"app": "frontend"},
									},
								},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ipBlock peer passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("ipblock-only", "default", map[string]interface{}{
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{"cidr": "10.0.0.0/8"},
								},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no ingress or egress rules passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("no-rules", "default", map[string]interface{}{
					"podSelector": map[string]interface{}{},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "empty namespaceSelector among multiple peers triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("mixed-peers", "default", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"podSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"app": "x"}},
								},
								map[string]interface{}{"namespaceSelector": map[string]interface{}{}},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
			wantResource: "mixed-peers",
		},
		{
			name: "multiple ingress rules one with empty selector",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("multi-rule", "default", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"namespaceSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"team": "a"}},
								},
							},
						},
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{"namespaceSelector": map[string]interface{}{}},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
			wantResource: "multi-rule",
		},
		{
			name: "multiple policies mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NetworkPolicyGVR, makeNetworkPolicy("good", "ns1", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{"namespaceSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"team": "a"}}},
							},
						},
					},
				}))
				cache.Add(NetworkPolicyGVR, makeNetworkPolicy("bad", "ns2", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{"namespaceSelector": map[string]interface{}{}},
							},
						},
					},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "bad",
		},
		{
			name: "non-map peer entry is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("bad-peer", "default", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{"from": []interface{}{"not-a-map"}},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "finding has correct severity and field path",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("check", "default", map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{"namespaceSelector": map[string]interface{}{}},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
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
				assert.Equal(t, "network-policy-empty-namespace-selector", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "NetworkPolicy", findings[0].Kind)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestEmptyNamespaceSelectorChecker_CancelledContext(t *testing.T) {
	c := &EmptyNamespaceSelectorChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(NetworkPolicyGVR, makeNetworkPolicy("test", "default", map[string]interface{}{}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestEmptyNamespaceSelectorChecker_Fixtures(t *testing.T) {
	c := &EmptyNamespaceSelectorChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-empty-namespace-selector", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-empty-namespace-selector", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
