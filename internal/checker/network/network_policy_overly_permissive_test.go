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

func TestOverlyPermissiveChecker_Metadata(t *testing.T) {
	c := &OverlyPermissiveChecker{}

	assert.Equal(t, "network-policy-overly-permissive", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, NetworkPolicyGVR)
}

func TestOverlyPermissiveChecker_RequiredGVRs(t *testing.T) {
	c := &OverlyPermissiveChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{NetworkPolicyGVR}
	assert.Equal(t, expected, gvrs)
}

func TestOverlyPermissiveChecker_Run(t *testing.T) {
	c := &OverlyPermissiveChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		verify       func(t *testing.T, findings []checker.Finding)
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "default deny policy produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-all", "my-app", "Ingress", "Egress"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ingress with empty from triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("allow-all-ingress", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
					"ingress": []interface{}{
						map[string]interface{}{},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, ".spec.ingress", findings[0].FieldPath)
				assert.Contains(t, findings[0].Message, "ingress")
			},
		},
		{
			name: "egress with empty to triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("allow-all-egress", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, ".spec.egress", findings[0].FieldPath)
				assert.Contains(t, findings[0].Message, "egress")
			},
		},
		{
			name: "ingress with 0.0.0.0/0 CIDR triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("wide-cidr", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr": "0.0.0.0/0",
									},
								},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ingress with 0.0.0.0/0 CIDR and except does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("cidr-with-except", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr":   "0.0.0.0/0",
										"except": []interface{}{"10.0.0.0/8"},
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
			name: "restricted policy with specific podSelector and from produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("restricted", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"podSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{"role": "frontend"},
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
			name: "both ingress and egress overly permissive triggers two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("allow-all", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress", "Egress"},
					"ingress": []interface{}{
						map[string]interface{}{},
					},
					"egress": []interface{}{
						map[string]interface{}{},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "egress with 0.0.0.0/0 CIDR without except triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pol := makeNetworkPolicy("wide-egress", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr": "0.0.0.0/0",
									},
								},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "multiple policies only some permissive",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				good := makeNetworkPolicy("restrictive", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"podSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{"app": "web"},
									},
								},
							},
						},
					},
				})
				bad := makeNetworkPolicy("wide-open", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{},
					},
				})
				cache.Add(NetworkPolicyGVR, good)
				cache.Add(NetworkPolicyGVR, bad)
				return cache
			},
			wantFindings: 1,
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "wide-open", findings[0].Resource)
			},
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
				assert.Equal(t, "network-policy-overly-permissive", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "NetworkPolicy", findings[0].Kind)
			}

			if tt.verify != nil {
				tt.verify(t, findings)
			}
		})
	}
}

func TestOverlyPermissiveChecker_CancelledContext(t *testing.T) {
	c := &OverlyPermissiveChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("test", "my-app", "Ingress"))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestOverlyPermissiveChecker_Fixtures(t *testing.T) {
	c := &OverlyPermissiveChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-overly-permissive", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-overly-permissive", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
