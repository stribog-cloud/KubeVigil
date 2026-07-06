package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestMetadataServiceEgressChecker_Metadata(t *testing.T) {
	c := &MetadataServiceEgressChecker{}

	assert.Equal(t, "metadata-service-egress-unblocked", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, NetworkPolicyGVR)
	assert.Contains(t, gvrs, NamespaceGVR)
	for _, gvr := range workload.GVRs() {
		assert.Contains(t, gvrs, gvr)
	}
}

func TestMetadataServiceEgressChecker_RequiredGVRs(t *testing.T) {
	c := &MetadataServiceEgressChecker{}
	gvrs := c.RequiredResources()
	expected := append([]schema.GroupVersionResource{NetworkPolicyGVR, NamespaceGVR}, workload.GVRs()...)
	assert.Equal(t, expected, gvrs)
}

// deploymentGVR is the GVR used to add test Deployment fixtures to the cache.
var deploymentGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

func TestMetadataServiceEgressChecker_Run(t *testing.T) {
	c := &MetadataServiceEgressChecker{}
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
			name: "namespace with no workloads produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("empty-ns"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace with only hostNetwork workload produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("hostnet-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "hostnet-ns", true))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace with workload and no NetworkPolicy triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				cache.Add(deploymentGVR, makeDeployment("app", "my-app", false))
				return cache
			},
			wantFindings: 1,
			wantResource: "my-app",
		},
		{
			name: "namespace with default-deny egress policy passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("protected-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "protected-ns", false))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-egress", "protected-ns", "Egress"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "NetworkPolicy without Egress policyType does not protect",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("ingress-only-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "ingress-only-ns", false))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-ingress", "ingress-only-ns", "Ingress"))
				return cache
			},
			wantFindings: 1,
			wantResource: "ingress-only-ns",
		},
		{
			name: "Egress policy with no 'to' restriction on a rule does not protect",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("open-egress-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "open-egress-ns", false))
				pol := makeNetworkPolicy("allow-all-egress", "open-egress-ns", map[string]interface{}{
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
			wantResource: "open-egress-ns",
		},
		{
			name: "Egress policy with 0.0.0.0/0 and no except does not protect",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("open-cidr-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "open-cidr-ns", false))
				pol := makeNetworkPolicy("egress-open-cidr", "open-cidr-ns", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{"cidr": "0.0.0.0/0"},
								},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
			wantResource: "open-cidr-ns",
		},
		{
			name: "Egress policy with 0.0.0.0/0 and metadata IP excepted passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("excepted-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "excepted-ns", false))
				pol := makeNetworkPolicy("egress-excepted", "excepted-ns", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr":   "0.0.0.0/0",
										"except": []interface{}{"169.254.169.254/32"},
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
			name: "Egress policy scoped to unrelated CIDR passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("scoped-cidr-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "scoped-cidr-ns", false))
				pol := makeNetworkPolicy("egress-scoped", "scoped-cidr-ns", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
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
			name: "Egress policy with only podSelector/namespaceSelector peers passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("peer-selector-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "peer-selector-ns", false))
				pol := makeNetworkPolicy("egress-peer-selector", "peer-selector-ns", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"namespaceSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"team": "db"}},
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
			name: "Egress policy with non-empty podSelector does not count as namespace-wide protection",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("scoped-pod-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "scoped-pod-ns", false))
				pol := makeNetworkPolicy("egress-scoped-pod", "scoped-pod-ns", map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{"app": "only-this-one"},
					},
					"policyTypes": []interface{}{"Egress"},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 1,
			wantResource: "scoped-pod-ns",
		},
		{
			name: "system namespace is excluded even without protection",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("kube-system"))
				cache.Add(deploymentGVR, makeDeployment("app", "kube-system", false))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "malformed CIDR in ipBlock does not grant metadata access",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("malformed-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "malformed-ns", false))
				pol := makeNetworkPolicy("egress-malformed", "malformed-ns", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{"cidr": "not-a-cidr"},
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
			name: "policy in a different namespace does not protect",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("ns-a"))
				cache.Add(NamespaceGVR, makeNamespace("ns-b"))
				cache.Add(deploymentGVR, makeDeployment("app", "ns-a", false))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-egress", "ns-b", "Egress"))
				return cache
			},
			wantFindings: 1,
			wantResource: "ns-a",
		},
		{
			name: "multiple namespaces mixed protection",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("protected"))
				cache.Add(NamespaceGVR, makeNamespace("unprotected"))
				cache.Add(deploymentGVR, makeDeployment("app", "protected", false))
				cache.Add(deploymentGVR, makeDeployment("app", "unprotected", false))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-egress", "protected", "Egress"))
				return cache
			},
			wantFindings: 1,
			wantResource: "unprotected",
		},
		{
			name: "finding has correct severity and kind",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("check-ns"))
				cache.Add(deploymentGVR, makeDeployment("app", "check-ns", false))
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
				assert.Equal(t, "metadata-service-egress-unblocked", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Equal(t, "Namespace", findings[0].Kind)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestMetadataServiceEgressChecker_CancelledContext(t *testing.T) {
	c := &MetadataServiceEgressChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(NamespaceGVR, makeNamespace("test"))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestMetadataServiceEgressChecker_Fixtures(t *testing.T) {
	c := &MetadataServiceEgressChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "metadata-service-egress-unblocked", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "metadata-service-egress-unblocked", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
