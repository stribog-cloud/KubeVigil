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

func TestDefaultDenyChecker_Metadata(t *testing.T) {
	c := &DefaultDenyChecker{}

	assert.Equal(t, "network-policy-default-deny", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, NetworkPolicyGVR)
	assert.Contains(t, gvrs, NamespaceGVR)
}

func TestDefaultDenyChecker_RequiredGVRs(t *testing.T) {
	c := &DefaultDenyChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{NetworkPolicyGVR, NamespaceGVR}
	assert.Equal(t, expected, gvrs)
}

func TestDefaultDenyChecker_Run(t *testing.T) {
	c := &DefaultDenyChecker{}
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
			name: "namespace with no policies is skipped (handled by policy-missing)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace with default-deny ingress and egress produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("secure-app"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-all", "secure-app", "Ingress", "Egress"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace with only ingress deny triggers egress finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("partial-deny"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-ingress", "partial-deny", "Ingress"))
				return cache
			},
			wantFindings: 1,
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Contains(t, findings[0].Message, "egress")
			},
		},
		{
			name: "namespace with only egress deny triggers ingress finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("partial-deny"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-egress", "partial-deny", "Egress"))
				return cache
			},
			wantFindings: 1,
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Contains(t, findings[0].Message, "ingress")
			},
		},
		{
			name: "namespace with non-deny policies triggers both findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				// A policy that selects specific pods (not empty selector) with ingress rules.
				pol := makeNetworkPolicy("allow-web", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{"app": "web"},
					},
					"policyTypes": []interface{}{"Ingress"},
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{"podSelector": map[string]interface{}{}},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "default-deny with ingress rules is NOT a default deny",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				pol := makeNetworkPolicy("not-deny", "my-app", map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{"podSelector": map[string]interface{}{}},
							},
						},
					},
				})
				cache.Add(NetworkPolicyGVR, pol)
				return cache
			},
			wantFindings: 2,
			verify: func(t *testing.T, findings []checker.Finding) {
				// Should report both missing ingress and egress default deny.
				messages := make([]string, len(findings))
				for i, f := range findings {
					messages[i] = f.Message
				}
				hasIngress := false
				hasEgress := false
				for _, m := range messages {
					if len(m) > 0 {
						if contains(m, "ingress") {
							hasIngress = true
						}
						if contains(m, "egress") {
							hasEgress = true
						}
					}
				}
				assert.True(t, hasIngress, "expected finding about missing ingress deny")
				assert.True(t, hasEgress, "expected finding about missing egress deny")
			},
		},
		{
			name: "system namespaces are skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("kube-system"))
				cache.Add(NetworkPolicyGVR, makeNetworkPolicy("some-policy", "kube-system", map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{"app": "dns"},
					},
					"policyTypes": []interface{}{"Ingress"},
				}))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "separate default-deny ingress and egress policies",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("my-app"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-ingress", "my-app", "Ingress"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-egress", "my-app", "Egress"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple namespaces with mixed coverage",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace("secure"))
				cache.Add(NamespaceGVR, makeNamespace("partial"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-all", "secure", "Ingress", "Egress"))
				cache.Add(NetworkPolicyGVR, makeDefaultDenyPolicy("deny-ingress", "partial", "Ingress"))
				return cache
			},
			wantFindings: 1,
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "partial", findings[0].Namespace)
				assert.Contains(t, findings[0].Message, "egress")
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
				assert.Equal(t, "network-policy-default-deny", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Equal(t, "Namespace", findings[0].Kind)
			}

			if tt.verify != nil {
				tt.verify(t, findings)
			}
		})
	}
}

func TestDefaultDenyChecker_CancelledContext(t *testing.T) {
	c := &DefaultDenyChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(NamespaceGVR, makeNamespace("my-app"))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestDefaultDenyChecker_Fixtures(t *testing.T) {
	c := &DefaultDenyChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-default-deny", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "network-policy-default-deny", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

// contains checks if a string contains a substring (used for message verification).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
