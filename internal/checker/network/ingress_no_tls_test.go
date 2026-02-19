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

func TestIngressNoTLSChecker_Metadata(t *testing.T) {
	c := &IngressNoTLSChecker{}

	assert.Equal(t, "ingress-no-tls", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, IngressGVR)
}

func TestIngressNoTLSChecker_RequiredGVRs(t *testing.T) {
	c := &IngressNoTLSChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{IngressGVR}
	assert.Equal(t, expected, gvrs)
}

func TestIngressNoTLSChecker_Run(t *testing.T) {
	c := &IngressNoTLSChecker{}
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
			name: "ingress without TLS triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("my-ingress", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule("example.com"),
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			wantResource: "my-ingress",
		},
		{
			name: "ingress with TLS produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("secure-ingress", "default", map[string]interface{}{
					"tls": []interface{}{
						makeIngressTLS([]string{"example.com"}, "tls-secret"),
					},
					"rules": []interface{}{
						makeIngressRule("example.com"),
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ingress with empty TLS list triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("empty-tls", "default", map[string]interface{}{
					"tls": []interface{}{},
					"rules": []interface{}{
						makeIngressRule("example.com"),
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			wantResource: "empty-tls",
		},
		{
			name: "multiple ingresses mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				secure := makeIngress("secure", "default", map[string]interface{}{
					"tls": []interface{}{
						makeIngressTLS([]string{"secure.example.com"}, "tls-secret"),
					},
					"rules": []interface{}{
						makeIngressRule("secure.example.com"),
					},
				})
				insecure := makeIngress("insecure", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule("insecure.example.com"),
					},
				})
				cache.Add(IngressGVR, secure)
				cache.Add(IngressGVR, insecure)
				return cache
			},
			wantFindings: 1,
			wantResource: "insecure",
		},
		{
			name: "ingress with no spec fields",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("minimal", "default", map[string]interface{}{})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			wantResource: "minimal",
		},
		{
			name: "multiple insecure ingresses",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(IngressGVR, makeIngress("ing-a", "ns1", map[string]interface{}{
					"rules": []interface{}{makeIngressRule("a.example.com")},
				}))
				cache.Add(IngressGVR, makeIngress("ing-b", "ns2", map[string]interface{}{
					"rules": []interface{}{makeIngressRule("b.example.com")},
				}))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "finding has correct severity and field path",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(IngressGVR, makeIngress("test-ing", "default", map[string]interface{}{
					"rules": []interface{}{makeIngressRule("test.example.com")},
				}))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ingress with multiple TLS entries",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("multi-tls", "default", map[string]interface{}{
					"tls": []interface{}{
						makeIngressTLS([]string{"a.example.com"}, "tls-a"),
						makeIngressTLS([]string{"b.example.com"}, "tls-b"),
					},
					"rules": []interface{}{
						makeIngressRule("a.example.com"),
						makeIngressRule("b.example.com"),
					},
				})
				cache.Add(IngressGVR, ing)
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
				assert.Equal(t, "ingress-no-tls", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Equal(t, "Ingress", findings[0].Kind)
				assert.Equal(t, ".spec.tls", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestIngressNoTLSChecker_CancelledContext(t *testing.T) {
	c := &IngressNoTLSChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(IngressGVR, makeIngress("test", "default", map[string]interface{}{}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestIngressNoTLSChecker_Fixtures(t *testing.T) {
	c := &IngressNoTLSChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "ingress-no-tls", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "ingress-no-tls", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
