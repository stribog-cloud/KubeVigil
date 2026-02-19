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

func TestIngressWildcardHostChecker_Metadata(t *testing.T) {
	c := &IngressWildcardHostChecker{}

	assert.Equal(t, "ingress-wildcard-host", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, IngressGVR)
}

func TestIngressWildcardHostChecker_RequiredGVRs(t *testing.T) {
	c := &IngressWildcardHostChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{IngressGVR}
	assert.Equal(t, expected, gvrs)
}

func TestIngressWildcardHostChecker_Run(t *testing.T) {
	c := &IngressWildcardHostChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
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
			name: "ingress with explicit host produces no finding",
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
			wantFindings: 0,
		},
		{
			name: "ingress with empty host triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("wildcard-ing", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule(""),
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			wantResource: "wildcard-ing",
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, ".spec.rules[0].host", findings[0].FieldPath)
			},
		},
		{
			name: "ingress with star host triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("star-ing", "default", map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"host": "*",
							"http": map[string]interface{}{
								"paths": []interface{}{},
							},
						},
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			wantResource: "star-ing",
		},
		{
			name: "ingress with no rules produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("no-rules", "default", map[string]interface{}{})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ingress with mixed rules triggers only for wildcard",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("mixed-ing", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule("specific.example.com"),
						makeIngressRule(""),
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, ".spec.rules[1].host", findings[0].FieldPath)
			},
		},
		{
			name: "multiple wildcard rules in same ingress",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("multi-wild", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule(""),
						makeIngressRule(""),
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 2,
			verify: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, ".spec.rules[0].host", findings[0].FieldPath)
				assert.Equal(t, ".spec.rules[1].host", findings[1].FieldPath)
			},
		},
		{
			name: "multiple ingresses with one wildcard",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				good := makeIngress("good-ing", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule("good.example.com"),
					},
				})
				bad := makeIngress("bad-ing", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule(""),
					},
				})
				cache.Add(IngressGVR, good)
				cache.Add(IngressGVR, bad)
				return cache
			},
			wantFindings: 1,
			wantResource: "bad-ing",
		},
		{
			name: "ingress with subdomain host is not wildcard",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("subdomain-ing", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule("app.example.com"),
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
				assert.Equal(t, "ingress-wildcard-host", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "Ingress", findings[0].Kind)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}

			if tt.verify != nil {
				tt.verify(t, findings)
			}
		})
	}
}

func TestIngressWildcardHostChecker_CancelledContext(t *testing.T) {
	c := &IngressWildcardHostChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(IngressGVR, makeIngress("test", "default", map[string]interface{}{
		"rules": []interface{}{makeIngressRule("")},
	}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestIngressWildcardHostChecker_Fixtures(t *testing.T) {
	c := &IngressWildcardHostChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "ingress-wildcard-host", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "ingress-wildcard-host", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
