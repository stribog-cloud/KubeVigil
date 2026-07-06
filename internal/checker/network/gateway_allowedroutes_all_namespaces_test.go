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

func TestGatewayAllowedRoutesAllNamespacesChecker_Metadata(t *testing.T) {
	c := &GatewayAllowedRoutesAllNamespacesChecker{}

	assert.Equal(t, "gateway-allowedroutes-all-namespaces", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, GatewayGVR)
}

func TestGatewayAllowedRoutesAllNamespacesChecker_RequiredGVRs(t *testing.T) {
	c := &GatewayAllowedRoutesAllNamespacesChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{GatewayGVR}
	assert.Equal(t, expected, gvrs)
}

func listenerWithAllowedRoutesFrom(from string) map[string]interface{} {
	l := map[string]interface{}{"name": "https", "protocol": "HTTPS", "port": int64(443)}
	if from != "" {
		l["allowedRoutes"] = map[string]interface{}{
			"namespaces": map[string]interface{}{"from": from},
		}
	}
	return l
}

func TestGatewayAllowedRoutesAllNamespacesChecker_Run(t *testing.T) {
	c := &GatewayAllowedRoutesAllNamespacesChecker{}
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
			name: "allowedRoutes from All triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw", "default", map[string]interface{}{
					"listeners": []interface{}{listenerWithAllowedRoutesFrom("All")},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 1,
			wantResource: "gw",
		},
		{
			name: "allowedRoutes from Same passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-same", "default", map[string]interface{}{
					"listeners": []interface{}{listenerWithAllowedRoutesFrom("Same")},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "allowedRoutes from Selector passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-selector", "default", map[string]interface{}{
					"listeners": []interface{}{listenerWithAllowedRoutesFrom("Selector")},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "listener with no allowedRoutes passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-none", "default", map[string]interface{}{
					"listeners": []interface{}{listenerWithAllowedRoutesFrom("")},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple listeners mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-mixed", "default", map[string]interface{}{
					"listeners": []interface{}{
						listenerWithAllowedRoutesFrom("All"),
						listenerWithAllowedRoutesFrom("Same"),
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 1,
			wantResource: "gw-mixed",
		},
		{
			name: "multiple listeners all All triggers multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-double", "default", map[string]interface{}{
					"listeners": []interface{}{
						listenerWithAllowedRoutesFrom("All"),
						listenerWithAllowedRoutesFrom("All"),
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 2,
			wantResource: "gw-double",
		},
		{
			name: "gateway with no listeners produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(GatewayGVR, makeGateway("gw-empty", "default", map[string]interface{}{}))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "gateway with no spec produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(GatewayGVR, makeGateway("gw-nospec", "default", nil))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple gateways",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(GatewayGVR, makeGateway("gw-a", "ns1", map[string]interface{}{
					"listeners": []interface{}{listenerWithAllowedRoutesFrom("All")},
				}))
				cache.Add(GatewayGVR, makeGateway("gw-b", "ns2", map[string]interface{}{
					"listeners": []interface{}{listenerWithAllowedRoutesFrom("Same")},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "gw-a",
		},
		{
			name: "non-listener entry in list is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-bad-entry", "default", map[string]interface{}{
					"listeners": []interface{}{"not-a-map"},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "lowercase all does not match",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-lowercase", "default", map[string]interface{}{
					"listeners": []interface{}{listenerWithAllowedRoutesFrom("all")},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "finding has correct severity and field path",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-check", "default", map[string]interface{}{
					"listeners": []interface{}{listenerWithAllowedRoutesFrom("All")},
				})
				cache.Add(GatewayGVR, gw)
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
				assert.Equal(t, "gateway-allowedroutes-all-namespaces", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "Gateway", findings[0].Kind)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestGatewayAllowedRoutesAllNamespacesChecker_CancelledContext(t *testing.T) {
	c := &GatewayAllowedRoutesAllNamespacesChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(GatewayGVR, makeGateway("test", "default", map[string]interface{}{}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestGatewayAllowedRoutesAllNamespacesChecker_Fixtures(t *testing.T) {
	c := &GatewayAllowedRoutesAllNamespacesChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "gateway-allowedroutes-all-namespaces", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "gateway-allowedroutes-all-namespaces", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
