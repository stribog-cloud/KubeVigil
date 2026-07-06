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

func TestHTTPRouteWildcardHostnameChecker_Metadata(t *testing.T) {
	c := &HTTPRouteWildcardHostnameChecker{}

	assert.Equal(t, "httproute-wildcard-hostname", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, HTTPRouteGVR)
}

func TestHTTPRouteWildcardHostnameChecker_RequiredGVRs(t *testing.T) {
	c := &HTTPRouteWildcardHostnameChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{HTTPRouteGVR}
	assert.Equal(t, expected, gvrs)
}

func TestHTTPRouteWildcardHostnameChecker_Run(t *testing.T) {
	c := &HTTPRouteWildcardHostnameChecker{}
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
			name: "explicit hostname passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route", "default", map[string]interface{}{
					"hostnames": []interface{}{"app.example.com"},
				}))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "wildcard hostname triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-wild", "default", map[string]interface{}{
					"hostnames": []interface{}{"*.example.com"},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "route-wild",
		},
		{
			name: "bare star hostname triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-star", "default", map[string]interface{}{
					"hostnames": []interface{}{"*"},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "route-star",
		},
		{
			name: "empty hostnames list triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-empty", "default", map[string]interface{}{
					"hostnames": []interface{}{},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "route-empty",
		},
		{
			name: "absent hostnames field triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-absent", "default", map[string]interface{}{}))
				return cache
			},
			wantFindings: 1,
			wantResource: "route-absent",
		},
		{
			name: "multiple explicit hostnames pass",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-multi", "default", map[string]interface{}{
					"hostnames": []interface{}{"a.example.com", "b.example.com"},
				}))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "one wildcard among explicit hostnames triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-mixed", "default", map[string]interface{}{
					"hostnames": []interface{}{"a.example.com", "*.example.com"},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "route-mixed",
		},
		{
			name: "multiple routes mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("ok-route", "ns1", map[string]interface{}{
					"hostnames": []interface{}{"ok.example.com"},
				}))
				cache.Add(HTTPRouteGVR, makeHTTPRoute("bad-route", "ns2", map[string]interface{}{
					"hostnames": []interface{}{"*.example.com"},
				}))
				return cache
			},
			wantFindings: 1,
			wantResource: "bad-route",
		},
		{
			name: "multiple wildcard routes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-a", "ns1", map[string]interface{}{}))
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-b", "ns2", map[string]interface{}{}))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "hostname resembling wildcard but not prefixed passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-starred-mid", "default", map[string]interface{}{
					"hostnames": []interface{}{"app.example.com"},
				}))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "finding has correct severity and field path",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(HTTPRouteGVR, makeHTTPRoute("route-check", "default", map[string]interface{}{
					"hostnames": []interface{}{"*"},
				}))
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
				assert.Equal(t, "httproute-wildcard-hostname", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "HTTPRoute", findings[0].Kind)
				assert.Equal(t, ".spec.hostnames", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestHTTPRouteWildcardHostnameChecker_CancelledContext(t *testing.T) {
	c := &HTTPRouteWildcardHostnameChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(HTTPRouteGVR, makeHTTPRoute("test", "default", map[string]interface{}{}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestHTTPRouteWildcardHostnameChecker_Fixtures(t *testing.T) {
	c := &HTTPRouteWildcardHostnameChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "httproute-wildcard-hostname", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "httproute-wildcard-hostname", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
