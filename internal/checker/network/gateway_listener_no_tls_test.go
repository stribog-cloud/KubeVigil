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

func TestGatewayListenerNoTLSChecker_Metadata(t *testing.T) {
	c := &GatewayListenerNoTLSChecker{}

	assert.Equal(t, "gateway-listener-no-tls", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, GatewayGVR)
}

func TestGatewayListenerNoTLSChecker_RequiredGVRs(t *testing.T) {
	c := &GatewayListenerNoTLSChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{GatewayGVR}
	assert.Equal(t, expected, gvrs)
}

func TestGatewayListenerNoTLSChecker_Run(t *testing.T) {
	c := &GatewayListenerNoTLSChecker{}
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
			name: "HTTP listener triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{"name": "http", "protocol": "HTTP", "port": int64(80)},
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 1,
			wantResource: "gw",
		},
		{
			name: "HTTPS Terminate with certificateRefs passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-secure", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{
							"name":     "https",
							"protocol": "HTTPS",
							"port":     int64(443),
							"tls": map[string]interface{}{
								"mode": "Terminate",
								"certificateRefs": []interface{}{
									map[string]interface{}{"name": "gw-tls-cert"},
								},
							},
						},
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "HTTPS Terminate with no tls block triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-notls", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{"name": "https", "protocol": "HTTPS", "port": int64(443)},
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 1,
			wantResource: "gw-notls",
		},
		{
			name: "HTTPS Terminate with empty certificateRefs triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-empty-refs", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{
							"name":     "https",
							"protocol": "HTTPS",
							"port":     int64(443),
							"tls": map[string]interface{}{
								"mode":            "Terminate",
								"certificateRefs": []interface{}{},
							},
						},
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 1,
			wantResource: "gw-empty-refs",
		},
		{
			name: "TLS protocol Passthrough mode with no certs passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-passthrough", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{
							"name":     "tls-passthrough",
							"protocol": "TLS",
							"port":     int64(443),
							"tls": map[string]interface{}{
								"mode": "Passthrough",
							},
						},
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "TLS protocol Terminate mode with no certs triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-tls-terminate", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{
							"name":     "tls",
							"protocol": "TLS",
							"port":     int64(443),
							"tls": map[string]interface{}{
								"mode": "Terminate",
							},
						},
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 1,
			wantResource: "gw-tls-terminate",
		},
		{
			name: "multiple listeners mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-mixed", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{"name": "http", "protocol": "HTTP", "port": int64(80)},
						map[string]interface{}{
							"name":     "https",
							"protocol": "HTTPS",
							"port":     int64(443),
							"tls": map[string]interface{}{
								"mode": "Terminate",
								"certificateRefs": []interface{}{
									map[string]interface{}{"name": "cert"},
								},
							},
						},
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 1,
			wantResource: "gw-mixed",
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
			name: "multiple gateways with HTTP listeners",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(GatewayGVR, makeGateway("gw-a", "ns1", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{"name": "http", "protocol": "HTTP", "port": int64(80)},
					},
				}))
				cache.Add(GatewayGVR, makeGateway("gw-b", "ns2", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{"name": "http", "protocol": "HTTP", "port": int64(80)},
					},
				}))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "HTTPS Terminate mode default (mode omitted) with no certs triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-default-mode", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{
							"name":     "https",
							"protocol": "HTTPS",
							"port":     int64(443),
							"tls":      map[string]interface{}{},
						},
					},
				})
				cache.Add(GatewayGVR, gw)
				return cache
			},
			wantFindings: 1,
			wantResource: "gw-default-mode",
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
			name: "finding has correct severity and field path",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				gw := makeGateway("gw-check", "default", map[string]interface{}{
					"listeners": []interface{}{
						map[string]interface{}{"name": "http", "protocol": "HTTP", "port": int64(80)},
					},
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
				assert.Equal(t, "gateway-listener-no-tls", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Equal(t, "Gateway", findings[0].Kind)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestGatewayListenerNoTLSChecker_CancelledContext(t *testing.T) {
	c := &GatewayListenerNoTLSChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(GatewayGVR, makeGateway("test", "default", map[string]interface{}{}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestGatewayListenerNoTLSChecker_Fixtures(t *testing.T) {
	c := &GatewayListenerNoTLSChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "gateway-listener-no-tls", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "gateway-listener-no-tls", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
