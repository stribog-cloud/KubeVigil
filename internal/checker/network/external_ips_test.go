package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestExternalIPsChecker_Metadata(t *testing.T) {
	c := &ExternalIPsChecker{}

	assert.Equal(t, "external-ips", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, ServiceGVR, c.RequiredResources()[0])
}

func TestExternalIPsChecker_Run(t *testing.T) {
	c := &ExternalIPsChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		checkMessage string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "service with externalIPs triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeServiceWithExternalIPs(t, "ext-ip-svc", "default", []string{"10.0.0.1"})
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 1,
			wantResource: "ext-ip-svc",
			checkMessage: "CVE-2020-8554",
		},
		{
			name: "service with multiple externalIPs triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeServiceWithExternalIPs(t, "multi-ip-svc", "default", []string{"10.0.0.1", "10.0.0.2", "192.168.1.100"})
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 1,
			wantResource: "multi-ip-svc",
		},
		{
			name: "service without externalIPs does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "normal-svc", "default", "ClusterIP")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "LoadBalancer service without externalIPs does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "lb-svc", "default", "LoadBalancer")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "service with empty externalIPs does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeServiceWithExternalIPs(t, "empty-ip-svc", "default", []string{})
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple services with one having externalIPs triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeService(t, "normal-svc", "default", "ClusterIP"))
				cache.Add(ServiceGVR, makeServiceWithExternalIPs(t, "ext-svc", "default", []string{"10.0.0.5"}))
				return cache
			},
			wantFindings: 1,
			wantResource: "ext-svc",
		},
		{
			name: "multiple services with externalIPs trigger multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeServiceWithExternalIPs(t, "ext-1", "ns1", []string{"10.0.0.1"}))
				cache.Add(ServiceGVR, makeServiceWithExternalIPs(t, "ext-2", "ns2", []string{"10.0.0.2"}))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "fixture: failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "external-ips", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "external-ip-service",
			checkMessage: "CVE-2020-8554",
		},
		{
			name: "fixture: passing.yaml does not trigger finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "external-ips", "passing.yaml")
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
				assert.Equal(t, "external-ips", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Equal(t, "Service", findings[0].Kind)
				assert.Equal(t, ".spec.externalIPs", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.checkMessage != "" {
					assert.Contains(t, findings[0].Message, tt.checkMessage)
				}
			}
		})
	}
}

func TestExternalIPsChecker_CancelledContext(t *testing.T) {
	c := &ExternalIPsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	svc := makeServiceWithExternalIPs(t, "ext-svc", "default", []string{"10.0.0.1"})
	cache.Add(ServiceGVR, svc)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestExternalIPsChecker_MessageContainsIPs(t *testing.T) {
	c := &ExternalIPsChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	svc := makeServiceWithExternalIPs(t, "multi-ip-svc", "default", []string{"10.0.0.1", "192.168.1.100"})
	cache.Add(ServiceGVR, svc)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "10.0.0.1")
	assert.Contains(t, findings[0].Message, "192.168.1.100")
}
