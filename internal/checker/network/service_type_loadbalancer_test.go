package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestServiceTypeLoadBalancerChecker_Metadata(t *testing.T) {
	c := &ServiceTypeLoadBalancerChecker{}

	assert.Equal(t, "service-type-loadbalancer", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, ServiceGVR, c.RequiredResources()[0])
}

func TestServiceTypeLoadBalancerChecker_Run(t *testing.T) {
	c := &ServiceTypeLoadBalancerChecker{}
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
			name: "LoadBalancer service triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "my-lb-svc", "default", "LoadBalancer")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 1,
			wantResource: "my-lb-svc",
		},
		{
			name: "ClusterIP service does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "my-clusterip-svc", "default", "ClusterIP")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "NodePort service does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "my-nodeport-svc", "default", "NodePort")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalName service does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "my-externalname-svc", "default", "ExternalName")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple services with one LoadBalancer triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeService(t, "clusterip-svc", "default", "ClusterIP"))
				cache.Add(ServiceGVR, makeService(t, "lb-svc", "default", "LoadBalancer"))
				cache.Add(ServiceGVR, makeService(t, "nodeport-svc", "default", "NodePort"))
				return cache
			},
			wantFindings: 1,
			wantResource: "lb-svc",
		},
		{
			name: "multiple LoadBalancer services trigger multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeService(t, "lb-1", "ns1", "LoadBalancer"))
				cache.Add(ServiceGVR, makeService(t, "lb-2", "ns2", "LoadBalancer"))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "LoadBalancer in different namespace preserves namespace in finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "prod-lb", "production", "LoadBalancer")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 1,
			wantResource: "prod-lb",
		},
		{
			name: "fixture: failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "service-type-loadbalancer", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "my-lb-service",
		},
		{
			name: "fixture: passing.yaml does not trigger finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "service-type-loadbalancer", "passing.yaml")
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
				assert.Equal(t, "service-type-loadbalancer", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "Service", findings[0].Kind)
				assert.Equal(t, ".spec.type", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestServiceTypeLoadBalancerChecker_CancelledContext(t *testing.T) {
	c := &ServiceTypeLoadBalancerChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	svc := makeService(t, "my-lb-svc", "default", "LoadBalancer")
	cache.Add(ServiceGVR, svc)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestServiceTypeLoadBalancerChecker_FindingNamespace(t *testing.T) {
	c := &ServiceTypeLoadBalancerChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	svc := makeService(t, "prod-lb", "production", "LoadBalancer")
	cache.Add(ServiceGVR, svc)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "production", findings[0].Namespace)
}
