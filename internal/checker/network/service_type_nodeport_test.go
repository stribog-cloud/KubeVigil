package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestServiceTypeNodePortChecker_Metadata(t *testing.T) {
	c := &ServiceTypeNodePortChecker{}

	assert.Equal(t, "service-type-nodeport", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, ServiceGVR, c.RequiredResources()[0])
}

func TestServiceTypeNodePortChecker_Run(t *testing.T) {
	c := &ServiceTypeNodePortChecker{}
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
			name: "NodePort service triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "my-nodeport-svc", "default", "NodePort")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 1,
			wantResource: "my-nodeport-svc",
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
			name: "LoadBalancer service does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "my-lb-svc", "default", "LoadBalancer")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalName service does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "my-en-svc", "default", "ExternalName")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple services with one NodePort triggers one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeService(t, "clusterip-svc", "default", "ClusterIP"))
				cache.Add(ServiceGVR, makeService(t, "nodeport-svc", "default", "NodePort"))
				cache.Add(ServiceGVR, makeService(t, "lb-svc", "default", "LoadBalancer"))
				return cache
			},
			wantFindings: 1,
			wantResource: "nodeport-svc",
		},
		{
			name: "multiple NodePort services trigger multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeService(t, "np-1", "ns1", "NodePort"))
				cache.Add(ServiceGVR, makeService(t, "np-2", "ns2", "NodePort"))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "NodePort in different namespace preserves namespace in finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				svc := makeService(t, "staging-np", "staging", "NodePort")
				cache.Add(ServiceGVR, svc)
				return cache
			},
			wantFindings: 1,
			wantResource: "staging-np",
		},
		{
			name: "fixture: failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "service-type-nodeport", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "my-nodeport-service",
		},
		{
			name: "fixture: passing.yaml does not trigger finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "service-type-nodeport", "passing.yaml")
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
				assert.Equal(t, "service-type-nodeport", findings[0].Checker)
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

func TestServiceTypeNodePortChecker_CancelledContext(t *testing.T) {
	c := &ServiceTypeNodePortChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	svc := makeService(t, "my-nodeport-svc", "default", "NodePort")
	cache.Add(ServiceGVR, svc)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestServiceTypeNodePortChecker_FindingNamespace(t *testing.T) {
	c := &ServiceTypeNodePortChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	svc := makeService(t, "staging-np", "staging", "NodePort")
	cache.Add(ServiceGVR, svc)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "staging", findings[0].Namespace)
}
