package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// makeExternalNameService builds an unstructured ExternalName Service for testing.
func makeExternalNameService(t *testing.T, name, namespace, externalName string) unstructured.Unstructured {
	t.Helper()
	svc := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: externalName,
		},
	}
	return toUnstructured(t, svc)
}

func TestServiceExternalNameDanglingChecker_Metadata(t *testing.T) {
	c := &ServiceExternalNameDanglingChecker{}

	assert.Equal(t, "service-externalname-dangling", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, ServiceGVR)
}

func TestServiceExternalNameDanglingChecker_RequiredGVRs(t *testing.T) {
	c := &ServiceExternalNameDanglingChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{ServiceGVR}
	assert.Equal(t, expected, gvrs)
}

func TestServiceExternalNameDanglingChecker_Run(t *testing.T) {
	c := &ServiceExternalNameDanglingChecker{}
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
			name: "ClusterIP service passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeService(t, "clusterip-svc", "default", "ClusterIP"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalName pointing to external domain triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "vendor-api", "default", "legacy-vendor-api.example-vendor.com"))
				return cache
			},
			wantFindings: 1,
			wantResource: "vendor-api",
		},
		{
			name: "ExternalName pointing to svc.cluster.local passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "internal-alias", "default", "backend.other-ns.svc.cluster.local"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalName pointing to bare .svc passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "bare-svc-alias", "default", "backend.other-ns.svc"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ExternalName with empty externalName passes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "empty-name", "default", ""))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "LoadBalancer service passes (not ExternalName)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeService(t, "lb-svc", "default", "LoadBalancer"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "NodePort service passes (not ExternalName)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeService(t, "np-svc", "default", "NodePort"))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple ExternalName services mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "ext-a", "ns1", "vendor-a.example.com"))
				cache.Add(ServiceGVR, makeExternalNameService(t, "ext-b", "ns2", "backend.other-ns.svc.cluster.local"))
				return cache
			},
			wantFindings: 1,
			wantResource: "ext-a",
		},
		{
			name: "multiple external ExternalName services all flagged",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "ext-c", "ns1", "vendor-c.example.com"))
				cache.Add(ServiceGVR, makeExternalNameService(t, "ext-d", "ns2", "vendor-d.example.com"))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "subdomain-only externalName still flagged",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "api-alias", "default", "api.thirdparty.io"))
				return cache
			},
			wantFindings: 1,
			wantResource: "api-alias",
		},
		{
			name: "domain containing svc substring but not internal suffix is flagged",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "tricky", "default", "myservice.example.com"))
				return cache
			},
			wantFindings: 1,
			wantResource: "tricky",
		},
		{
			name: "finding has correct severity and field path",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(ServiceGVR, makeExternalNameService(t, "check", "default", "vendor.example.com"))
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
				assert.Equal(t, "service-externalname-dangling", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "Service", findings[0].Kind)
				assert.Equal(t, ".spec.externalName", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestServiceExternalNameDanglingChecker_CancelledContext(t *testing.T) {
	c := &ServiceExternalNameDanglingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(ServiceGVR, makeService(t, "test", "default", "ClusterIP"))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestServiceExternalNameDanglingChecker_Fixtures(t *testing.T) {
	c := &ServiceExternalNameDanglingChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "service-externalname-dangling", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "service-externalname-dangling", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
