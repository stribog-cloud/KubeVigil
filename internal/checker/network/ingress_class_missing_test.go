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

func TestIngressClassMissingChecker_Metadata(t *testing.T) {
	c := &IngressClassMissingChecker{}

	assert.Equal(t, "ingress-class-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)

	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, IngressGVR)
}

func TestIngressClassMissingChecker_RequiredGVRs(t *testing.T) {
	c := &IngressClassMissingChecker{}
	gvrs := c.RequiredResources()
	expected := []schema.GroupVersionResource{IngressGVR}
	assert.Equal(t, expected, gvrs)
}

func TestIngressClassMissingChecker_Run(t *testing.T) {
	c := &IngressClassMissingChecker{}
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
			name: "ingress without ingressClassName or annotation triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("no-class", "default", map[string]interface{}{
					"rules": []interface{}{
						makeIngressRule("example.com"),
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			wantResource: "no-class",
		},
		{
			name: "ingress with ingressClassName produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("with-class", "default", map[string]interface{}{
					"ingressClassName": "nginx",
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
			name: "ingress with deprecated annotation produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngressWithAnnotations("with-annotation", "default",
					map[string]string{
						"kubernetes.io/ingress.class": "nginx",
					},
					map[string]interface{}{
						"rules": []interface{}{
							makeIngressRule("example.com"),
						},
					},
				)
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ingress with empty ingressClassName triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngress("empty-class", "default", map[string]interface{}{
					"ingressClassName": "",
					"rules": []interface{}{
						makeIngressRule("example.com"),
					},
				})
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			wantResource: "empty-class",
		},
		{
			name: "ingress with empty annotation value triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngressWithAnnotations("empty-ann", "default",
					map[string]string{
						"kubernetes.io/ingress.class": "",
					},
					map[string]interface{}{
						"rules": []interface{}{
							makeIngressRule("example.com"),
						},
					},
				)
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 1,
			wantResource: "empty-ann",
		},
		{
			name: "multiple ingresses mixed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				good := makeIngress("with-class", "default", map[string]interface{}{
					"ingressClassName": "nginx",
					"rules":            []interface{}{makeIngressRule("good.example.com")},
				})
				bad := makeIngress("no-class", "default", map[string]interface{}{
					"rules": []interface{}{makeIngressRule("bad.example.com")},
				})
				cache.Add(IngressGVR, good)
				cache.Add(IngressGVR, bad)
				return cache
			},
			wantFindings: 1,
			wantResource: "no-class",
		},
		{
			name: "ingress with both className and annotation produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ing := makeIngressWithAnnotations("both", "default",
					map[string]string{
						"kubernetes.io/ingress.class": "nginx",
					},
					map[string]interface{}{
						"ingressClassName": "nginx",
						"rules":            []interface{}{makeIngressRule("example.com")},
					},
				)
				cache.Add(IngressGVR, ing)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "finding has correct severity and field path",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(IngressGVR, makeIngress("test", "default", map[string]interface{}{}))
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
				assert.Equal(t, "ingress-class-missing", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				assert.Equal(t, "Ingress", findings[0].Kind)
				assert.Equal(t, ".spec.ingressClassName", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestIngressClassMissingChecker_CancelledContext(t *testing.T) {
	c := &IngressClassMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cache.Add(IngressGVR, makeIngress("test", "default", map[string]interface{}{}))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestIngressClassMissingChecker_Fixtures(t *testing.T) {
	c := &IngressClassMissingChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "ingress-class-missing", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "ingress-class-missing", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
