package psa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestLabelsMissingChecker_Metadata(t *testing.T) {
	c := &LabelsMissingChecker{}

	assert.Equal(t, "psa-labels-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryPSS)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), NamespaceGVR)
}

func TestLabelsMissingChecker_Run(t *testing.T) {
	c := &LabelsMissingChecker{}
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
			name: "namespace with enforce label produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "my-app", map[string]string{
					psaEnforce: "baseline",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace without enforce label triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "my-app", nil)
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "my-app",
		},
		{
			name: "namespace with empty labels triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "staging", map[string]string{
					"team": "backend",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "staging",
		},
		{
			name: "kube-system is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-system", nil)
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-public is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-public", nil)
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-node-lease is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-node-lease", nil)
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple namespaces mixed compliance",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace(t, "compliant", map[string]string{
					psaEnforce: "restricted",
				}))
				cache.Add(NamespaceGVR, makeNamespace(t, "non-compliant", nil))
				cache.Add(NamespaceGVR, makeNamespace(t, "kube-system", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "non-compliant",
		},
		{
			name: "namespace with restricted enforce produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "secure-ns", map[string]string{
					psaEnforce: "restricted",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace with only audit label still triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "audit-only-ns", map[string]string{
					psaAudit: "baseline",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "audit-only-ns",
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
				assert.Equal(t, "psa-labels-missing", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "Namespace", findings[0].Kind)
				assert.Equal(t, ".metadata.labels", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestLabelsMissingChecker_CancelledContext(t *testing.T) {
	c := &LabelsMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	ns := makeNamespace(t, "test-ns", nil)
	cache.Add(NamespaceGVR, ns)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestLabelsMissingChecker_Fixtures(t *testing.T) {
	c := &LabelsMissingChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-labels-missing", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "my-app")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-labels-missing", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
