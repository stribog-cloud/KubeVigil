package psa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestModeAuditOnlyChecker_Metadata(t *testing.T) {
	c := &ModeAuditOnlyChecker{}

	assert.Equal(t, "psa-mode-audit-only", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryPSS)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), NamespaceGVR)
}

func TestModeAuditOnlyChecker_Run(t *testing.T) {
	c := &ModeAuditOnlyChecker{}
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
			name: "namespace with enforce and audit produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "my-app", map[string]string{
					psaEnforce: "baseline",
					psaAudit:   "restricted",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace with audit only triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "audit-ns", map[string]string{
					psaAudit: "baseline",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "audit-ns",
		},
		{
			name: "namespace with warn only triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "warn-ns", map[string]string{
					psaWarn: "restricted",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "warn-ns",
		},
		{
			name: "namespace with both audit and warn but no enforce triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "audit-warn-ns", map[string]string{
					psaAudit: "baseline",
					psaWarn:  "baseline",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "audit-warn-ns",
		},
		{
			name: "namespace with no PSA labels produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "plain-ns", map[string]string{
					"team": "backend",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-system is skipped even with audit only",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-system", map[string]string{
					psaAudit: "restricted",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple namespaces mixed compliance",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(NamespaceGVR, makeNamespace(t, "enforced", map[string]string{
					psaEnforce: "restricted",
					psaAudit:   "restricted",
				}))
				cache.Add(NamespaceGVR, makeNamespace(t, "audit-only", map[string]string{
					psaAudit: "baseline",
				}))
				cache.Add(NamespaceGVR, makeNamespace(t, "no-labels", nil))
				return cache
			},
			wantFindings: 1,
			wantResource: "audit-only",
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
				assert.Equal(t, "psa-mode-audit-only", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)
				assert.Equal(t, "Namespace", findings[0].Kind)
				assert.Equal(t, ".metadata.labels", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}

				// Regression: Namespace field must match the namespace name, not be empty.
				// Bug fix: psa_mode_audit_only.go changed Namespace: "" to Namespace: name.
				for _, f := range findings {
					assert.Equal(t, f.Resource, f.Namespace,
						"Finding.Namespace must equal the namespace name (Resource), not be empty")
				}
			}
		})
	}
}

func TestModeAuditOnlyChecker_CancelledContext(t *testing.T) {
	c := &ModeAuditOnlyChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	ns := makeNamespace(t, "test-ns", map[string]string{
		psaAudit: "baseline",
	})
	cache.Add(NamespaceGVR, ns)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestModeAuditOnlyChecker_Fixtures(t *testing.T) {
	c := &ModeAuditOnlyChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-mode-audit-only", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "audit-only-ns")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-mode-audit-only", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
