package psa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestVersionPinningChecker_Metadata(t *testing.T) {
	c := &VersionPinningChecker{}

	assert.Equal(t, "psa-version-pinning", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryPSS)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), NamespaceGVR)
}

func TestVersionPinningChecker_Run(t *testing.T) {
	c := &VersionPinningChecker{}
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
			name: "namespace with version set to latest produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "my-app", map[string]string{
					psaEnforce:    "restricted",
					psaEnforceVer: "latest",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "namespace with pinned enforce version triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "pinned-ns", map[string]string{
					psaEnforce:    "restricted",
					psaEnforceVer: "v1.25",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "pinned-ns",
		},
		{
			name: "namespace with pinned audit version triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "audit-pinned", map[string]string{
					psaAudit:    "baseline",
					psaAuditVer: "v1.28",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "audit-pinned",
		},
		{
			name: "namespace with pinned warn version triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "warn-pinned", map[string]string{
					psaWarn:    "baseline",
					psaWarnVer: "v1.27",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "warn-pinned",
		},
		{
			name: "namespace with multiple pinned versions triggers multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "multi-pinned", map[string]string{
					psaEnforce:    "restricted",
					psaEnforceVer: "v1.25",
					psaAudit:      "restricted",
					psaAuditVer:   "v1.25",
					psaWarn:       "restricted",
					psaWarnVer:    "v1.25",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 3,
			wantResource: "multi-pinned",
		},
		{
			name: "namespace with no version labels produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "no-version", map[string]string{
					psaEnforce: "baseline",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "kube-system is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "kube-system", map[string]string{
					psaEnforceVer: "v1.25",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "mixed latest and pinned produces findings only for pinned",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				ns := makeNamespace(t, "mixed-versions", map[string]string{
					psaEnforce:    "restricted",
					psaEnforceVer: "latest",
					psaAudit:      "restricted",
					psaAuditVer:   "v1.26",
				})
				cache.Add(NamespaceGVR, ns)
				return cache
			},
			wantFindings: 1,
			wantResource: "mixed-versions",
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
				assert.Equal(t, "psa-version-pinning", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				assert.Equal(t, "Namespace", findings[0].Kind)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}

				// Regression: Namespace field must match the namespace name, not be empty.
				// Bug fix: psa_version_pinning.go changed Namespace: "" to Namespace: name.
				for _, f := range findings {
					assert.Equal(t, f.Resource, f.Namespace,
						"Finding.Namespace must equal the namespace name (Resource), not be empty")
				}
			}
		})
	}
}

func TestVersionPinningChecker_CancelledContext(t *testing.T) {
	c := &VersionPinningChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	ns := makeNamespace(t, "test-ns", map[string]string{
		psaEnforceVer: "v1.25",
	})
	cache.Add(NamespaceGVR, ns)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestVersionPinningChecker_Fixtures(t *testing.T) {
	c := &VersionPinningChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-version-pinning", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "pinned-ns")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-version-pinning", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
