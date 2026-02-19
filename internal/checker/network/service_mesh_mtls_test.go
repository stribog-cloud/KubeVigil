package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestServiceMeshMTLSChecker_Metadata(t *testing.T) {
	c := &ServiceMeshMTLSChecker{}

	assert.Equal(t, "service-mesh-mtls", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryNetwork)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	require.Len(t, c.RequiredResources(), 1)
	assert.Equal(t, PeerAuthenticationGVR, c.RequiredResources()[0])
}

func TestServiceMeshMTLSChecker_Run(t *testing.T) {
	c := &ServiceMeshMTLSChecker{}
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
			name: "STRICT mode does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pa := makePeerAuthentication(t, "default", "istio-system", "STRICT")
				cache.Add(PeerAuthenticationGVR, pa)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "PERMISSIVE mode triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pa := makePeerAuthentication(t, "default", "istio-system", "PERMISSIVE")
				cache.Add(PeerAuthenticationGVR, pa)
				return cache
			},
			wantFindings: 1,
			wantResource: "default",
			checkMessage: "PERMISSIVE",
		},
		{
			name: "DISABLE mode triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pa := makePeerAuthentication(t, "default", "istio-system", "DISABLE")
				cache.Add(PeerAuthenticationGVR, pa)
				return cache
			},
			wantFindings: 1,
			wantResource: "default",
			checkMessage: "DISABLED",
		},
		{
			name: "no mtls field triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pa := makePeerAuthenticationNoMTLS(t, "no-mtls", "default")
				cache.Add(PeerAuthenticationGVR, pa)
				return cache
			},
			wantFindings: 1,
			wantResource: "no-mtls",
			checkMessage: "no mTLS mode configured",
		},
		{
			name: "mesh-wide PERMISSIVE in istio-system mentions mesh-wide policy",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pa := makePeerAuthentication(t, "default", "istio-system", "PERMISSIVE")
				cache.Add(PeerAuthenticationGVR, pa)
				return cache
			},
			wantFindings: 1,
			checkMessage: "mesh-wide policy",
		},
		{
			name: "namespace-scoped PERMISSIVE mentions namespace-wide policy",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pa := makePeerAuthentication(t, "default", "production", "PERMISSIVE")
				cache.Add(PeerAuthenticationGVR, pa)
				return cache
			},
			wantFindings: 1,
			checkMessage: "namespace-wide policy",
		},
		{
			name: "workload-scoped PERMISSIVE mentions workload-scoped policy",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pa := makePeerAuthenticationWithSelector(t, "app-mtls", "production", "PERMISSIVE",
					map[string]string{"app": "my-app"})
				cache.Add(PeerAuthenticationGVR, pa)
				return cache
			},
			wantFindings: 1,
			checkMessage: "workload-scoped policy",
		},
		{
			name: "multiple PeerAuthentication resources with mixed modes",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cache.Add(PeerAuthenticationGVR, makePeerAuthentication(t, "strict-pa", "ns1", "STRICT"))
				cache.Add(PeerAuthenticationGVR, makePeerAuthentication(t, "permissive-pa", "ns2", "PERMISSIVE"))
				cache.Add(PeerAuthenticationGVR, makePeerAuthentication(t, "disable-pa", "ns3", "DISABLE"))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "fixture: failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "service-mesh-mtls", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "default",
			checkMessage: "PERMISSIVE",
		},
		{
			name: "fixture: passing.yaml does not trigger finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "service-mesh-mtls", "passing.yaml")
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
				assert.Equal(t, "service-mesh-mtls", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Equal(t, "PeerAuthentication", findings[0].Kind)
				assert.Equal(t, ".spec.mtls.mode", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.checkMessage != "" {
					found := false
					for _, f := range findings {
						if assert.ObjectsAreEqual(tt.checkMessage, "") {
							continue
						}
						if containsSubstring(f.Message, tt.checkMessage) {
							found = true
							break
						}
					}
					assert.True(t, found, "expected message containing %q in findings", tt.checkMessage)
				}
			}
		})
	}
}

func TestServiceMeshMTLSChecker_CancelledContext(t *testing.T) {
	c := &ServiceMeshMTLSChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	pa := makePeerAuthentication(t, "default", "istio-system", "PERMISSIVE")
	cache.Add(PeerAuthenticationGVR, pa)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestServiceMeshMTLSChecker_AllSTRICT(t *testing.T) {
	c := &ServiceMeshMTLSChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cache.Add(PeerAuthenticationGVR, makePeerAuthentication(t, "mesh-pa", "istio-system", "STRICT"))
	cache.Add(PeerAuthenticationGVR, makePeerAuthentication(t, "ns-pa", "production", "STRICT"))
	cache.Add(PeerAuthenticationGVR, makePeerAuthenticationWithSelector(t, "app-pa", "production", "STRICT",
		map[string]string{"app": "web"}))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// containsSubstring checks if a string contains a substring (case-sensitive).
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (substr == "" || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
