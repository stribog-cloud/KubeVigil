package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestWebhookTamperingChecker_Metadata(t *testing.T) {
	c := &WebhookTamperingChecker{}

	assert.Equal(t, "rbac-webhook-tampering", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestWebhookTamperingChecker_Run(t *testing.T) {
	c := &WebhookTamperingChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantKind     string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "Role with patch on validatingwebhookconfigurations triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("vwc-patcher", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"patch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "vwc-patcher",
			wantKind:     "Role",
		},
		{
			name: "Role with delete on mutatingwebhookconfigurations triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mwc-deleter", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"mutatingwebhookconfigurations"}, []string{"delete"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with update on validatingwebhookconfigurations triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("vwc-updater", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"update"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with deletecollection on mutatingwebhookconfigurations triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mwc-deletecollection", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"mutatingwebhookconfigurations"}, []string{"deletecollection"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with wildcard verb on webhook config triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("wc-wildcard", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"*"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ClusterRole with patch/delete triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("cluster-webhook-tamperer", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"patch", "delete"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "cluster-webhook-tamperer",
			wantKind:     "ClusterRole",
		},
		{
			name: "Role with read-only access produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("wc-reader", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}, []string{"get", "list", "watch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with create on webhook config produces no findings (create not in tamper verbs)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("wc-creator", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with patch on unrelated resource produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("pod-patcher", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"patch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "two violating rules in one role produces single finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("double-violation", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"patch"}),
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"mutatingwebhookconfigurations"}, []string{"delete"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "multiple roles each with violation produce separate findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role1 := makeRole("role-a", "ns1", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"patch"}),
				})
				role2 := makeRole("role-b", "ns2", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"mutatingwebhookconfigurations"}, []string{"delete"}),
				})
				cache.Add(RoleGVR, role1)
				cache.Add(RoleGVR, role2)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "resource mixed with other resources triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-resources", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}, []string{"patch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "empty rules produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("empty-rules-role", "default", []map[string]interface{}{})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "verb mixed with wildcard triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-verbs", "default", []map[string]interface{}{
					makeRule([]string{"admissionregistration.k8s.io"}, []string{"mutatingwebhookconfigurations"}, []string{"get", "*", "list"}),
				})
				cache.Add(RoleGVR, role)
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
				assert.Equal(t, "rbac-webhook-tampering", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantKind != "" {
					assert.Equal(t, tt.wantKind, findings[0].Kind)
				}
			}
		})
	}
}

func TestWebhookTamperingChecker_CancelledContext(t *testing.T) {
	c := &WebhookTamperingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"patch"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestWebhookTamperingChecker_FieldPath(t *testing.T) {
	c := &WebhookTamperingChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
		makeRule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"patch"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].resources", findings[0].FieldPath)
}

func TestWebhookTamperingChecker_Fixtures(t *testing.T) {
	c := &WebhookTamperingChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-webhook-tampering", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "webhook-tampering-failing-role")
		assert.Equal(t, "ClusterRole", findings[0].Kind)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-webhook-tampering", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

func TestWebhookTamperingChecker_RequiredGVRs(t *testing.T) {
	c := &WebhookTamperingChecker{}
	gvrs := c.RequiredResources()

	expected := []schema.GroupVersionResource{RoleGVR, ClusterRoleGVR}
	assert.Equal(t, expected, gvrs)
}
