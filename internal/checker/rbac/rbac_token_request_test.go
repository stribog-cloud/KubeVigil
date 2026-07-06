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

func TestTokenRequestChecker_Metadata(t *testing.T) {
	c := &TokenRequestChecker{}

	assert.Equal(t, "rbac-token-request", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestTokenRequestChecker_Run(t *testing.T) {
	c := &TokenRequestChecker{}
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
			name: "Role with unrestricted create on serviceaccounts/token triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("token-minter", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "token-minter",
			wantKind:     "Role",
		},
		{
			name: "Role with wildcard verb on serviceaccounts/token triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("token-wildcard", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"*"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ClusterRole with unrestricted create triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("cluster-token-minter", []map[string]interface{}{
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "cluster-token-minter",
			wantKind:     "ClusterRole",
		},
		{
			name: "Role with resourceNames narrowing produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("token-scoped", "default", []map[string]interface{}{
					makeRuleWithResourceNames([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}, []string{"my-app-sa"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with no serviceaccounts/token grant produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("no-token-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"serviceaccounts"}, []string{"get", "list"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with get on serviceaccounts/token produces no findings (not create/*)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("token-reader", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with get on pods produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("pod-reader", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
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
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
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
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
				})
				role2 := makeRole("role-b", "ns2", []map[string]interface{}{
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"*"}),
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
					makeRule([]string{""}, []string{"serviceaccounts", "serviceaccounts/token"}, []string{"create"}),
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
			name: "resourceNames with wildcard verb still narrowed produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("token-scoped-wildcard", "default", []map[string]interface{}{
					makeRuleWithResourceNames([]string{""}, []string{"serviceaccounts/token"}, []string{"*"}, []string{"my-app-sa", "my-other-sa"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "verb mixed with wildcard on token triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-verbs", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"get", "*"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "delete verb only on token produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("token-delete-only", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"delete"}),
				})
				cache.Add(RoleGVR, role)
				return cache
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
				assert.Equal(t, "rbac-token-request", findings[0].Checker)
				assert.Equal(t, checker.SeverityCritical, findings[0].Severity)

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

func TestTokenRequestChecker_CancelledContext(t *testing.T) {
	c := &TokenRequestChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestTokenRequestChecker_FieldPath(t *testing.T) {
	c := &TokenRequestChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
		makeRule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].resources", findings[0].FieldPath)
}

func TestTokenRequestChecker_Fixtures(t *testing.T) {
	c := &TokenRequestChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-token-request", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "token-request-failing-role")
		assert.Equal(t, "ClusterRole", findings[0].Kind)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-token-request", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

func TestTokenRequestChecker_RequiredGVRs(t *testing.T) {
	c := &TokenRequestChecker{}
	gvrs := c.RequiredResources()

	expected := []schema.GroupVersionResource{RoleGVR, ClusterRoleGVR}
	assert.Equal(t, expected, gvrs)
}
