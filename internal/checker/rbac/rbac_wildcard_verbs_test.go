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

func TestWildcardVerbsChecker_Metadata(t *testing.T) {
	c := &WildcardVerbsChecker{}

	assert.Equal(t, "rbac-wildcard-verbs", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())

	// RequiredResources should include Role and ClusterRole GVRs.
	gvrs := c.RequiredResources()
	assert.Contains(t, gvrs, RoleGVR)
	assert.Contains(t, gvrs, ClusterRoleGVR)
}

func TestWildcardVerbsChecker_Run(t *testing.T) {
	c := &WildcardVerbsChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantKind     string
		wantSeverity checker.Severity
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "Role with wildcard verbs triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("admin-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"*"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "admin-role",
			wantKind:     "Role",
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "ClusterRole with wildcard verbs triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("super-admin", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"*"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "super-admin",
			wantKind:     "ClusterRole",
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "Role with specific verbs produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("reader", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list", "watch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple rules only violating one triggers single finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
					makeRule([]string{"apps"}, []string{"deployments"}, []string{"*"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "mixed-role",
		},
		{
			name: "multiple roles each with violation produce separate findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role1 := makeRole("role-a", "ns1", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"*"}),
				})
				role2 := makeRole("role-b", "ns2", []map[string]interface{}{
					makeRule([]string{""}, []string{"services"}, []string{"*"}),
				})
				cache.Add(RoleGVR, role1)
				cache.Add(RoleGVR, role2)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "wildcard verb mixed with specific verbs triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-verbs", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "*", "list"}),
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
				assert.Equal(t, "rbac-wildcard-verbs", findings[0].Checker)
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

func TestWildcardVerbsChecker_CancelledContext(t *testing.T) {
	c := &WildcardVerbsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"*"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestWildcardVerbsChecker_FieldPath(t *testing.T) {
	c := &WildcardVerbsChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
		makeRule([]string{"apps"}, []string{"deployments"}, []string{"*"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].verbs", findings[0].FieldPath)
}

func TestWildcardVerbsChecker_Fixtures(t *testing.T) {
	c := &WildcardVerbsChecker{}
	ctx := context.Background()

	t.Run("fixture: role-wildcard-verbs.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-wildcard-verbs", "role-wildcard-verbs.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "wildcard-verbs-role")
	})

	t.Run("fixture: role-specific-verbs.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-wildcard-verbs", "role-specific-verbs.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("fixture: clusterrole-wildcard-verbs.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-wildcard-verbs", "clusterrole-wildcard-verbs.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "wildcard-verbs-clusterrole")
		assert.Equal(t, "ClusterRole", findings[0].Kind)
	})
}

func TestWildcardVerbsChecker_RequiredGVRs(t *testing.T) {
	c := &WildcardVerbsChecker{}
	gvrs := c.RequiredResources()

	expected := []schema.GroupVersionResource{RoleGVR, ClusterRoleGVR}
	assert.Equal(t, expected, gvrs)
}
