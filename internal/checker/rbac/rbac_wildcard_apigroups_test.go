package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestWildcardAPIGroupsChecker_Metadata(t *testing.T) {
	c := &WildcardAPIGroupsChecker{}

	assert.Equal(t, "rbac-wildcard-apigroups", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestWildcardAPIGroupsChecker_Run(t *testing.T) {
	c := &WildcardAPIGroupsChecker{}
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
			name: "Role with wildcard API groups triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("all-apigroups", "default", []map[string]interface{}{
					makeRule([]string{"*"}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "all-apigroups",
			wantKind:     "Role",
		},
		{
			name: "ClusterRole with wildcard API groups triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("cluster-all-apigroups", []map[string]interface{}{
					makeRule([]string{"*"}, []string{"deployments"}, []string{"list"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "cluster-all-apigroups",
			wantKind:     "ClusterRole",
		},
		{
			name: "empty string apiGroup is core group not wildcard — no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("core-group", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "specific API groups produce no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("apps-group", "default", []map[string]interface{}{
					makeRule([]string{"apps", "batch"}, []string{"deployments"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "wildcard mixed with specific API groups triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-apigroups", "default", []map[string]interface{}{
					makeRule([]string{"", "*", "apps"}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "multiple rules only violating one triggers single finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("multi-rule", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
					makeRule([]string{"*"}, []string{"deployments"}, []string{"list"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "both Role and ClusterRole with violations produce two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("role-a", "ns1", []map[string]interface{}{
					makeRule([]string{"*"}, []string{"pods"}, []string{"get"}),
				})
				cr := makeClusterRole("cr-b", []map[string]interface{}{
					makeRule([]string{"*"}, []string{"nodes"}, []string{"list"}),
				})
				cache.Add(RoleGVR, role)
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 2,
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
				assert.Equal(t, "rbac-wildcard-apigroups", findings[0].Checker)
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

func TestWildcardAPIGroupsChecker_CancelledContext(t *testing.T) {
	c := &WildcardAPIGroupsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{"*"}, []string{"pods"}, []string{"get"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestWildcardAPIGroupsChecker_FieldPath(t *testing.T) {
	c := &WildcardAPIGroupsChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
		makeRule([]string{"*"}, []string{"deployments"}, []string{"list"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].apiGroups", findings[0].FieldPath)
}

func TestWildcardAPIGroupsChecker_Fixtures(t *testing.T) {
	c := &WildcardAPIGroupsChecker{}
	ctx := context.Background()

	t.Run("fixture: role-wildcard-apigroups.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-wildcard-apigroups", "role-wildcard-apigroups.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "wildcard-apigroups-role")
	})

	t.Run("fixture: role-specific-apigroups.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-wildcard-apigroups", "role-specific-apigroups.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
