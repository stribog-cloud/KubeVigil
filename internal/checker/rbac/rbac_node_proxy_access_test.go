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

func TestNodeProxyAccessChecker_Metadata(t *testing.T) {
	c := &NodeProxyAccessChecker{}

	assert.Equal(t, "rbac-node-proxy-access", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestNodeProxyAccessChecker_Run(t *testing.T) {
	c := &NodeProxyAccessChecker{}
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
			name: "Role with get on nodes/proxy triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("node-proxy-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "node-proxy-role",
			wantKind:     "Role",
		},
		{
			name: "Role with create on nodes/proxy triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("node-proxy-create", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with wildcard verb on nodes/proxy triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("node-proxy-wildcard", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"*"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ClusterRole with get/create on nodes/proxy triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("cluster-node-proxy", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"get", "create"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "cluster-node-proxy",
			wantKind:     "ClusterRole",
		},
		{
			// "nodes/*" is NOT valid Kubernetes RBAC syntax — the authorizer only
			// recognises "*" and "*/subresource", so this rule is inert and must
			// NOT trigger a finding.
			name: "Role with non-syntactic nodes/* produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("node-wildcard-subresource", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/*"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			// The real subresource wildcard "*/proxy" grants nodes/proxy (and
			// services/proxy, pods/proxy) — must trigger.
			name: "Role with real subresource wildcard */proxy triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("proxy-wildcard", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"*/proxy"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "proxy-wildcard",
			wantKind:     "Role",
		},
		{
			name: "Role with full wildcard resource triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("full-wildcard", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"*"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "full-wildcard",
			wantKind:     "Role",
		},
		{
			name: "Role with plain nodes resource produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("node-reader", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes"}, []string{"get", "list"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with nodes/proxy but only list/watch produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("node-proxy-readonly", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"list", "watch"}),
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
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with nodes/status is not nodes/proxy produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("node-status", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/status"}, []string{"get", "update"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "nodes/proxy mixed with other resources triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-resources", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods", "nodes/proxy", "configmaps"}, []string{"get"}),
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
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"create"}),
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
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"get"}),
				})
				role2 := makeRole("role-b", "ns2", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role1)
				cache.Add(RoleGVR, role2)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "verb mixed with wildcard triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-verbs", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"list", "*", "watch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with delete on nodes/proxy produces no findings (not get/create/*)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("node-proxy-delete-only", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes/proxy"}, []string{"delete"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)

			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				helpers.AssertAllFindingsHaveRequiredFields(t, findings)
				assert.Equal(t, "rbac-node-proxy-access", findings[0].Checker)
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

func TestNodeProxyAccessChecker_CancelledContext(t *testing.T) {
	c := &NodeProxyAccessChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"nodes/proxy"}, []string{"get"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestNodeProxyAccessChecker_FieldPath(t *testing.T) {
	c := &NodeProxyAccessChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
		makeRule([]string{""}, []string{"nodes/proxy"}, []string{"create"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].resources", findings[0].FieldPath)
}

func TestNodeProxyAccessChecker_Fixtures(t *testing.T) {
	c := &NodeProxyAccessChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-node-proxy-access", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "node-proxy-failing-role")
		assert.Equal(t, "ClusterRole", findings[0].Kind)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-node-proxy-access", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

func TestNodeProxyAccessChecker_RequiredGVRs(t *testing.T) {
	c := &NodeProxyAccessChecker{}
	gvrs := c.RequiredResources()

	expected := []schema.GroupVersionResource{RoleGVR, ClusterRoleGVR}
	assert.Equal(t, expected, gvrs)
}
