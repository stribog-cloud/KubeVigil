package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestExecAccessChecker_Metadata(t *testing.T) {
	c := &ExecAccessChecker{}

	assert.Equal(t, "rbac-exec-access", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestExecAccessChecker_Run(t *testing.T) {
	c := &ExecAccessChecker{}
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
			name: "Role with create pods/exec triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("exec-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods/exec"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "exec-role",
			wantKind:     "Role",
		},
		{
			name: "Role with create pods/attach triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("attach-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods/attach"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "attach-role",
		},
		{
			name: "Role with wildcard verb on pods/exec triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("wildcard-exec", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods/exec"}, []string{"*"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ClusterRole with create pods/exec triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("cluster-exec", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods/exec"}, []string{"create"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "cluster-exec",
			wantKind:     "ClusterRole",
		},
		{
			name: "Role with get on pods/exec produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("exec-getter", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods/exec"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with create on pods (not pods/exec) produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("pod-creator", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pods/exec and pods/attach both present triggers single finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("exec-attach", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods/exec", "pods/attach"}, []string{"create"}),
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
					makeRule([]string{""}, []string{"pods/exec"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "both Role and ClusterRole with exec produce two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("role-exec", "ns1", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods/exec"}, []string{"create"}),
				})
				cr := makeClusterRole("cr-exec", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods/attach"}, []string{"create"}),
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
				assert.Equal(t, "rbac-exec-access", findings[0].Checker)
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

func TestExecAccessChecker_CancelledContext(t *testing.T) {
	c := &ExecAccessChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods/exec"}, []string{"create"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestExecAccessChecker_FieldPath(t *testing.T) {
	c := &ExecAccessChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
		makeRule([]string{""}, []string{"pods/exec"}, []string{"create"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].resources", findings[0].FieldPath)
}

func TestExecAccessChecker_Fixtures(t *testing.T) {
	c := &ExecAccessChecker{}
	ctx := context.Background()

	t.Run("fixture: role-exec-access.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-exec-access", "role-exec-access.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "exec-access-role")
	})

	t.Run("fixture: role-no-exec-access.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-exec-access", "role-no-exec-access.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
