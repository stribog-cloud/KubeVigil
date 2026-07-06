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

func TestDeleteCollectionBroadChecker_Metadata(t *testing.T) {
	c := &DeleteCollectionBroadChecker{}

	assert.Equal(t, "rbac-deletecollection-broad", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestDeleteCollectionBroadChecker_Run(t *testing.T) {
	c := &DeleteCollectionBroadChecker{}
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
			name: "Role with deletecollection on secrets triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("secret-deleter", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"secrets"}, []string{"deletecollection"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "secret-deleter",
			wantKind:     "Role",
		},
		{
			name: "Role with deletecollection on pods triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("pod-deleter", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"deletecollection"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with deletecollection on persistentvolumeclaims triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("pvc-deleter", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"persistentvolumeclaims"}, []string{"deletecollection"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with deletecollection on namespaces triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("ns-deleter", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"namespaces"}, []string{"deletecollection"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with deletecollection on wildcard resources triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("wildcard-deleter", "default", []map[string]interface{}{
					makeRule([]string{"*"}, []string{"*"}, []string{"deletecollection"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ClusterRole with deletecollection on secrets triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("cluster-secret-deleter", []map[string]interface{}{
					makeRule([]string{""}, []string{"secrets"}, []string{"deletecollection"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "cluster-secret-deleter",
			wantKind:     "ClusterRole",
		},
		{
			name: "Role with single-object delete only produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("single-deleter", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list", "delete"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with deletecollection but resourceNames narrowed produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("scoped-deleter", "default", []map[string]interface{}{
					makeRuleWithResourceNames([]string{""}, []string{"secrets"}, []string{"deletecollection"}, []string{"specific-secret"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with deletecollection on non-denylisted resource produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("configmap-deleter", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"configmaps"}, []string{"deletecollection"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with get/list only produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("reader-only", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"secrets"}, []string{"get", "list"}),
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
					makeRule([]string{""}, []string{"pods"}, []string{"deletecollection"}),
					makeRule([]string{""}, []string{"secrets"}, []string{"deletecollection"}),
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
					makeRule([]string{""}, []string{"pods"}, []string{"deletecollection"}),
				})
				role2 := makeRole("role-b", "ns2", []map[string]interface{}{
					makeRule([]string{""}, []string{"secrets"}, []string{"deletecollection"}),
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
					makeRule([]string{""}, []string{"configmaps", "secrets"}, []string{"deletecollection"}),
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
			name: "verbs mixed with deletecollection and other verbs triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-verbs", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list", "deletecollection"}),
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
				assert.Equal(t, "rbac-deletecollection-broad", findings[0].Checker)
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

func TestDeleteCollectionBroadChecker_CancelledContext(t *testing.T) {
	c := &DeleteCollectionBroadChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"secrets"}, []string{"deletecollection"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestDeleteCollectionBroadChecker_FieldPath(t *testing.T) {
	c := &DeleteCollectionBroadChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"configmaps"}, []string{"get"}),
		makeRule([]string{""}, []string{"secrets"}, []string{"deletecollection"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].verbs", findings[0].FieldPath)
}

func TestDeleteCollectionBroadChecker_Fixtures(t *testing.T) {
	c := &DeleteCollectionBroadChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-deletecollection-broad", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "deletecollection-failing-role")
		assert.Equal(t, "ClusterRole", findings[0].Kind)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-deletecollection-broad", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

func TestDeleteCollectionBroadChecker_RequiredGVRs(t *testing.T) {
	c := &DeleteCollectionBroadChecker{}
	gvrs := c.RequiredResources()

	expected := []schema.GroupVersionResource{RoleGVR, ClusterRoleGVR}
	assert.Equal(t, expected, gvrs)
}
