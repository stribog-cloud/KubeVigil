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

func TestCrossNamespaceServiceAccountChecker_Metadata(t *testing.T) {
	c := &CrossNamespaceServiceAccountChecker{}

	assert.Equal(t, "rbac-crossnamespace-serviceaccount", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleBindingGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleBindingGVR)
}

func TestCrossNamespaceServiceAccountChecker_Run(t *testing.T) {
	c := &CrossNamespaceServiceAccountChecker{}
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
			name: "RoleBinding with ServiceAccount in different namespace triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("crossns-binding", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "app-sa", "namespace": "ns-b"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
			wantResource: "crossns-binding",
			wantKind:     "RoleBinding",
		},
		{
			name: "RoleBinding with ServiceAccount in same namespace produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("samens-binding", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "app-sa", "namespace": "ns-a"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "RoleBinding with ServiceAccount subject with empty namespace produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("empty-ns-binding", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "app-sa", "namespace": ""},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "RoleBinding with User subject produces no findings (not a ServiceAccount)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("user-binding", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "User", "name": "jane", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "RoleBinding with Group subject produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("group-binding", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "Group", "name": "developers", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ClusterRoleBinding with cross-namespace-looking SA is exempt",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("crb-sa", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "app-sa", "namespace": "ns-b"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "RoleBinding with multiple cross-namespace SA subjects produces multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("multi-crossns", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "sa-one", "namespace": "ns-b"},
					{"kind": "ServiceAccount", "name": "sa-two", "namespace": "ns-c"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "RoleBinding with mixed same-ns and cross-ns SA subjects produces one finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("mixed-subjects", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "sa-local", "namespace": "ns-a"},
					{"kind": "ServiceAccount", "name": "sa-remote", "namespace": "ns-b"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "multiple RoleBindings each with cross-ns SA produce separate findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb1 := makeRoleBinding("binding-a", "ns-a", "Role", "role-a", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "sa-a", "namespace": "ns-x"},
				})
				rb2 := makeRoleBinding("binding-b", "ns-b", "Role", "role-b", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "sa-b", "namespace": "ns-y"},
				})
				cache.Add(RoleBindingGVR, rb1)
				cache.Add(RoleBindingGVR, rb2)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "RoleBinding in default namespace referencing kube-system SA triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("default-to-kubesystem", "default", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "sa", "namespace": "kube-system"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "RoleBinding with ServiceAccount and User subjects, only SA cross-ns triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("mixed-kinds", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "User", "name": "jane", "apiGroup": "rbac.authorization.k8s.io"},
					{"kind": "ServiceAccount", "name": "app-sa", "namespace": "ns-b"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "RoleBinding with no subjects produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("no-subjects", "ns-a", "Role", "some-role", []map[string]interface{}{})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ClusterRoleBinding with User subject produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("crb-user", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "User", "name": "admin", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "RoleBinding and ClusterRoleBinding mixed — only RoleBinding SA cross-ns counted",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("rb-crossns", "ns-a", "Role", "some-role", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "app-sa", "namespace": "ns-b"},
				})
				crb := makeClusterRoleBinding("crb-any-sa", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "any-sa", "namespace": "ns-z"},
				})
				cache.Add(RoleBindingGVR, rb)
				cache.Add(ClusterRoleBindingGVR, crb)
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
				assert.Equal(t, "rbac-crossnamespace-serviceaccount", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)

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

func TestCrossNamespaceServiceAccountChecker_CancelledContext(t *testing.T) {
	c := &CrossNamespaceServiceAccountChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	rb := makeRoleBinding("test-binding", "ns-a", "Role", "some-role", []map[string]interface{}{
		{"kind": "ServiceAccount", "name": "app-sa", "namespace": "ns-b"},
	})
	cache.Add(RoleBindingGVR, rb)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestCrossNamespaceServiceAccountChecker_FieldPath(t *testing.T) {
	c := &CrossNamespaceServiceAccountChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	rb := makeRoleBinding("fp-binding", "ns-a", "Role", "some-role", []map[string]interface{}{
		{"kind": "ServiceAccount", "name": "app-sa", "namespace": "ns-b"},
	})
	cache.Add(RoleBindingGVR, rb)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".subjects", findings[0].FieldPath)
}

func TestCrossNamespaceServiceAccountChecker_Fixtures(t *testing.T) {
	c := &CrossNamespaceServiceAccountChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-crossnamespace-serviceaccount", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "crossns-failing-binding")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-crossnamespace-serviceaccount", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

func TestCrossNamespaceServiceAccountChecker_RequiredGVRs(t *testing.T) {
	c := &CrossNamespaceServiceAccountChecker{}
	gvrs := c.RequiredResources()

	expected := []schema.GroupVersionResource{RoleBindingGVR, ClusterRoleBindingGVR}
	assert.Equal(t, expected, gvrs)
}
