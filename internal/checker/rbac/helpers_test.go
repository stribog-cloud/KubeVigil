package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// makeRole builds an unstructured Role for testing.
func makeRole(name, namespace string, rules []map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"rules":      toInterfaceSlice(rules),
	}}
}

// makeClusterRole builds an unstructured ClusterRole for testing.
func makeClusterRole(name string, rules []map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": name},
		"rules":      toInterfaceSlice(rules),
	}}
}

// makeRoleBinding builds an unstructured RoleBinding for testing.
func makeRoleBinding(name, namespace, roleRefKind, roleRefName string, subjects []map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"roleRef":    map[string]interface{}{"apiGroup": "rbac.authorization.k8s.io", "kind": roleRefKind, "name": roleRefName},
		"subjects":   toInterfaceSlice(subjects),
	}}
}

// makeClusterRoleBinding builds an unstructured ClusterRoleBinding for testing.
func makeClusterRoleBinding(name, roleRefKind, roleRefName string, subjects []map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]interface{}{"name": name},
		"roleRef":    map[string]interface{}{"apiGroup": "rbac.authorization.k8s.io", "kind": roleRefKind, "name": roleRefName},
		"subjects":   toInterfaceSlice(subjects),
	}}
}

// makeRule builds a rule map suitable for use in makeRole/makeClusterRole.
func makeRule(apiGroups, resources, verbs []string) map[string]interface{} {
	return map[string]interface{}{
		"apiGroups": toStringInterfaceSlice(apiGroups),
		"resources": toStringInterfaceSlice(resources),
		"verbs":     toStringInterfaceSlice(verbs),
	}
}

// makeRuleWithResourceNames builds a rule map with resourceNames.
func makeRuleWithResourceNames(apiGroups, resources, verbs, resourceNames []string) map[string]interface{} {
	return map[string]interface{}{
		"apiGroups":     toStringInterfaceSlice(apiGroups),
		"resources":     toStringInterfaceSlice(resources),
		"verbs":         toStringInterfaceSlice(verbs),
		"resourceNames": toStringInterfaceSlice(resourceNames),
	}
}

// toStringInterfaceSlice converts []string to []interface{} for unstructured map building.
func toStringInterfaceSlice(ss []string) []interface{} {
	result := make([]interface{}, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

// toInterfaceSlice converts []map[string]interface{} to []interface{} for unstructured nesting.
func toInterfaceSlice(ms []map[string]interface{}) []interface{} {
	result := make([]interface{}, len(ms))
	for i, m := range ms {
		result[i] = m
	}
	return result
}

func TestExtractRoles(t *testing.T) {
	tests := []struct {
		name      string
		setup     func() *checker.ResourceCache
		wantCount int
		verify    func(t *testing.T, roles []RoleInfo)
	}{
		{
			name: "empty cache returns empty slice",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantCount: 0,
		},
		{
			name: "single Role with rules",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("pod-reader", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list", "watch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantCount: 1,
			verify: func(t *testing.T, roles []RoleInfo) {
				assert.Equal(t, "pod-reader", roles[0].Name)
				assert.Equal(t, "default", roles[0].Namespace)
				assert.Equal(t, "Role", roles[0].Kind)
				require.Len(t, roles[0].Rules, 1)
				assert.Equal(t, []string{""}, roles[0].Rules[0].APIGroups)
				assert.Equal(t, []string{"pods"}, roles[0].Rules[0].Resources)
				assert.Equal(t, []string{"get", "list", "watch"}, roles[0].Rules[0].Verbs)
			},
		},
		{
			name: "single ClusterRole with rules",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("node-reader", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes"}, []string{"get", "list"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantCount: 1,
			verify: func(t *testing.T, roles []RoleInfo) {
				assert.Equal(t, "node-reader", roles[0].Name)
				assert.Equal(t, "", roles[0].Namespace)
				assert.Equal(t, "ClusterRole", roles[0].Kind)
				require.Len(t, roles[0].Rules, 1)
			},
		},
		{
			name: "mixed Roles and ClusterRoles",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("role-a", "ns1", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cr := makeClusterRole("cr-b", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes"}, []string{"list"}),
				})
				cache.Add(RoleGVR, role)
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantCount: 2,
			verify: func(t *testing.T, roles []RoleInfo) {
				names := make(map[string]bool)
				for i := range roles {
					names[roles[i].Name] = true
				}
				assert.True(t, names["role-a"])
				assert.True(t, names["cr-b"])
			},
		},
		{
			name: "Role with no rules is not extracted",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "rbac.authorization.k8s.io/v1",
					"kind":       "Role",
					"metadata":   map[string]interface{}{"name": "empty-role", "namespace": "default"},
				}}
				cache.Add(RoleGVR, obj)
				return cache
			},
			wantCount: 0,
		},
		{
			name: "rule field extraction includes resourceNames",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("specific-role", "default", []map[string]interface{}{
					makeRuleWithResourceNames(
						[]string{""},
						[]string{"configmaps"},
						[]string{"get"},
						[]string{"my-config"},
					),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantCount: 1,
			verify: func(t *testing.T, roles []RoleInfo) {
				require.Len(t, roles[0].Rules, 1)
				assert.Equal(t, []string{"my-config"}, roles[0].Rules[0].ResourceNames)
			},
		},
		{
			name: "multiple rules in single role",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("multi-rule", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
					makeRule([]string{"apps"}, []string{"deployments"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantCount: 1,
			verify: func(t *testing.T, roles []RoleInfo) {
				require.Len(t, roles[0].Rules, 2)
				assert.Equal(t, []string{"pods"}, roles[0].Rules[0].Resources)
				assert.Equal(t, []string{"deployments"}, roles[0].Rules[1].Resources)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			roles := ExtractRoles(cache)
			assert.Len(t, roles, tt.wantCount)
			if tt.verify != nil && len(roles) > 0 {
				tt.verify(t, roles)
			}
		})
	}
}

func TestExtractBindings(t *testing.T) {
	tests := []struct {
		name      string
		setup     func() *checker.ResourceCache
		wantCount int
		verify    func(t *testing.T, bindings []BindingInfo)
	}{
		{
			name: "empty cache returns empty slice",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantCount: 0,
		},
		{
			name: "single RoleBinding with subjects",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				binding := makeRoleBinding("read-pods", "default", "Role", "pod-reader", []map[string]interface{}{
					{"kind": "User", "name": "jane", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, binding)
				return cache
			},
			wantCount: 1,
			verify: func(t *testing.T, bindings []BindingInfo) {
				assert.Equal(t, "read-pods", bindings[0].Name)
				assert.Equal(t, "default", bindings[0].Namespace)
				assert.Equal(t, "RoleBinding", bindings[0].Kind)
				assert.Equal(t, "Role", bindings[0].RoleRef.Kind)
				assert.Equal(t, "pod-reader", bindings[0].RoleRef.Name)
				assert.Equal(t, "rbac.authorization.k8s.io", bindings[0].RoleRef.APIGroup)
				require.Len(t, bindings[0].Subjects, 1)
				assert.Equal(t, "User", bindings[0].Subjects[0].Kind)
				assert.Equal(t, "jane", bindings[0].Subjects[0].Name)
			},
		},
		{
			name: "single ClusterRoleBinding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				binding := makeClusterRoleBinding("admin-binding", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "Group", "name": "system:masters", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, binding)
				return cache
			},
			wantCount: 1,
			verify: func(t *testing.T, bindings []BindingInfo) {
				assert.Equal(t, "admin-binding", bindings[0].Name)
				assert.Equal(t, "", bindings[0].Namespace)
				assert.Equal(t, "ClusterRoleBinding", bindings[0].Kind)
				assert.Equal(t, "ClusterRole", bindings[0].RoleRef.Kind)
				assert.Equal(t, "cluster-admin", bindings[0].RoleRef.Name)
				require.Len(t, bindings[0].Subjects, 1)
				assert.Equal(t, "Group", bindings[0].Subjects[0].Kind)
			},
		},
		{
			name: "binding with no roleRef is not extracted",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				obj := unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "rbac.authorization.k8s.io/v1",
					"kind":       "RoleBinding",
					"metadata":   map[string]interface{}{"name": "broken", "namespace": "default"},
					"subjects":   []interface{}{map[string]interface{}{"kind": "User", "name": "bob"}},
				}}
				cache.Add(RoleBindingGVR, obj)
				return cache
			},
			wantCount: 0,
		},
		{
			name: "binding with ServiceAccount subject",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				binding := makeRoleBinding("sa-binding", "production", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "deployer", "namespace": "production"},
				})
				cache.Add(RoleBindingGVR, binding)
				return cache
			},
			wantCount: 1,
			verify: func(t *testing.T, bindings []BindingInfo) {
				require.Len(t, bindings[0].Subjects, 1)
				assert.Equal(t, "ServiceAccount", bindings[0].Subjects[0].Kind)
				assert.Equal(t, "deployer", bindings[0].Subjects[0].Name)
				assert.Equal(t, "production", bindings[0].Subjects[0].Namespace)
			},
		},
		{
			name: "binding with multiple subjects",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				binding := makeRoleBinding("multi-subject", "default", "Role", "viewer", []map[string]interface{}{
					{"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"},
					{"kind": "Group", "name": "developers", "apiGroup": "rbac.authorization.k8s.io"},
					{"kind": "ServiceAccount", "name": "ci-bot", "namespace": "ci"},
				})
				cache.Add(RoleBindingGVR, binding)
				return cache
			},
			wantCount: 1,
			verify: func(t *testing.T, bindings []BindingInfo) {
				require.Len(t, bindings[0].Subjects, 3)
				assert.Equal(t, "alice", bindings[0].Subjects[0].Name)
				assert.Equal(t, "developers", bindings[0].Subjects[1].Name)
				assert.Equal(t, "ci-bot", bindings[0].Subjects[2].Name)
			},
		},
		{
			name: "mixed RoleBindings and ClusterRoleBindings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("rb1", "default", "Role", "viewer", []map[string]interface{}{
					{"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"},
				})
				crb := makeClusterRoleBinding("crb1", "ClusterRole", "admin", []map[string]interface{}{
					{"kind": "User", "name": "bob", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, rb)
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantCount: 2,
			verify: func(t *testing.T, bindings []BindingInfo) {
				kinds := make(map[string]bool)
				for i := range bindings {
					kinds[bindings[i].Kind] = true
				}
				assert.True(t, kinds["RoleBinding"])
				assert.True(t, kinds["ClusterRoleBinding"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setup()
			bindings := ExtractBindings(cache)
			assert.Len(t, bindings, tt.wantCount)
			if tt.verify != nil && len(bindings) > 0 {
				tt.verify(t, bindings)
			}
		})
	}
}

func TestGVRConstants(t *testing.T) {
	t.Run("RoleGVRs returns Role and ClusterRole", func(t *testing.T) {
		gvrs := RoleGVRs()
		require.Len(t, gvrs, 2)
		assert.Equal(t, RoleGVR, gvrs[0])
		assert.Equal(t, ClusterRoleGVR, gvrs[1])
	})

	t.Run("BindingGVRs returns RoleBinding and ClusterRoleBinding", func(t *testing.T) {
		gvrs := BindingGVRs()
		require.Len(t, gvrs, 2)
		assert.Equal(t, RoleBindingGVR, gvrs[0])
		assert.Equal(t, ClusterRoleBindingGVR, gvrs[1])
	})

	t.Run("AllGVRs returns all four RBAC GVRs", func(t *testing.T) {
		gvrs := AllGVRs()
		require.Len(t, gvrs, 4)
	})
}

func TestContainsString(t *testing.T) {
	assert.True(t, containsString([]string{"a", "b", "c"}, "b"))
	assert.False(t, containsString([]string{"a", "b", "c"}, "d"))
	assert.False(t, containsString(nil, "a"))
	assert.False(t, containsString([]string{}, "a"))
}

func TestContainsAny(t *testing.T) {
	assert.True(t, containsAny([]string{"a", "b", "c"}, "b", "d"))
	assert.True(t, containsAny([]string{"a", "b", "c"}, "d", "c"))
	assert.False(t, containsAny([]string{"a", "b", "c"}, "d", "e"))
	assert.False(t, containsAny(nil, "a"))
}

func TestToStringSlice(t *testing.T) {
	assert.Nil(t, toStringSlice(nil))
	assert.Nil(t, toStringSlice("not a slice"))
	assert.Equal(t, []string{"a", "b"}, toStringSlice([]interface{}{"a", "b"}))
	// Mixed types: non-string items are skipped.
	assert.Equal(t, []string{"a"}, toStringSlice([]interface{}{"a", 42}))
}

func TestStringFromMap(t *testing.T) {
	m := map[string]interface{}{"key": "value", "num": 42}
	assert.Equal(t, "value", stringFromMap(m, "key"))
	assert.Equal(t, "", stringFromMap(m, "num"))
	assert.Equal(t, "", stringFromMap(m, "missing"))
}
