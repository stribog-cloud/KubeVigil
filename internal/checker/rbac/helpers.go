// Package rbac implements RBAC (Role-Based Access Control) security checkers.
// These checkers analyze Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings
// for overly permissive or risky access grants.
package rbac

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// GVR constants for RBAC resources.
var (
	// RoleGVR is the GroupVersionResource for Role.
	RoleGVR = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}
	// ClusterRoleGVR is the GroupVersionResource for ClusterRole.
	ClusterRoleGVR = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}
	// RoleBindingGVR is the GroupVersionResource for RoleBinding.
	RoleBindingGVR = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}
	// ClusterRoleBindingGVR is the GroupVersionResource for ClusterRoleBinding.
	ClusterRoleBindingGVR = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}
)

// RoleGVRs returns the GVRs needed for role-analysis checks (Role + ClusterRole).
func RoleGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{RoleGVR, ClusterRoleGVR}
}

// BindingGVRs returns the GVRs needed for binding-analysis checks (RoleBinding + ClusterRoleBinding).
func BindingGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{RoleBindingGVR, ClusterRoleBindingGVR}
}

// AllGVRs returns all RBAC GVRs (roles, clusterroles, rolebindings, clusterrolebindings).
func AllGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{RoleGVR, ClusterRoleGVR, RoleBindingGVR, ClusterRoleBindingGVR}
}

// PolicyRule represents a single RBAC policy rule extracted from a Role or ClusterRole.
type PolicyRule struct {
	APIGroups     []string
	Resources     []string
	Verbs         []string
	ResourceNames []string
}

// RoleInfo holds extracted Role or ClusterRole data for analysis by checkers.
type RoleInfo struct {
	Name      string
	Namespace string // empty for ClusterRole
	Kind      string // "Role" or "ClusterRole"
	Rules     []PolicyRule
}

// BindingInfo holds extracted RoleBinding or ClusterRoleBinding data.
type BindingInfo struct {
	Name      string
	Namespace string // empty for ClusterRoleBinding
	Kind      string // "RoleBinding" or "ClusterRoleBinding"
	RoleRef   RoleRef
	Subjects  []Subject
}

// RoleRef identifies which Role or ClusterRole a binding refers to.
type RoleRef struct {
	APIGroup string
	Kind     string // "Role" or "ClusterRole"
	Name     string
}

// Subject identifies a user, group, or service account in a binding.
type Subject struct {
	APIGroup  string
	Kind      string // "User", "Group", or "ServiceAccount"
	Name      string
	Namespace string
}

// ExtractRoles extracts RoleInfo from all Roles and ClusterRoles in the cache.
func ExtractRoles(cache *checker.ResourceCache) []RoleInfo {
	var roles []RoleInfo

	for _, obj := range cache.List(RoleGVR) {
		if r, ok := parseRole(obj, "Role"); ok {
			roles = append(roles, r)
		}
	}
	for _, obj := range cache.List(ClusterRoleGVR) {
		if r, ok := parseRole(obj, "ClusterRole"); ok {
			roles = append(roles, r)
		}
	}

	return roles
}

// ExtractBindings extracts BindingInfo from all RoleBindings and ClusterRoleBindings in the cache.
func ExtractBindings(cache *checker.ResourceCache) []BindingInfo {
	var bindings []BindingInfo

	for _, obj := range cache.List(RoleBindingGVR) {
		if b, ok := parseBinding(obj, "RoleBinding"); ok {
			bindings = append(bindings, b)
		}
	}
	for _, obj := range cache.List(ClusterRoleBindingGVR) {
		if b, ok := parseBinding(obj, "ClusterRoleBinding"); ok {
			bindings = append(bindings, b)
		}
	}

	return bindings
}

// parseRole extracts RoleInfo from an unstructured Role or ClusterRole object.
func parseRole(obj unstructured.Unstructured, kind string) (RoleInfo, bool) {
	rules, found, _ := unstructured.NestedSlice(obj.Object, "rules")
	if !found {
		return RoleInfo{}, false
	}

	role := RoleInfo{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		Kind:      kind,
	}

	for _, r := range rules {
		ruleMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		role.Rules = append(role.Rules, PolicyRule{
			APIGroups:     toStringSlice(ruleMap["apiGroups"]),
			Resources:     toStringSlice(ruleMap["resources"]),
			Verbs:         toStringSlice(ruleMap["verbs"]),
			ResourceNames: toStringSlice(ruleMap["resourceNames"]),
		})
	}

	return role, true
}

// parseBinding extracts BindingInfo from an unstructured RoleBinding or ClusterRoleBinding object.
func parseBinding(obj unstructured.Unstructured, kind string) (BindingInfo, bool) {
	binding := BindingInfo{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		Kind:      kind,
	}

	// Parse roleRef.
	roleRefMap, found, _ := unstructured.NestedMap(obj.Object, "roleRef")
	if !found {
		return BindingInfo{}, false
	}
	binding.RoleRef = RoleRef{
		APIGroup: stringFromMap(roleRefMap, "apiGroup"),
		Kind:     stringFromMap(roleRefMap, "kind"),
		Name:     stringFromMap(roleRefMap, "name"),
	}

	// Parse subjects.
	subjects, found, _ := unstructured.NestedSlice(obj.Object, "subjects")
	if found {
		for _, s := range subjects {
			subMap, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			binding.Subjects = append(binding.Subjects, Subject{
				APIGroup:  stringFromMap(subMap, "apiGroup"),
				Kind:      stringFromMap(subMap, "kind"),
				Name:      stringFromMap(subMap, "name"),
				Namespace: stringFromMap(subMap, "namespace"),
			})
		}
	}

	return binding, true
}

// toStringSlice converts an interface{} (expected []interface{}) to []string.
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	slice, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// stringFromMap extracts a string value from a map by key, returning "" if not found.
func stringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// containsString checks if a string slice contains a specific value.
func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// containsAny checks if a string slice contains any of the specified values.
func containsAny(slice []string, vals ...string) bool {
	for _, v := range vals {
		if containsString(slice, v) {
			return true
		}
	}
	return false
}
