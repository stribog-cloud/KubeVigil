package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestUnusedRolesChecker_Interface(t *testing.T) {
	c := &UnusedRolesChecker{}
	assert.Equal(t, "rbac-unused-roles", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Equal(t, []checker.Category{checker.CategoryRBAC}, c.Categories())
	assert.Equal(t, []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}, c.SupportedModes())
	assert.Equal(t, AllGVRs(), c.RequiredResources())
}

func TestUnusedRolesChecker_Run(t *testing.T) {
	tests := []struct {
		name           string
		setup          func() *checker.ResourceCache
		wantFindings   int
		wantSeverity   checker.Severity
		cancelContext  bool
		wantErr        bool
		verifyFindings func(t *testing.T, findings []checker.Finding)
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name:          "cancelled context returns error",
			cancelContext: true,
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantErr: true,
		},
		{
			name: "Role with matching RoleBinding produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("pod-reader", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
				})
				rb := makeRoleBinding("read-pods", "default", "Role", "pod-reader", []map[string]interface{}{
					{"kind": "User", "name": "jane", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleGVR, role)
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role without any binding produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("orphan-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityInfo,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "rbac-unused-roles", findings[0].Checker)
				assert.Equal(t, "orphan-role", findings[0].Resource)
				assert.Equal(t, "default", findings[0].Namespace)
				assert.Equal(t, "Role", findings[0].Kind)
				assert.Contains(t, findings[0].Message, "no bindings")
			},
		},
		{
			name: "ClusterRole without binding produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("orphan-cluster-role", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityInfo,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "orphan-cluster-role", findings[0].Resource)
				assert.Equal(t, "ClusterRole", findings[0].Kind)
				assert.Empty(t, findings[0].Namespace)
			},
		},
		{
			name: "system role without binding is skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("system:controller:node-controller", []map[string]interface{}{
					makeRule([]string{""}, []string{"nodes"}, []string{"get", "list", "watch"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with binding in different namespace is still unused",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("deploy-reader", "production", []map[string]interface{}{
					makeRule([]string{"apps"}, []string{"deployments"}, []string{"get", "list"}),
				})
				rb := makeRoleBinding("read-deploys", "staging", "Role", "deploy-reader", []map[string]interface{}{
					{"kind": "User", "name": "dev@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleGVR, role)
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityInfo,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "deploy-reader", findings[0].Resource)
				assert.Equal(t, "production", findings[0].Namespace)
			},
		},
		{
			name: "ClusterRole referenced by ClusterRoleBinding is not unused",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("cluster-viewer", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods", "services"}, []string{"get", "list"}),
				})
				crb := makeClusterRoleBinding("viewer-binding", "ClusterRole", "cluster-viewer", []map[string]interface{}{
					{"kind": "Group", "name": "developers", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleGVR, cr)
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ClusterRole referenced by RoleBinding is not unused",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("editor", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "update"}),
				})
				rb := makeRoleBinding("ns-editor", "default", "ClusterRole", "editor", []map[string]interface{}{
					{"kind": "User", "name": "dev@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleGVR, cr)
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple roles some used some unused",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				usedRole := makeRole("used-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				unusedRole := makeRole("unused-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"secrets"}, []string{"get"}),
				})
				rb := makeRoleBinding("used-binding", "default", "Role", "used-role", []map[string]interface{}{
					{"kind": "User", "name": "user@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleGVR, usedRole)
				cache.Add(RoleGVR, unusedRole)
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityInfo,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "unused-role", findings[0].Resource)
			},
		},
		{
			name: "multiple system roles all skipped",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr1 := makeClusterRole("system:basic-user", []map[string]interface{}{
					makeRule([]string{""}, []string{"selfsubjectaccessreviews"}, []string{"create"}),
				})
				cr2 := makeClusterRole("system:discovery", []map[string]interface{}{
					makeRule([]string{""}, []string{"nonresourceurls"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr1)
				cache.Add(ClusterRoleGVR, cr2)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role referenced by binding with wrong roleRef.kind is unused",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("my-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				// Binding references a ClusterRole, not a Role
				rb := makeRoleBinding("wrong-kind-binding", "default", "ClusterRole", "my-role", []map[string]interface{}{
					{"kind": "User", "name": "user@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleGVR, role)
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityInfo,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "my-role", findings[0].Resource)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			cache := tt.setup()
			c := &UnusedRolesChecker{}
			findings, err := c.Run(ctx, cache)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				assert.Equal(t, tt.wantSeverity, findings[0].Severity)
			}
			if tt.verifyFindings != nil && len(findings) > 0 {
				tt.verifyFindings(t, findings)
			}
		})
	}
}
