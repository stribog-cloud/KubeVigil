package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestClusterAdminChecker_Interface(t *testing.T) {
	c := &ClusterAdminChecker{}
	assert.Equal(t, "rbac-cluster-admin", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Equal(t, []checker.Category{checker.CategoryRBAC}, c.Categories())
	assert.Equal(t, []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}, c.SupportedModes())
	assert.Equal(t, BindingGVRs(), c.RequiredResources())
}

func TestClusterAdminChecker_Run(t *testing.T) {
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
			name: "ClusterRoleBinding to cluster-admin produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("admin-binding", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "User", "name": "admin@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "rbac-cluster-admin", findings[0].Checker)
				assert.Equal(t, "admin-binding", findings[0].Resource)
				assert.Equal(t, "ClusterRoleBinding", findings[0].Kind)
				assert.Equal(t, ".roleRef", findings[0].FieldPath)
				assert.Contains(t, findings[0].Message, "cluster-admin")
			},
		},
		{
			name: "RoleBinding to cluster-admin produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("ns-admin-binding", "production", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "User", "name": "dev@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "production", findings[0].Namespace)
				assert.Equal(t, "RoleBinding", findings[0].Kind)
			},
		},
		{
			name: "binding to non-cluster-admin produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("viewer-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "viewer@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "binding to Role named cluster-admin produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("misleading-binding", "default", "Role", "cluster-admin", []map[string]interface{}{
					{"kind": "User", "name": "dev@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple bindings only cluster-admin ones trigger findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb1 := makeClusterRoleBinding("admin-binding", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "User", "name": "admin@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				crb2 := makeClusterRoleBinding("viewer-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "viewer@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				crb3 := makeClusterRoleBinding("edit-binding", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "Group", "name": "developers", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb1)
				cache.Add(ClusterRoleBindingGVR, crb2)
				cache.Add(ClusterRoleBindingGVR, crb3)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "admin-binding", findings[0].Resource)
			},
		},
		{
			name: "multiple cluster-admin bindings produce multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb1 := makeClusterRoleBinding("admin-binding-1", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "User", "name": "admin1@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				crb2 := makeClusterRoleBinding("admin-binding-2", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "User", "name": "admin2@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb1)
				cache.Add(ClusterRoleBindingGVR, crb2)
				return cache
			},
			wantFindings: 2,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "binding to ClusterRole with similar name does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("almost-admin", "ClusterRole", "cluster-admin-readonly", []map[string]interface{}{
					{"kind": "User", "name": "user@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "mixed RoleBinding and ClusterRoleBinding to cluster-admin",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("rb-admin", "kube-system", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "admin-sa", "namespace": "kube-system"},
				})
				crb := makeClusterRoleBinding("crb-admin", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "Group", "name": "system:masters", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, rb)
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 2,
			wantSeverity: checker.SeverityCritical,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				kinds := make(map[string]bool)
				for idx := range findings {
					kinds[findings[idx].Kind] = true
				}
				assert.True(t, kinds["RoleBinding"])
				assert.True(t, kinds["ClusterRoleBinding"])
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
			c := &ClusterAdminChecker{}
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
