package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestSubjectExternalChecker_Interface(t *testing.T) {
	c := &SubjectExternalChecker{}
	assert.Equal(t, "rbac-subject-external", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Equal(t, []checker.Category{checker.CategoryRBAC}, c.Categories())
	assert.Equal(t, []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}, c.SupportedModes())
	assert.Equal(t, BindingGVRs(), c.RequiredResources())
}

func TestSubjectExternalChecker_Run(t *testing.T) {
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
			name: "binding with external User subject produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("admin-binding", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "User", "name": "admin@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityLow,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "rbac-subject-external", findings[0].Checker)
				assert.Equal(t, "admin-binding", findings[0].Resource)
				assert.Equal(t, "ClusterRoleBinding", findings[0].Kind)
				assert.Equal(t, ".subjects", findings[0].FieldPath)
				assert.Contains(t, findings[0].Message, "admin@example.com")
				assert.Contains(t, findings[0].Message, "external user")
			},
		},
		{
			name: "binding with system user produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("system-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "system:admin", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "binding with system:serviceaccount user produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("sa-user-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "system:serviceaccount:default:my-sa", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "binding with ServiceAccount subject produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("sa-binding", "default", "Role", "viewer", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "deployer", "namespace": "default"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "binding with Group subject produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("group-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "Group", "name": "developers", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple external users in one binding produce multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("multi-user-binding", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "User", "name": "alice@example.com", "apiGroup": "rbac.authorization.k8s.io"},
					{"kind": "User", "name": "bob@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 2,
			wantSeverity: checker.SeverityLow,
		},
		{
			name: "mixed subjects only User subjects trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("mixed-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "admin@example.com", "apiGroup": "rbac.authorization.k8s.io"},
					{"kind": "Group", "name": "developers", "apiGroup": "rbac.authorization.k8s.io"},
					{"kind": "ServiceAccount", "name": "sa", "namespace": "default"},
					{"kind": "User", "name": "system:kube-proxy", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1, // only admin@example.com; system: prefix is excluded
			wantSeverity: checker.SeverityLow,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Contains(t, findings[0].Message, "admin@example.com")
			},
		},
		{
			name: "RoleBinding with external user produces finding with namespace",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("ns-user-binding", "production", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "User", "name": "dev@corp.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityLow,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "production", findings[0].Namespace)
				assert.Equal(t, "RoleBinding", findings[0].Kind)
				assert.Contains(t, findings[0].Message, "dev@corp.com")
			},
		},
		{
			name: "User with plain name (not email) still triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("plain-user-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "john-doe", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityLow,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Contains(t, findings[0].Message, "john-doe")
			},
		},
		{
			name: "multiple bindings with external users",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb1 := makeClusterRoleBinding("binding-1", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "user1@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				crb2 := makeClusterRoleBinding("binding-2", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "User", "name": "user2@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb1)
				cache.Add(ClusterRoleBindingGVR, crb2)
				return cache
			},
			wantFindings: 2,
			wantSeverity: checker.SeverityLow,
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
			c := &SubjectExternalChecker{}
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
