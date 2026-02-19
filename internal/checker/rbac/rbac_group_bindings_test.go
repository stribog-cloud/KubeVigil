package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestGroupBindingsChecker_Interface(t *testing.T) {
	c := &GroupBindingsChecker{}
	assert.Equal(t, "rbac-group-bindings", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Equal(t, []checker.Category{checker.CategoryRBAC}, c.Categories())
	assert.Equal(t, []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}, c.SupportedModes())
	assert.Equal(t, BindingGVRs(), c.RequiredResources())
}

func TestGroupBindingsChecker_Run(t *testing.T) {
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
			name: "binding to system:authenticated produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("auth-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityHigh,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "rbac-group-bindings", findings[0].Checker)
				assert.Equal(t, "auth-binding", findings[0].Resource)
				assert.Equal(t, "ClusterRoleBinding", findings[0].Kind)
				assert.Equal(t, ".subjects", findings[0].FieldPath)
				assert.Contains(t, findings[0].Message, "system:authenticated")
			},
		},
		{
			name: "binding to system:unauthenticated produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("unauth-binding", "ClusterRole", "discovery", []map[string]interface{}{
					{"kind": "Group", "name": "system:unauthenticated", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityHigh,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Contains(t, findings[0].Message, "system:unauthenticated")
			},
		},
		{
			name: "binding to system:anonymous produces finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("anon-binding", "ClusterRole", "basic-user", []map[string]interface{}{
					{"kind": "Group", "name": "system:anonymous", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityHigh,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Contains(t, findings[0].Message, "system:anonymous")
			},
		},
		{
			name: "binding to specific group produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("dev-binding", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "Group", "name": "developers", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "binding to system:masters produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("masters-binding", "ClusterRole", "cluster-admin", []map[string]interface{}{
					{"kind": "Group", "name": "system:masters", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "binding to ServiceAccount subject produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("sa-binding", "default", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "ServiceAccount", "name": "deployer", "namespace": "default"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "binding to User subject produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("user-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "admin@example.com", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "one finding per binding with multiple broad groups",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("multi-group-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"},
					{"kind": "Group", "name": "system:unauthenticated", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1, // breaks after first match per binding
			wantSeverity: checker.SeverityHigh,
		},
		{
			name: "multiple bindings with broad groups produce multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb1 := makeClusterRoleBinding("binding-1", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"},
				})
				crb2 := makeClusterRoleBinding("binding-2", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "Group", "name": "system:unauthenticated", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb1)
				cache.Add(ClusterRoleBindingGVR, crb2)
				return cache
			},
			wantFindings: 2,
			wantSeverity: checker.SeverityHigh,
		},
		{
			name: "RoleBinding with broad group also triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				rb := makeRoleBinding("ns-auth-binding", "production", "ClusterRole", "edit", []map[string]interface{}{
					{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(RoleBindingGVR, rb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityHigh,
			verifyFindings: func(t *testing.T, findings []checker.Finding) {
				assert.Equal(t, "production", findings[0].Namespace)
				assert.Equal(t, "RoleBinding", findings[0].Kind)
			},
		},
		{
			name: "mixed subjects with broad group triggers on group only",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				crb := makeClusterRoleBinding("mixed-binding", "ClusterRole", "view", []map[string]interface{}{
					{"kind": "User", "name": "admin@example.com", "apiGroup": "rbac.authorization.k8s.io"},
					{"kind": "ServiceAccount", "name": "sa", "namespace": "default"},
					{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"},
				})
				cache.Add(ClusterRoleBindingGVR, crb)
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityHigh,
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
			c := &GroupBindingsChecker{}
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
