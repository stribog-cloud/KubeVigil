package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestEscalationVerbsChecker_Metadata(t *testing.T) {
	c := &EscalationVerbsChecker{}

	assert.Equal(t, "rbac-escalation-verbs", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestEscalationVerbsChecker_Run(t *testing.T) {
	c := &EscalationVerbsChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantKind     string
		wantMessage  string // substring to check in message
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "Role with bind verb triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("binder-role", "default", []map[string]interface{}{
					makeRule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "binder-role",
			wantKind:     "Role",
			wantMessage:  "bind",
		},
		{
			name: "Role with escalate verb triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("escalator-role", "default", []map[string]interface{}{
					makeRule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "escalator-role",
			wantMessage:  "escalate",
		},
		{
			name: "ClusterRole with impersonate verb triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("impersonator", []map[string]interface{}{
					makeRule([]string{""}, []string{"users"}, []string{"impersonate"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "impersonator",
			wantKind:     "ClusterRole",
			wantMessage:  "impersonate",
		},
		{
			name: "Role with normal verbs produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("normal-role", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list", "watch", "create", "update", "delete"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple escalation verbs in one rule produce single finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("multi-escalation", "default", []map[string]interface{}{
					makeRule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind", "escalate", "impersonate"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "multi-escalation",
		},
		{
			name: "escalation verb in second rule triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("second-rule", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
					makeRule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "both Role and ClusterRole with escalation produce two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("role-esc", "ns1", []map[string]interface{}{
					makeRule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}),
				})
				cr := makeClusterRole("cr-esc", []map[string]interface{}{
					makeRule([]string{""}, []string{"users"}, []string{"impersonate"}),
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
				assert.Equal(t, "rbac-escalation-verbs", findings[0].Checker)
				assert.Equal(t, checker.SeverityCritical, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantKind != "" {
					assert.Equal(t, tt.wantKind, findings[0].Kind)
				}
				if tt.wantMessage != "" {
					assert.Contains(t, findings[0].Message, tt.wantMessage)
				}
			}
		})
	}
}

func TestEscalationVerbsChecker_CancelledContext(t *testing.T) {
	c := &EscalationVerbsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"roles"}, []string{"bind"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestEscalationVerbsChecker_FieldPath(t *testing.T) {
	c := &EscalationVerbsChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
		makeRule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].verbs", findings[0].FieldPath)
}

func TestEscalationVerbsChecker_Fixtures(t *testing.T) {
	c := &EscalationVerbsChecker{}
	ctx := context.Background()

	t.Run("fixture: role-escalation-verbs.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-escalation-verbs", "role-escalation-verbs.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "escalation-verbs-role")
	})

	t.Run("fixture: role-normal-verbs.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-escalation-verbs", "role-normal-verbs.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
