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

func TestCSRApprovalChecker_Metadata(t *testing.T) {
	c := &CSRApprovalChecker{}

	assert.Equal(t, "rbac-csr-approval", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), RoleGVR)
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestCSRApprovalChecker_Run(t *testing.T) {
	c := &CSRApprovalChecker{}
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
			name: "Role with update on certificatesigningrequests/approval triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("csr-approver", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
			wantResource: "csr-approver",
			wantKind:     "Role",
		},
		{
			name: "Role with approve on signers triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("signer-approver", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"approve"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with wildcard verb on signers triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("signer-wildcard", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"*"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "ClusterRole with update on approval triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("cluster-csr-approver", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "cluster-csr-approver",
			wantKind:     "ClusterRole",
		},
		{
			name: "signers with resourceNames still triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("signer-scoped", "default", []map[string]interface{}{
					makeRuleWithResourceNames([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"approve"}, []string{"kubernetes.io/kube-apiserver-client"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "Role with read-only CSR access produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("csr-reader", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests"}, []string{"get", "list", "watch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with create on certificatesigningrequests produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("csr-creator", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests"}, []string{"create"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with get on signers produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("signer-reader", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"get", "list"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "Role with get on pods produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("pod-reader", "default", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
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
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}),
					makeRuleWithResourceNames([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"approve"}, []string{"kubernetes.io/kube-apiserver-client"}),
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
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}),
				})
				role2 := makeRole("role-b", "ns2", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"approve"}),
				})
				cache.Add(RoleGVR, role1)
				cache.Add(RoleGVR, role2)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "patch on approval produces no findings (not update/approve/*)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("approval-patch", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"patch"}),
				})
				cache.Add(RoleGVR, role)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "resource mixed with other resources triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("mixed-resources", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests", "signers"}, []string{"approve"}),
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
			name: "verb mixed with wildcard on approval triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				role := makeRole("approval-wildcard-mix", "default", []map[string]interface{}{
					makeRule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"get", "*"}),
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
				assert.Equal(t, "rbac-csr-approval", findings[0].Checker)
				assert.Equal(t, checker.SeverityCritical, findings[0].Severity)

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

func TestCSRApprovalChecker_CancelledContext(t *testing.T) {
	c := &CSRApprovalChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	role := makeRole("test-role", "default", []map[string]interface{}{
		makeRule([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"approve"}),
	})
	cache.Add(RoleGVR, role)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestCSRApprovalChecker_FieldPath(t *testing.T) {
	c := &CSRApprovalChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	role := makeRole("fp-role", "default", []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
		makeRule([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"approve"}),
	})
	cache.Add(RoleGVR, role)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".rules[1].resources", findings[0].FieldPath)
}

func TestCSRApprovalChecker_Fixtures(t *testing.T) {
	c := &CSRApprovalChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-csr-approval", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "csr-approval-failing-role")
		assert.Equal(t, "ClusterRole", findings[0].Kind)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-csr-approval", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

func TestCSRApprovalChecker_RequiredGVRs(t *testing.T) {
	c := &CSRApprovalChecker{}
	gvrs := c.RequiredResources()

	expected := []schema.GroupVersionResource{RoleGVR, ClusterRoleGVR}
	assert.Equal(t, expected, gvrs)
}
