package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// makeClusterRoleWithLabels builds an unstructured ClusterRole with labels for testing.
func makeClusterRoleWithLabels(name string, labels map[string]string, rules []map[string]interface{}) unstructured.Unstructured {
	meta := map[string]interface{}{"name": name}
	if len(labels) > 0 {
		labelsIface := make(map[string]interface{}, len(labels))
		for k, v := range labels {
			labelsIface[k] = v
		}
		meta["labels"] = labelsIface
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   meta,
		"rules":      toInterfaceSlice(rules),
	}}
}

func TestAggregationLabelInjectionChecker_Metadata(t *testing.T) {
	c := &AggregationLabelInjectionChecker{}

	assert.Equal(t, "rbac-aggregation-label-injection", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryRBAC)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
	assert.Contains(t, c.RequiredResources(), ClusterRoleGVR)
}

func TestAggregationLabelInjectionChecker_Run(t *testing.T) {
	c := &AggregationLabelInjectionChecker{}
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
			name: "custom ClusterRole with aggregate-to-admin label triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("my-custom-role", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-admin": "true",
				}, []map[string]interface{}{
					makeRule([]string{"*"}, []string{"*"}, []string{"*"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
			wantResource: "my-custom-role",
			wantKind:     "ClusterRole",
		},
		{
			name: "custom ClusterRole with aggregate-to-edit label triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("my-edit-injector", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-edit": "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"secrets"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "custom ClusterRole with aggregate-to-view label triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("my-view-injector", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-view": "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "custom ClusterRole with no labels produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRole("my-plain-role", []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "custom ClusterRole with non-standard label produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("my-labeled-role", map[string]string{
					"team": "platform",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "aggregation label with value false produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("false-label-role", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-admin": "false",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "built-in admin ClusterRole with its own aggregation label is exempt",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("admin", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-admin": "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "built-in cluster-admin ClusterRole is exempt",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("cluster-admin", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-admin": "true",
				}, []map[string]interface{}{
					makeRule([]string{"*"}, []string{"*"}, []string{"*"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "built-in edit ClusterRole is exempt",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("edit", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-edit": "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "built-in view ClusterRole is exempt",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("view", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-view": "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ClusterRole with multiple aggregation labels produces single finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("multi-label-role", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-admin": "true",
					"rbac.authorization.k8s.io/aggregate-to-edit":  "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "multiple custom ClusterRoles each with aggregation label produce separate findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr1 := makeClusterRoleWithLabels("role-a", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-admin": "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cr2 := makeClusterRoleWithLabels("role-b", map[string]string{
					"rbac.authorization.k8s.io/aggregate-to-view": "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr1)
				cache.Add(ClusterRoleGVR, cr2)
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "ClusterRole with empty labels map produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("empty-labels-role", map[string]string{}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "ClusterRole with mixed real label and aggregation label triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				cr := makeClusterRoleWithLabels("mixed-labels-role", map[string]string{
					"team": "platform",
					"rbac.authorization.k8s.io/aggregate-to-view": "true",
				}, []map[string]interface{}{
					makeRule([]string{""}, []string{"pods"}, []string{"get"}),
				})
				cache.Add(ClusterRoleGVR, cr)
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
				assert.Equal(t, "rbac-aggregation-label-injection", findings[0].Checker)
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

func TestAggregationLabelInjectionChecker_CancelledContext(t *testing.T) {
	c := &AggregationLabelInjectionChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	cr := makeClusterRoleWithLabels("test-role", map[string]string{
		"rbac.authorization.k8s.io/aggregate-to-admin": "true",
	}, []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
	})
	cache.Add(ClusterRoleGVR, cr)

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestAggregationLabelInjectionChecker_FieldPath(t *testing.T) {
	c := &AggregationLabelInjectionChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	cr := makeClusterRoleWithLabels("fp-role", map[string]string{
		"rbac.authorization.k8s.io/aggregate-to-admin": "true",
	}, []map[string]interface{}{
		makeRule([]string{""}, []string{"pods"}, []string{"get"}),
	})
	cache.Add(ClusterRoleGVR, cr)

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, ".metadata.labels[rbac.authorization.k8s.io/aggregate-to-admin]", findings[0].FieldPath)
}

func TestAggregationLabelInjectionChecker_Fixtures(t *testing.T) {
	c := &AggregationLabelInjectionChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers finding", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-aggregation-label-injection", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		helpers.AssertFindingForResource(t, findings, "my-custom-role")
		assert.Equal(t, "ClusterRole", findings[0].Kind)
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "rbac-aggregation-label-injection", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

func TestAggregationLabelInjectionChecker_RequiredGVRs(t *testing.T) {
	c := &AggregationLabelInjectionChecker{}
	gvrs := c.RequiredResources()

	expected := []schema.GroupVersionResource{ClusterRoleGVR}
	assert.Equal(t, expected, gvrs)
}
