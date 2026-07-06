package workload

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func boolPtr(v bool) *bool { return &v }

func TestHostUsersNotIsolatedChecker_Metadata(t *testing.T) {
	c := &HostUsersNotIsolatedChecker{}

	assert.Equal(t, "host-users-not-isolated", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestHostUsersNotIsolatedChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &HostUsersNotIsolatedChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
	}{
		{
			name: "hostUsers unset triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("unset-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "unset-pod",
		},
		{
			name: "hostUsers explicitly true triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("true-pod"))
				pod.Spec.HostUsers = boolPtr(true)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "true-pod",
		},
		{
			name: "hostUsers false produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("isolated-pod"))
				pod.Spec.HostUsers = boolPtr(false)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with hostUsers unset triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment()
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "deployment with hostUsers false produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment()
				dep.Spec.Template.Spec.HostUsers = boolPtr(false)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple pods — only unisolated ones trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				isolated := helpers.GeneratePod(helpers.WithName("isolated"))
				isolated.Spec.HostUsers = boolPtr(false)
				shared := helpers.GeneratePod(helpers.WithName("shared"))
				cache.Add(podGVR, toUnstructured(t, isolated))
				cache.Add(podGVR, toUnstructured(t, shared))
				return cache
			},
			wantFindings: 1,
			wantResource: "shared",
		},
		{
			name: "namespace is propagated to finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("ns-pod"), helpers.WithNamespace("prod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "ns-pod",
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fixture: failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-users-not-isolated", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "shared-userns-pod",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-users-not-isolated", "passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "two unisolated pods produce two findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod1 := helpers.GeneratePod(helpers.WithName("pod-a"))
				pod2 := helpers.GeneratePod(helpers.WithName("pod-b"))
				cache.Add(podGVR, toUnstructured(t, pod1))
				cache.Add(podGVR, toUnstructured(t, pod2))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "hostUsers true alongside other fields still triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("mixed-pod"),
					helpers.WithHostNetwork(false),
				)
				pod.Spec.HostUsers = boolPtr(true)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "mixed-pod",
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
				assert.Equal(t, "host-users-not-isolated", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)
				assert.Empty(t, findings[0].Container, "host-users-not-isolated is a pod-level check")
				assert.Equal(t, ".spec.hostUsers", findings[0].FieldPath)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestHostUsersNotIsolatedChecker_CancelledContext(t *testing.T) {
	c := &HostUsersNotIsolatedChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestHostUsersNotIsolatedChecker_AllWorkloadTypes(t *testing.T) {
	c := &HostUsersNotIsolatedChecker{}
	ctx := context.Background()

	workloadTypes := []struct {
		name     string
		gvr      schema.GroupVersionResource
		generate func() interface{}
	}{
		{
			name: "StatefulSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"},
			generate: func() interface{} {
				return helpers.GenerateStatefulSet()
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet()
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob()
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob()
			},
		},
	}

	for _, wt := range workloadTypes {
		t.Run(wt.name, func(t *testing.T) {
			cache := checker.NewResourceCache()
			cache.Add(wt.gvr, toUnstructured(t, wt.generate()))

			findings, err := c.Run(ctx, cache)
			require.NoError(t, err)
			assert.Len(t, findings, 1, "expected finding for %s", wt.name)
			if len(findings) > 0 {
				assert.Equal(t, wt.name, findings[0].Kind)
			}
		})
	}
}
