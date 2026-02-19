package workload

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestResourceLimitsMissingChecker_Metadata(t *testing.T) {
	c := &ResourceLimitsMissingChecker{}

	assert.Equal(t, "resource-limits-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestResourceLimitsMissingChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &ResourceLimitsMissingChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
		checkMessage  string
	}{
		{
			name: "no limits triggers finding mentioning both",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-limits-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "no-limits-pod",
			checkMessage:  "both CPU and memory",
		},
		{
			name: "cpu and memory limits set produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("limits-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceLimits("500m", "128Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "only cpu limit set triggers finding mentioning memory",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				podObj := helpers.GeneratePod(
					helpers.WithName("cpu-only-pod"),
				)
				podObj.Spec.Containers[0].Resources.Limits = corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse("500m"),
				}
				cache.Add(podGVR, toUnstructured(t, podObj))
				return cache
			},
			wantFindings: 1,
			checkMessage: "memory",
		},
		{
			name: "only memory limit set triggers finding mentioning CPU",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				podObj := helpers.GeneratePod(
					helpers.WithName("mem-only-pod"),
				)
				podObj.Spec.Containers[0].Resources.Limits = corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				}
				cache.Add(podGVR, toUnstructured(t, podObj))
				return cache
			},
			wantFindings: 1,
			checkMessage: "CPU",
		},
		{
			name: "deployment without limits triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "init container without limits triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithResourceLimits("500m", "128Mi"))),
					helpers.WithInitContainer(helpers.NewContainer("init-setup")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without limits triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithResourceLimits("500m", "128Mi"))),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "resource-limits-missing", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "no-limits-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "resource-limits-missing", "pod-passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "resource-limits-missing", "deployment-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "no-limits-deploy",
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
				assert.Equal(t, "resource-limits-missing", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)

				if tt.checkMessage != "" {
					assert.Contains(t, findings[0].Message, tt.checkMessage)
				}
				if tt.wantContainer != "" {
					helpers.AssertFindingForContainer(t, findings, tt.wantContainer)
				}
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestResourceLimitsMissingChecker_CancelledContext(t *testing.T) {
	c := &ResourceLimitsMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestResourceLimitsMissingChecker_AllWorkloadTypes(t *testing.T) {
	c := &ResourceLimitsMissingChecker{}
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
				return helpers.GenerateStatefulSet(
					helpers.WithContainer(helpers.NewContainer("app")),
				)
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet(
					helpers.WithContainer(helpers.NewContainer("app")),
				)
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob(
					helpers.WithContainer(helpers.NewContainer("app")),
				)
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob(
					helpers.WithContainer(helpers.NewContainer("app")),
				)
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
