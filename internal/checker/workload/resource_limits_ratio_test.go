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

func TestResourceLimitsRatioChecker_Metadata(t *testing.T) {
	c := &ResourceLimitsRatioChecker{}

	assert.Equal(t, "resource-limits-ratio", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestResourceLimitsRatioChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &ResourceLimitsRatioChecker{}
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
			name: "high cpu ratio triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("high-cpu-ratio"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "128Mi"),
						helpers.WithResourceLimits("500m", "128Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "high-cpu-ratio",
			checkMessage:  "CPU",
		},
		{
			name: "high memory ratio triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("high-mem-ratio"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("500m", "64Mi"),
						helpers.WithResourceLimits("500m", "512Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "high-mem-ratio",
			checkMessage:  "memory",
		},
		{
			name: "both high ratios triggers one finding mentioning both",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("high-both"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("500m", "512Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			checkMessage: "CPU",
		},
		{
			name: "ratio at exactly 3x produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("exact-3x"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("300m", "192Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "low ratio (2x) produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("low-ratio"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("250m", "128Mi"),
						helpers.WithResourceLimits("500m", "256Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no limits set skips check (no finding)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-limits"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "only limits set without requests skips check",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("only-limits"),
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
			name: "only requests set without limits skips check",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("only-requests"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "zero request value skips check",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				podObj := helpers.GeneratePod(
					helpers.WithName("zero-request"),
				)
				podObj.Spec.Containers[0].Resources.Requests = corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("0"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				}
				podObj.Spec.Containers[0].Resources.Limits = corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("500m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				}
				cache.Add(podGVR, toUnstructured(t, podObj))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with high ratio triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("1", "640Mi"),
					)),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "init container with high ratio triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("200m", "128Mi"),
					)),
					helpers.WithInitContainer(helpers.NewContainer("init-setup",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("500m", "512Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container with high ratio triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("200m", "128Mi"),
					)),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("500m", "512Mi"),
					)),
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
				return helpers.LoadFixture(t, "resource-limits-ratio", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "high-ratio-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "resource-limits-ratio", "pod-passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "resource-limits-ratio", "deployment-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "high-ratio-deploy",
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
				assert.Equal(t, "resource-limits-ratio", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)

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

func TestResourceLimitsRatioChecker_CancelledContext(t *testing.T) {
	c := &ResourceLimitsRatioChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestResourceLimitsRatioChecker_AllWorkloadTypes(t *testing.T) {
	c := &ResourceLimitsRatioChecker{}
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
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("500m", "512Mi"),
					)),
				)
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet(
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("500m", "512Mi"),
					)),
				)
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob(
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("500m", "512Mi"),
					)),
				)
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob(
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "64Mi"),
						helpers.WithResourceLimits("500m", "512Mi"),
					)),
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
