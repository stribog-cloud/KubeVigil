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

func TestEphemeralStorageRequestsMissingChecker_Metadata(t *testing.T) {
	c := &EphemeralStorageRequestsMissingChecker{}

	assert.Equal(t, "ephemeral-storage-requests-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestEphemeralStorageRequestsMissingChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &EphemeralStorageRequestsMissingChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "no ephemeral-storage request triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-request-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "no-request-pod",
		},
		{
			name: "ephemeral-storage request set produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				podObj := helpers.GeneratePod(helpers.WithName("request-set-pod"))
				podObj.Spec.Containers[0].Resources.Requests = corev1.ResourceList{
					corev1.ResourceEphemeralStorage: resource.MustParse("500Mi"),
				}
				cache.Add(podGVR, toUnstructured(t, podObj))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "limit set but no request still triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				podObj := helpers.GeneratePod(helpers.WithName("limit-only-pod"))
				podObj.Spec.Containers[0].Resources.Limits = corev1.ResourceList{
					corev1.ResourceEphemeralStorage: resource.MustParse("2Gi"),
				}
				cache.Add(podGVR, toUnstructured(t, podObj))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "cpu and memory requests but no ephemeral-storage triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-eph-request-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithResourceRequests("100m", "128Mi"),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "all requests including ephemeral-storage produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				podObj := helpers.GeneratePod(helpers.WithName("all-requests-pod"))
				podObj.Spec.Containers[0].Resources.Requests = corev1.ResourceList{
					corev1.ResourceCPU:              resource.MustParse("100m"),
					corev1.ResourceMemory:           resource.MustParse("128Mi"),
					corev1.ResourceEphemeralStorage: resource.MustParse("500Mi"),
				}
				cache.Add(podGVR, toUnstructured(t, podObj))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment without ephemeral-storage request triggers finding",
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
			name: "init container without ephemeral-storage request triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				podObj := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
					helpers.WithInitContainer(helpers.NewContainer("init-setup")),
				)
				podObj.Spec.Containers[0].Resources.Requests = corev1.ResourceList{
					corev1.ResourceEphemeralStorage: resource.MustParse("500Mi"),
				}
				cache.Add(podGVR, toUnstructured(t, podObj))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without ephemeral-storage request triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				podObj := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy")),
				)
				podObj.Spec.Containers[0].Resources.Requests = corev1.ResourceList{
					corev1.ResourceEphemeralStorage: resource.MustParse("500Mi"),
				}
				cache.Add(podGVR, toUnstructured(t, podObj))
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
			name: "fixture: failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "ephemeral-storage-requests-missing", "failing.yaml")
			},
			wantFindings: 1,
			wantResource: "no-ephemeral-storage-request-pod",
		},
		{
			name: "fixture: passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "ephemeral-storage-requests-missing", "passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "multiple containers — only missing-request one triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				withReq := helpers.GeneratePod(helpers.WithName("with-req"))
				withReq.Spec.Containers[0].Resources.Requests = corev1.ResourceList{
					corev1.ResourceEphemeralStorage: resource.MustParse("500Mi"),
				}
				withoutReq := helpers.GeneratePod(helpers.WithName("without-req"))
				cache.Add(podGVR, toUnstructured(t, withReq))
				cache.Add(podGVR, toUnstructured(t, withoutReq))
				return cache
			},
			wantFindings: 1,
			wantResource: "without-req",
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
				assert.Equal(t, "ephemeral-storage-requests-missing", findings[0].Checker)
				assert.Equal(t, checker.SeverityLow, findings[0].Severity)

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

func TestEphemeralStorageRequestsMissingChecker_CancelledContext(t *testing.T) {
	c := &EphemeralStorageRequestsMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestEphemeralStorageRequestsMissingChecker_AllWorkloadTypes(t *testing.T) {
	c := &EphemeralStorageRequestsMissingChecker{}
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
