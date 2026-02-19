package workload

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestRunAsGroupChecker_Metadata(t *testing.T) {
	c := &RunAsGroupChecker{}

	assert.Equal(t, "run-as-group", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestRunAsGroupChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &RunAsGroupChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "no securityContext triggers finding (runAsGroup missing)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-sc-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "no-sc-pod",
		},
		{
			name: "container runAsGroup: 1000 produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("group-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsGroup(1000))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container runAsGroup: 0 triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("gid0-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsGroup(0))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "pod-level runAsGroup: 1000 produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				var gid int64 = 1000
				pod := helpers.GeneratePod(
					helpers.WithName("pod-gid-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsGroup: &gid,
					}),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod-level runAsGroup: 0 triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				var gid int64
				pod := helpers.GeneratePod(
					helpers.WithName("pod-gid0-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsGroup: &gid,
					}),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "container overrides pod-level runAsGroup: 0 with non-zero produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				var podGID int64
				pod := helpers.GeneratePod(
					helpers.WithName("override-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsGroup: &podGID,
					}),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsGroup(1000))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container overrides pod-level runAsGroup with 0 triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				var podGID int64 = 1000
				pod := helpers.GeneratePod(
					helpers.WithName("override-gid0-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsGroup: &podGID,
					}),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsGroup(0))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "deployment with missing runAsGroup triggers finding",
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
			name: "init container without runAsGroup triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup")
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsGroup(1000))),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without runAsGroup triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := helpers.NewContainer("envoy")
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsGroup(1000))),
					helpers.WithSidecarContainer(sidecar),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "init container inherits pod-level runAsGroup: 1000 produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				var gid int64 = 1000
				initC := helpers.NewContainer("init-setup")
				pod := helpers.GeneratePod(
					helpers.WithName("init-inherit-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsGroup: &gid,
					}),
					helpers.WithContainer(helpers.NewContainer("app")),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
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
				return helpers.LoadFixture(t, "run-as-group", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "no-group-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "run-as-group", "pod-passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "run-as-group", "deployment-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "gid-zero-deploy",
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
				assert.Equal(t, "run-as-group", findings[0].Checker)
				assert.Equal(t, checker.SeverityMedium, findings[0].Severity)

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

func TestRunAsGroupChecker_CancelledContext(t *testing.T) {
	c := &RunAsGroupChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app")),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestRunAsGroupChecker_FieldPath(t *testing.T) {
	c := &RunAsGroupChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	// Init container with missing group + regular container with gid 0
	initC := helpers.NewContainer("init-setup")
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithInitContainer(initC),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsGroup(0))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.NotEmpty(t, f.FieldPath)
		assert.Contains(t, f.FieldPath, "securityContext.runAsGroup")
	}
}

func TestRunAsGroupChecker_AllWorkloadTypes(t *testing.T) {
	c := &RunAsGroupChecker{}
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
