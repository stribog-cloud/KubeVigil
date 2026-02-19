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

func TestRunAsRootChecker_Metadata(t *testing.T) {
	c := &RunAsRootChecker{}

	assert.Equal(t, "run-as-root", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestRunAsRootChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &RunAsRootChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "no securityContext triggers finding (defaults to root)",
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
			name: "container runAsNonRoot: true produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("nonroot-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsNonRoot(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod-level runAsNonRoot: true produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				runAsNonRoot := true
				pod := helpers.GeneratePod(
					helpers.WithName("pod-level-nonroot"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
					}),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod-level runAsNonRoot: true but container overrides with runAsUser: 0 triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				runAsNonRoot := true
				pod := helpers.GeneratePod(
					helpers.WithName("override-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
					}),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsUser(0))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "container runAsUser: 1000 produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("uid-1000-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsUser(1000))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container runAsUser: 0 triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("uid-0-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsUser(0))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "runAsUser: 0 with runAsNonRoot: true still triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("conflict-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithRunAsUser(0),
						helpers.WithRunAsNonRoot(true),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "pod-level runAsUser: 1000 produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				var uid int64 = 1000
				pod := helpers.GeneratePod(
					helpers.WithName("pod-uid-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsUser: &uid,
					}),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod-level runAsUser: 0 triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				var uid int64
				pod := helpers.GeneratePod(
					helpers.WithName("pod-uid0-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsUser: &uid,
					}),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "container runAsUser overrides pod-level runAsUser",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				var podUID int64 = 1000
				pod := helpers.GeneratePod(
					helpers.WithName("override-uid-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsUser: &podUID,
					}),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsUser(0))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "container runAsNonRoot: false does not protect",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("nonroot-false-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsNonRoot(false))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "container overrides pod runAsNonRoot: true with runAsNonRoot: false triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				runAsNonRoot := true
				pod := helpers.GeneratePod(
					helpers.WithName("override-nonroot-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
					}),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsNonRoot(false))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "deployment with runAsUser: 0 triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsUser(0))),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "init container without securityContext triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup")
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsNonRoot(true))),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without runAsNonRoot triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := helpers.NewContainer("envoy")
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsNonRoot(true))),
					helpers.WithSidecarContainer(sidecar),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "init container inherits pod-level runAsNonRoot: true produces no finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				runAsNonRoot := true
				initC := helpers.NewContainer("init-setup")
				pod := helpers.GeneratePod(
					helpers.WithName("init-inherit-pod"),
					helpers.WithPodSecurityContext(&corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
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
				return helpers.LoadFixture(t, "run-as-root", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "root-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "run-as-root", "pod-passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "run-as-root", "deployment-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "root-deploy",
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
				assert.Equal(t, "run-as-root", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

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

func TestRunAsRootChecker_CancelledContext(t *testing.T) {
	c := &RunAsRootChecker{}
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

func TestRunAsRootChecker_FieldPath(t *testing.T) {
	c := &RunAsRootChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	// Pod with runAsUser: 0 (container) and no runAsNonRoot (init container)
	initC := helpers.NewContainer("init-setup")
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithInitContainer(initC),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithRunAsUser(0))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.NotEmpty(t, f.FieldPath)
		assert.Contains(t, f.FieldPath, "securityContext.runAs")
	}
}

func TestRunAsRootChecker_AllWorkloadTypes(t *testing.T) {
	c := &RunAsRootChecker{}
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
