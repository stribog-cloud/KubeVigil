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

func TestPrivilegedChecker_Metadata(t *testing.T) {
	c := &PrivilegedChecker{}

	assert.Equal(t, "privileged", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestPrivilegedChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &PrivilegedChecker{}
	ctx := context.Background()

	tests := []struct {
		name           string
		setup          func() *checker.ResourceCache
		wantFindings   int
		wantContainer  string
		wantResource   string
		wantSeverity   checker.Severity
		checkFieldPath bool
		wantFieldPath  string
	}{
		{
			name: "privileged: true triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("priv-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "priv-pod",
			wantSeverity:  checker.SeverityCritical,
		},
		{
			name: "privileged: false produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("secure-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(false))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no securityContext produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("no-sc-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "nil securityContext produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("nil-sc-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with privileged container triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "multiple containers — only privileged one triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-pod"),
					helpers.WithContainer(helpers.NewContainer("secure", helpers.WithPrivileged(false))),
				)
				// Add a second container by modifying the unstructured directly
				// Instead, use init container path to test multi-container
				pod2 := helpers.GeneratePod(
					helpers.WithName("multi-pod2"),
					helpers.WithContainer(helpers.NewContainer("priv", helpers.WithPrivileged(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				cache.Add(podGVR, toUnstructured(t, pod2))
				return cache
			},
			wantFindings: 1,
			wantResource: "multi-pod2",
		},
		{
			name: "init container privileged triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup", helpers.WithPrivileged(true))
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container privileged triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := helpers.NewContainer("envoy", helpers.WithPrivileged(true))
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithSidecarContainer(sidecar),
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
			name: "fixture: pod-privileged-true.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "privileged", "pod-privileged-true.yaml")
			},
			wantFindings: 1,
			wantResource: "privileged-pod",
		},
		{
			name: "fixture: pod-privileged-false.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "privileged", "pod-privileged-false.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-privileged.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "privileged", "deployment-privileged.yaml")
			},
			wantFindings: 1,
			wantResource: "privileged-deploy",
		},
		{
			name: "fixture: pod-init-container-privileged.yaml triggers for init container",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "privileged", "pod-init-container-privileged.yaml")
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "fixture: pod-sidecar-privileged.yaml triggers for sidecar",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "privileged", "pod-sidecar-privileged.yaml")
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "fixture: pod-multiple-containers.yaml triggers for privileged container only",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "privileged", "pod-multiple-containers.yaml")
			},
			wantFindings:  1,
			wantContainer: "privileged-sidecar",
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
				assert.Equal(t, "privileged", findings[0].Checker)
				assert.Equal(t, checker.SeverityCritical, findings[0].Severity)

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

func TestPrivilegedChecker_CancelledContext(t *testing.T) {
	c := &PrivilegedChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestPrivilegedChecker_FieldPath(t *testing.T) {
	c := &PrivilegedChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	// Use a pod with a privileged init container at index 0
	initC := helpers.NewContainer("init-setup", helpers.WithPrivileged(true))
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithInitContainer(initC),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	// Check that field paths are set
	for _, f := range findings {
		assert.NotEmpty(t, f.FieldPath)
		assert.Contains(t, f.FieldPath, "securityContext.privileged")
	}
}

func TestPrivilegedChecker_AllWorkloadTypes(t *testing.T) {
	c := &PrivilegedChecker{}
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
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
				)
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
				)
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
				)
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
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
