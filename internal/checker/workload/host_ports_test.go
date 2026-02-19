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

func TestHostPortsChecker_Metadata(t *testing.T) {
	c := &HostPortsChecker{}

	assert.Equal(t, "host-ports", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestHostPortsChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &HostPortsChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
		wantSeverity  checker.Severity
	}{
		{
			name: "container with hostPort triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("port-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithHostPort(8080))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "port-pod",
			wantSeverity:  checker.SeverityHigh,
		},
		{
			name: "container without hostPort produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("secure-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "container with containerPort only produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("cp-pod"))
				// Default container "app" has no ports
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with hostPort triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithHostPort(9090))),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "multiple host ports on same container produce multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-port-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithHostPort(8080),
						helpers.WithHostPort(9090),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "init container with hostPort triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup", helpers.WithHostPort(3000))
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
			name: "sidecar container with hostPort triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := helpers.NewContainer("envoy", helpers.WithHostPort(15001))
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
			name: "fixture: pod-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-ports", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "host-port-pod",
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-ports", "pod-passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-ports", "deployment-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "host-port-deploy",
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
				assert.Equal(t, "host-ports", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)
				assert.Contains(t, findings[0].Message, "host port")
				assert.NotEmpty(t, findings[0].FieldPath)

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

func TestHostPortsChecker_CancelledContext(t *testing.T) {
	c := &HostPortsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithHostPort(8080))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestHostPortsChecker_FieldPath(t *testing.T) {
	c := &HostPortsChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	initC := helpers.NewContainer("init-setup", helpers.WithHostPort(3000))
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithInitContainer(initC),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithHostPort(8080))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.NotEmpty(t, f.FieldPath)
		assert.Contains(t, f.FieldPath, "ports")
	}
}

func TestHostPortsChecker_AllWorkloadTypes(t *testing.T) {
	c := &HostPortsChecker{}
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
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithHostPort(8080))),
				)
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithHostPort(8080))),
				)
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithHostPort(8080))),
				)
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithHostPort(8080))),
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
