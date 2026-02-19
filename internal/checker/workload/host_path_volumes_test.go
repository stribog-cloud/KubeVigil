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

func TestHostPathVolumesChecker_Metadata(t *testing.T) {
	c := &HostPathVolumesChecker{}

	assert.Equal(t, "host-path-volumes", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestHostPathVolumesChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &HostPathVolumesChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		wantSeverity checker.Severity
	}{
		{
			name: "hostPath volume triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("hp-pod"),
					helpers.WithHostPathVolume("data", "/tmp/data"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "hp-pod",
			wantSeverity: checker.SeverityMedium,
		},
		{
			name: "no hostPath volume produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(helpers.WithName("secure-pod"))
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "root path is Critical",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("root-pod"),
					helpers.WithHostPathVolume("root", "/"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "/etc path is Critical",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("etc-pod"),
					helpers.WithHostPathVolume("etc", "/etc"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "/etc/kubernetes is Critical",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("etc-k8s-pod"),
					helpers.WithHostPathVolume("k8s-etc", "/etc/kubernetes"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "docker.sock is Critical",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("docker-pod"),
					helpers.WithHostPathVolume("docker", "/var/run/docker.sock"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "containerd.sock is Critical",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("containerd-pod"),
					helpers.WithHostPathVolume("containerd", "/run/containerd/containerd.sock"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "/var/log is High",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("log-pod"),
					helpers.WithHostPathVolume("logs", "/var/log"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityHigh,
		},
		{
			name: "/var/log/pods is High",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("log-pods-pod"),
					helpers.WithHostPathVolume("logs", "/var/log/pods"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityHigh,
		},
		{
			name: "generic path is Medium",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("generic-pod"),
					helpers.WithHostPathVolume("data", "/opt/data"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityMedium,
		},
		{
			name: "multiple hostPath volumes produce multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-vol-pod"),
					helpers.WithHostPathVolume("data", "/tmp/data"),
					helpers.WithHostPathVolume("logs", "/var/log"),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 2,
		},
		{
			name: "deployment with hostPath triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithHostPathVolume("data", "/tmp/data"),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
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
				return helpers.LoadFixture(t, "host-path-volumes", "pod-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "host-path-pod",
			wantSeverity: checker.SeverityMedium,
		},
		{
			name: "fixture: pod-passing.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-path-volumes", "pod-passing.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-critical-docker-sock.yaml is Critical",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-path-volumes", "pod-critical-docker-sock.yaml")
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "fixture: pod-critical-etc.yaml is Critical",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-path-volumes", "pod-critical-etc.yaml")
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "fixture: pod-critical-root.yaml is Critical",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-path-volumes", "pod-critical-root.yaml")
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityCritical,
		},
		{
			name: "fixture: pod-high-var-log.yaml is High",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-path-volumes", "pod-high-var-log.yaml")
			},
			wantFindings: 1,
			wantSeverity: checker.SeverityHigh,
		},
		{
			name: "fixture: deployment-failing.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "host-path-volumes", "deployment-failing.yaml")
			},
			wantFindings: 1,
			wantResource: "host-path-deploy",
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
				assert.Equal(t, "host-path-volumes", findings[0].Checker)
				assert.Empty(t, findings[0].Container, "host-path-volumes is a pod-level check, Container should be empty")
				assert.Contains(t, findings[0].FieldPath, ".spec.volumes[")
				assert.Contains(t, findings[0].FieldPath, "hostPath")
				assert.Contains(t, findings[0].Message, "hostPath")

				if tt.wantSeverity != 0 {
					assert.Equal(t, tt.wantSeverity, findings[0].Severity,
						"expected severity %s but got %s", tt.wantSeverity, findings[0].Severity)
				}
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
			}
		})
	}
}

func TestHostPathVolumesChecker_CancelledContext(t *testing.T) {
	c := &HostPathVolumesChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(helpers.WithHostPathVolume("data", "/tmp"))
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestHostPathVolumesChecker_FieldPath(t *testing.T) {
	c := &HostPathVolumesChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithHostPathVolume("vol0", "/tmp/a"),
		helpers.WithHostPathVolume("vol1", "/tmp/b"),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	assert.Equal(t, ".spec.volumes[0].hostPath", findings[0].FieldPath)
	assert.Equal(t, ".spec.volumes[1].hostPath", findings[1].FieldPath)
}

func TestHostPathSeverity(t *testing.T) {
	tests := []struct {
		path     string
		expected checker.Severity
	}{
		{"/", checker.SeverityCritical},
		{"/etc", checker.SeverityCritical},
		{"/etc/kubernetes", checker.SeverityCritical},
		{"/etc/shadow", checker.SeverityCritical},
		{"/var/run/docker.sock", checker.SeverityCritical},
		{"/run/containerd/containerd.sock", checker.SeverityCritical},
		{"/var/log", checker.SeverityHigh},
		{"/var/log/pods", checker.SeverityHigh},
		{"/var/log/containers", checker.SeverityHigh},
		{"/tmp", checker.SeverityMedium},
		{"/opt/data", checker.SeverityMedium},
		{"/home/user", checker.SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := hostPathSeverity(tt.path)
			assert.Equal(t, tt.expected, got, "path %q: expected %s got %s", tt.path, tt.expected, got)
		})
	}
}

func TestHostPathVolumesChecker_AllWorkloadTypes(t *testing.T) {
	c := &HostPathVolumesChecker{}
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
				return helpers.GenerateStatefulSet(helpers.WithHostPathVolume("data", "/tmp/data"))
			},
		},
		{
			name: "DaemonSet",
			gvr:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			generate: func() interface{} {
				return helpers.GenerateDaemonSet(helpers.WithHostPathVolume("data", "/tmp/data"))
			},
		},
		{
			name: "Job",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
			generate: func() interface{} {
				return helpers.GenerateJob(helpers.WithHostPathVolume("data", "/tmp/data"))
			},
		},
		{
			name: "CronJob",
			gvr:  schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			generate: func() interface{} {
				return helpers.GenerateCronJob(helpers.WithHostPathVolume("data", "/tmp/data"))
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
