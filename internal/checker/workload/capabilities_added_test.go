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

func TestCapabilitiesAddedChecker_Metadata(t *testing.T) {
	c := &CapabilitiesAddedChecker{}

	assert.Equal(t, "capabilities-added", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryWorkload)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestCapabilitiesAddedChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &CapabilitiesAddedChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
		wantSeverity  checker.Severity
		wantMessage   string
	}{
		{
			name: "SYS_ADMIN capability triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("sys-admin-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities(
							[]corev1.Capability{"SYS_ADMIN"},
							nil,
						),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "sys-admin-pod",
			wantSeverity:  checker.SeverityHigh,
			wantMessage:   "SYS_ADMIN",
		},
		{
			name: "multiple dangerous caps triggers single finding with all listed",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-caps-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities(
							[]corev1.Capability{"SYS_ADMIN", "NET_RAW", "SYS_PTRACE"},
							nil,
						),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantMessage:  "SYS_ADMIN",
		},
		{
			name: "safe capability does not trigger finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("safe-cap-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities(
							[]corev1.Capability{"CHOWN"},
							nil,
						),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no capabilities produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-caps-pod"),
					helpers.WithContainer(helpers.NewContainer("app")),
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
			name: "only drop caps produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("drop-only-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities(
							nil,
							[]corev1.Capability{"ALL"},
						),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "deployment with dangerous caps triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities(
							[]corev1.Capability{"NET_ADMIN"},
							nil,
						),
					)),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
			wantResource: "test-deployment",
		},
		{
			name: "init container with dangerous caps triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup",
					helpers.WithCapabilities(
						[]corev1.Capability{"SYS_RAWIO"},
						nil,
					),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("init-caps-pod"),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container with dangerous caps triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := helpers.NewContainer("envoy",
					helpers.WithCapabilities(
						[]corev1.Capability{"NET_RAW"},
						nil,
					),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-caps-pod"),
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
			name: "mix of dangerous and safe caps triggers finding for dangerous only",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("mixed-caps-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities(
							[]corev1.Capability{"CHOWN", "SYS_ADMIN", "AUDIT_WRITE"},
							nil,
						),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantMessage:  "SYS_ADMIN",
		},
		{
			name: "all dangerous caps in the list",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("all-dangerous-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities(
							[]corev1.Capability{
								"SYS_ADMIN", "NET_RAW", "SYS_PTRACE", "DAC_OVERRIDE",
								"SETUID", "SETGID", "NET_ADMIN", "SYS_RAWIO",
								"MKNOD", "SYS_MODULE", "DAC_READ_SEARCH", "FOWNER",
								"LINUX_IMMUTABLE", "SYS_CHROOT", "SYS_BOOT", "KILL",
								"NET_BIND_SERVICE",
							},
							nil,
						),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "fixture: pod-dangerous-caps.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "capabilities-added", "pod-dangerous-caps.yaml")
			},
			wantFindings: 1,
			wantResource: "dangerous-caps-pod",
		},
		{
			name: "fixture: pod-safe-caps.yaml produces no findings",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "capabilities-added", "pod-safe-caps.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-dangerous-caps.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "capabilities-added", "deployment-dangerous-caps.yaml")
			},
			wantFindings: 1,
			wantResource: "dangerous-caps-deploy",
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
				assert.Equal(t, "capabilities-added", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

				if tt.wantContainer != "" {
					helpers.AssertFindingForContainer(t, findings, tt.wantContainer)
				}
				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.wantMessage != "" {
					assert.Contains(t, findings[0].Message, tt.wantMessage)
				}
			}
		})
	}
}

func TestCapabilitiesAddedChecker_CancelledContext(t *testing.T) {
	c := &CapabilitiesAddedChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app",
			helpers.WithCapabilities([]corev1.Capability{"SYS_ADMIN"}, nil),
		)),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestCapabilitiesAddedChecker_FieldPath(t *testing.T) {
	c := &CapabilitiesAddedChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	initC := helpers.NewContainer("init-setup",
		helpers.WithCapabilities([]corev1.Capability{"SYS_ADMIN"}, nil),
	)
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithInitContainer(initC),
		helpers.WithContainer(helpers.NewContainer("app",
			helpers.WithCapabilities([]corev1.Capability{"NET_RAW"}, nil),
		)),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.NotEmpty(t, f.FieldPath)
		assert.Contains(t, f.FieldPath, "securityContext.capabilities.add")
	}
}

func TestCapabilitiesAddedChecker_AllWorkloadTypes(t *testing.T) {
	c := &CapabilitiesAddedChecker{}
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
						helpers.WithCapabilities([]corev1.Capability{"SYS_ADMIN"}, nil),
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
						helpers.WithCapabilities([]corev1.Capability{"SYS_ADMIN"}, nil),
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
						helpers.WithCapabilities([]corev1.Capability{"SYS_ADMIN"}, nil),
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
						helpers.WithCapabilities([]corev1.Capability{"SYS_ADMIN"}, nil),
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

func TestCapabilitiesAddedChecker_MessageListsDangerousCaps(t *testing.T) {
	c := &CapabilitiesAddedChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	pod := helpers.GeneratePod(
		helpers.WithName("multi-cap-pod"),
		helpers.WithContainer(helpers.NewContainer("app",
			helpers.WithCapabilities(
				[]corev1.Capability{"SYS_ADMIN", "NET_RAW", "CHOWN"},
				nil,
			),
		)),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Message should list the dangerous caps but not the safe one
	assert.Contains(t, findings[0].Message, "SYS_ADMIN")
	assert.Contains(t, findings[0].Message, "NET_RAW")
	assert.NotContains(t, findings[0].Message, "CHOWN")
}
