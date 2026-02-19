package psa

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

func TestBaselineViolationsChecker_Metadata(t *testing.T) {
	c := &BaselineViolationsChecker{}

	assert.Equal(t, "psa-baseline-violations", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryPSS)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestBaselineViolationsChecker_Run(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	c := &BaselineViolationsChecker{}
	ctx := context.Background()

	tests := []struct {
		name         string
		setup        func() *checker.ResourceCache
		wantFindings int
		wantResource string
		checkMsg     string
	}{
		{
			name: "empty cache returns no findings",
			setup: func() *checker.ResourceCache {
				return checker.NewResourceCache()
			},
			wantFindings: 0,
		},
		{
			name: "compliant pod produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("compliant-pod"),
					helpers.WithContainer(corev1.Container{
						Name:  "app",
						Image: "nginx:1.25",
					}),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "pod with hostNetwork triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("host-net-pod"),
					helpers.WithHostNetwork(true),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "host-net-pod",
			checkMsg:     "hostNetwork",
		},
		{
			name: "pod with hostPID triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("host-pid-pod"),
					helpers.WithHostPID(true),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "host-pid-pod",
			checkMsg:     "hostPID",
		},
		{
			name: "pod with hostIPC triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("host-ipc-pod"),
					helpers.WithHostIPC(true),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "host-ipc-pod",
			checkMsg:     "hostIPC",
		},
		{
			name: "pod with privileged container triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("priv-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "priv-pod",
			checkMsg:     "privileged",
		},
		{
			name: "pod with SYS_ADMIN capability triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("sysadmin-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities([]corev1.Capability{"SYS_ADMIN"}, nil),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "sysadmin-pod",
			checkMsg:     "SYS_ADMIN",
		},
		{
			name: "pod with ALL capabilities triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("all-caps-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities([]corev1.Capability{"ALL"}, nil),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "all-caps-pod",
			checkMsg:     "ALL",
		},
		{
			name: "pod with safe capabilities produces no findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("safe-caps-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithCapabilities([]corev1.Capability{"NET_BIND_SERVICE"}, nil),
					)),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "multiple violations on same pod produce multiple findings",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-violation"),
					helpers.WithHostNetwork(true),
					helpers.WithHostPID(true),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithPrivileged(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 3, // hostNetwork + hostPID + privileged
			wantResource: "multi-violation",
		},
		{
			name: "deployment with hostNetwork triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithName("net-deploy"),
					helpers.WithHostNetwork(true),
				)
				cache.Add(deployGVR, toUnstructured(t, dep))
				return cache
			},
			wantFindings: 1,
		},
		{
			name: "init container with privileged triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("init-priv"),
					helpers.WithInitContainer(helpers.NewContainer("init", helpers.WithPrivileged(true))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 1,
			wantResource: "init-priv",
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
				assert.Equal(t, "psa-baseline-violations", findings[0].Checker)
				assert.Equal(t, checker.SeverityHigh, findings[0].Severity)

				if tt.wantResource != "" {
					helpers.AssertFindingForResource(t, findings, tt.wantResource)
				}
				if tt.checkMsg != "" {
					assert.Contains(t, findings[0].Message, tt.checkMsg)
				}
			}
		})
	}
}

func TestBaselineViolationsChecker_CancelledContext(t *testing.T) {
	c := &BaselineViolationsChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(helpers.WithHostNetwork(true))
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestBaselineViolationsChecker_Fixtures(t *testing.T) {
	c := &BaselineViolationsChecker{}
	ctx := context.Background()

	t.Run("fixture: failing.yaml triggers findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-baseline-violations", "failing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
		helpers.AssertFindingForResource(t, findings, "privileged-deploy")
	})

	t.Run("fixture: passing.yaml produces no findings", func(t *testing.T) {
		cache := helpers.LoadFixture(t, "psa-baseline-violations", "passing.yaml")
		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}
