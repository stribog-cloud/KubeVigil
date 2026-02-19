package image

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestPullPolicyChecker_Metadata(t *testing.T) {
	c := &PullPolicyChecker{}

	assert.Equal(t, "image-pull-policy", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryImage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestPullPolicyChecker_Run(t *testing.T) {
	c := &PullPolicyChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "mutable tag with IfNotPresent triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app",
					helpers.WithContainerImage("nginx:v1"),
					helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("mutable-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "mutable-pod",
		},
		{
			name: "mutable tag with Never triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app",
					helpers.WithContainerImage("nginx:v1"),
					helpers.WithImagePullPolicy(corev1.PullNever),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("never-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "never-pod",
		},
		{
			name: "mutable tag with Always does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app",
					helpers.WithContainerImage("nginx:v1"),
					helpers.WithImagePullPolicy(corev1.PullAlways),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("always-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "latest tag with default policy (K8s defaults to Always) does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("latest-default-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "latest tag with explicit IfNotPresent triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app",
					helpers.WithContainerImage("nginx:latest"),
					helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("latest-ifnp-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "latest tag with explicit Always does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app",
					helpers.WithContainerImage("nginx:latest"),
					helpers.WithImagePullPolicy(corev1.PullAlways),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("latest-always-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "no tag with default policy (K8s defaults to Always) does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("notag-default-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "digest with IfNotPresent does not trigger (immutable)",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				container := helpers.NewContainer("app",
					helpers.WithContainerImage("nginx@sha256:abcdef1234567890"),
					helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("digest-ifnp-pod"),
					helpers.WithContainer(container),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "mutable tag with default policy (K8s defaults to IfNotPresent) triggers",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("default-policy-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
		},
		{
			name: "init container with mutable tag and IfNotPresent triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				initC := helpers.NewContainer("init-setup",
					helpers.WithContainerImage("busybox:1.36"),
					helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithContainerImage("nginx@sha256:abcdef1234567890"),
					)),
					helpers.WithInitContainer(initC),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container with mutable tag and IfNotPresent triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				sidecar := helpers.NewContainer("envoy",
					helpers.WithContainerImage("envoy:v1.28"),
					helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithContainerImage("nginx@sha256:abcdef1234567890"),
					)),
					helpers.WithSidecarContainer(sidecar),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "multiple containers — only mismatched ones trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				good := helpers.NewContainer("good",
					helpers.WithContainerImage("nginx:v1"),
					helpers.WithImagePullPolicy(corev1.PullAlways),
				)
				bad := helpers.NewContainer("bad",
					helpers.WithContainerImage("busybox:1.36"),
					helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
				)
				pod := helpers.GeneratePod(
					helpers.WithName("multi-pod"),
					helpers.WithContainer(good),
					helpers.WithInitContainer(bad),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "bad",
		},
		{
			name: "deployment with mutable tag triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app",
						helpers.WithContainerImage("myapp:v2"),
						helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
					)),
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
			name: "fixture: pod-latest-ifnotpresent.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-pull-policy", "pod-latest-ifnotpresent.yaml")
			},
			wantFindings: 1,
			wantResource: "latest-ifnp-pod",
		},
		{
			name: "fixture: pod-latest-always.yaml does not trigger",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-pull-policy", "pod-latest-always.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-latest-default.yaml does not trigger (K8s defaults to Always)",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-pull-policy", "pod-latest-default.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-mutable-ifnotpresent.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-pull-policy", "pod-mutable-ifnotpresent.yaml")
			},
			wantFindings: 1,
			wantResource: "mutable-ifnp-pod",
		},
		{
			name: "fixture: pod-digest-ifnotpresent.yaml does not trigger (digest is immutable)",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-pull-policy", "pod-digest-ifnotpresent.yaml")
			},
			wantFindings: 0,
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
				assert.Equal(t, "image-pull-policy", findings[0].Checker)
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

func TestPullPolicyChecker_CancelledContext(t *testing.T) {
	c := &PullPolicyChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	container := helpers.NewContainer("app",
		helpers.WithContainerImage("nginx:v1"),
		helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
	)
	pod := helpers.GeneratePod(helpers.WithContainer(container))
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestPullPolicyChecker_FieldPath(t *testing.T) {
	c := &PullPolicyChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	container := helpers.NewContainer("app",
		helpers.WithContainerImage("nginx:v1"),
		helpers.WithImagePullPolicy(corev1.PullIfNotPresent),
	)
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithContainer(container),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotEmpty(t, findings[0].FieldPath)
	assert.Contains(t, findings[0].FieldPath, "imagePullPolicy")
}
