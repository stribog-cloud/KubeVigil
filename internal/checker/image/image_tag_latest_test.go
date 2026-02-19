package image

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestTagLatestChecker_Metadata(t *testing.T) {
	c := &TagLatestChecker{}

	assert.Equal(t, "image-tag-latest", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryImage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestTagLatestChecker_Run(t *testing.T) {
	c := &TagLatestChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "explicit :latest tag triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("latest-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "latest-pod",
		},
		{
			name: "no tag (implicit latest) triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-tag-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "no-tag-pod",
		},
		{
			name: "specific tag does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("tagged-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "digest-only does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("digest-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx@sha256:abcdef1234567890"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "tag + digest does not trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("both-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25@sha256:abcdef1234567890"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
		},
		{
			name: "init container with :latest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithInitContainer(helpers.NewContainer("init-setup", helpers.WithContainerImage("busybox:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container with :latest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy", helpers.WithContainerImage("envoy:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "multiple containers — only latest ones trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-pod"),
					helpers.WithContainer(helpers.NewContainer("good", helpers.WithContainerImage("nginx:1.25"))),
					helpers.WithInitContainer(helpers.NewContainer("bad-init", helpers.WithContainerImage("busybox:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "bad-init",
		},
		{
			name: "deployment with :latest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
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
			name: "fixture: pod-latest-tag.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-tag-latest", "pod-latest-tag.yaml")
			},
			wantFindings: 1,
			wantResource: "latest-tag-pod",
		},
		{
			name: "fixture: pod-no-tag.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-tag-latest", "pod-no-tag.yaml")
			},
			wantFindings: 1,
			wantResource: "no-tag-pod",
		},
		{
			name: "fixture: pod-specific-tag.yaml does not trigger",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-tag-latest", "pod-specific-tag.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: deployment-latest.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-tag-latest", "deployment-latest.yaml")
			},
			wantFindings: 1,
			wantResource: "latest-deploy",
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
				assert.Equal(t, "image-tag-latest", findings[0].Checker)
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

func TestTagLatestChecker_CancelledContext(t *testing.T) {
	c := &TagLatestChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestTagLatestChecker_FieldPath(t *testing.T) {
	c := &TagLatestChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
		helpers.WithInitContainer(helpers.NewContainer("init-setup", helpers.WithContainerImage("busybox"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.NotEmpty(t, f.FieldPath)
		assert.Contains(t, f.FieldPath, "image")
	}
}

func TestTagLatestChecker_MessageVariants(t *testing.T) {
	c := &TagLatestChecker{}
	ctx := context.Background()

	t.Run("explicit latest mentions :latest in message", func(t *testing.T) {
		cache := checker.NewResourceCache()
		pod := helpers.GeneratePod(
			helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
		)
		cache.Add(podGVR, toUnstructured(t, pod))

		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, ":latest tag")
	})

	t.Run("implicit latest mentions no tag in message", func(t *testing.T) {
		cache := checker.NewResourceCache()
		pod := helpers.GeneratePod(
			helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx"))),
		)
		cache.Add(podGVR, toUnstructured(t, pod))

		findings, err := c.Run(ctx, cache)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Message, "no image tag")
	})
}
