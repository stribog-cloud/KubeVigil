package image

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestNoDigestChecker_Metadata(t *testing.T) {
	c := &NoDigestChecker{}

	assert.Equal(t, "image-no-digest", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryImage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestNoDigestChecker_Run(t *testing.T) {
	c := &NoDigestChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "image with tag but no digest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("no-digest-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "no-digest-pod",
		},
		{
			name: "image with no tag and no digest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("bare-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "app",
			wantResource:  "bare-pod",
		},
		{
			name: "image with :latest and no digest triggers finding",
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
		},
		{
			name: "image with digest does not trigger",
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
			name: "image with tag and digest does not trigger",
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
			name: "init container without digest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx@sha256:abcdef1234567890"))),
					helpers.WithInitContainer(helpers.NewContainer("init-setup", helpers.WithContainerImage("busybox:1.36"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without digest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx@sha256:abcdef1234567890"))),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy", helpers.WithContainerImage("envoy:v1.28"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "multiple containers — only ones without digest trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-pod"),
					helpers.WithContainer(helpers.NewContainer("pinned", helpers.WithContainerImage("nginx@sha256:abcdef1234567890"))),
					helpers.WithInitContainer(helpers.NewContainer("unpinned", helpers.WithContainerImage("busybox:1.36"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "unpinned",
		},
		{
			name: "deployment without digest triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("myapp:v2"))),
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
			name: "fixture: pod-no-digest.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-no-digest", "pod-no-digest.yaml")
			},
			wantFindings: 1,
			wantResource: "no-digest-pod",
		},
		{
			name: "fixture: pod-with-digest.yaml does not trigger",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-no-digest", "pod-with-digest.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-tag-and-digest.yaml does not trigger",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-no-digest", "pod-tag-and-digest.yaml")
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
				assert.Equal(t, "image-no-digest", findings[0].Checker)
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

func TestNoDigestChecker_CancelledContext(t *testing.T) {
	c := &NoDigestChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestNoDigestChecker_FieldPath(t *testing.T) {
	c := &NoDigestChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:1.25"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotEmpty(t, findings[0].FieldPath)
	assert.Contains(t, findings[0].FieldPath, "image")
}
