package image

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func TestTagMissingChecker_Metadata(t *testing.T) {
	c := &TagMissingChecker{}

	assert.Equal(t, "image-tag-missing", c.Name())
	assert.NotEmpty(t, c.Description())
	assert.Contains(t, c.Categories(), checker.CategoryImage)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeLive)
	assert.Contains(t, c.SupportedModes(), checker.ScanModeManifest)
	assert.NotEmpty(t, c.RequiredResources())
}

func TestTagMissingChecker_Run(t *testing.T) {
	c := &TagMissingChecker{}
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func() *checker.ResourceCache
		wantFindings  int
		wantContainer string
		wantResource  string
	}{
		{
			name: "no tag and no digest triggers finding",
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
			name: "explicit :latest has a tag — does NOT trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("latest-pod"),
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings: 0,
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
			name: "init container without tag triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("init-pod"),
					helpers.WithInitContainer(helpers.NewContainer("init-setup", helpers.WithContainerImage("busybox"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "init-setup",
		},
		{
			name: "sidecar container without tag triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("sidecar-pod"),
					helpers.WithSidecarContainer(helpers.NewContainer("envoy", helpers.WithContainerImage("envoy"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "envoy",
		},
		{
			name: "multiple containers — only untagged ones trigger",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				pod := helpers.GeneratePod(
					helpers.WithName("multi-pod"),
					helpers.WithContainer(helpers.NewContainer("good", helpers.WithContainerImage("nginx:1.25"))),
					helpers.WithInitContainer(helpers.NewContainer("bad-init", helpers.WithContainerImage("busybox"))),
				)
				cache.Add(podGVR, toUnstructured(t, pod))
				return cache
			},
			wantFindings:  1,
			wantContainer: "bad-init",
		},
		{
			name: "deployment without tag triggers finding",
			setup: func() *checker.ResourceCache {
				cache := checker.NewResourceCache()
				dep := helpers.GenerateDeployment(
					helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("myapp"))),
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
			name: "fixture: pod-no-tag.yaml triggers finding",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-tag-missing", "pod-no-tag.yaml")
			},
			wantFindings: 1,
			wantResource: "missing-tag-pod",
		},
		{
			name: "fixture: pod-with-tag.yaml does not trigger",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-tag-missing", "pod-with-tag.yaml")
			},
			wantFindings: 0,
		},
		{
			name: "fixture: pod-digest-only.yaml does not trigger",
			setup: func() *checker.ResourceCache {
				return helpers.LoadFixture(t, "image-tag-missing", "pod-digest-only.yaml")
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
				assert.Equal(t, "image-tag-missing", findings[0].Checker)
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

func TestTagMissingChecker_CancelledContext(t *testing.T) {
	c := &TagMissingChecker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	_, err := c.Run(ctx, cache)
	assert.Error(t, err)
}

func TestTagMissingChecker_FieldPath(t *testing.T) {
	c := &TagMissingChecker{}
	ctx := context.Background()

	cache := checker.NewResourceCache()
	pod := helpers.GeneratePod(
		helpers.WithName("fp-pod"),
		helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("nginx"))),
	)
	cache.Add(podGVR, toUnstructured(t, pod))

	findings, err := c.Run(ctx, cache)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotEmpty(t, findings[0].FieldPath)
	assert.Contains(t, findings[0].FieldPath, "image")
}
