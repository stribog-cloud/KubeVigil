package image

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/test/helpers"
)

func toUnstructured(t *testing.T, obj interface{}) unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	var result unstructured.Unstructured
	require.NoError(t, json.Unmarshal(data, &result.Object))
	return result
}

var podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
var deployGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

func TestExtractContainerImages(t *testing.T) {
	t.Run("pod with single container", func(t *testing.T) {
		cache := checker.NewResourceCache()
		pod := helpers.GeneratePod(
			helpers.WithName("web"),
			helpers.WithContainer(helpers.NewContainer("nginx", helpers.WithContainerImage("nginx:1.25"))),
		)
		cache.Add(podGVR, toUnstructured(t, pod))

		images := ExtractContainerImages(cache)
		require.Len(t, images, 1)

		img := images[0]
		assert.Equal(t, "nginx", img.ContainerName)
		assert.Equal(t, "web", img.ResourceName)
		assert.Equal(t, "default", img.Namespace)
		assert.Equal(t, "Pod", img.Kind)
		assert.Equal(t, workload.ContainerTypeRegular, img.ContainerType)
		assert.Equal(t, 0, img.ContainerIdx)
		assert.Equal(t, "nginx:1.25", img.Ref.Raw)
		assert.Equal(t, "1.25", img.Ref.Tag)
		assert.Equal(t, "library/nginx", img.Ref.Repository)
	})

	t.Run("deployment with init and regular containers", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := helpers.GenerateDeployment(
			helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("gcr.io/myproject/app:v2"))),
			helpers.WithInitContainer(helpers.NewContainer("init-db", helpers.WithContainerImage("busybox:latest"))),
		)
		cache.Add(deployGVR, toUnstructured(t, dep))

		images := ExtractContainerImages(cache)
		require.Len(t, images, 2)

		// Regular container should be first (IterateContainers does regular, then init).
		var regularFound, initFound bool
		for _, img := range images {
			switch img.ContainerType {
			case workload.ContainerTypeRegular:
				regularFound = true
				assert.Equal(t, "app", img.ContainerName)
				assert.Equal(t, "gcr.io", img.Ref.Registry)
				assert.Equal(t, "myproject/app", img.Ref.Repository)
				assert.Equal(t, "v2", img.Ref.Tag)
				assert.Equal(t, "Deployment", img.Kind)
				assert.Equal(t, "test-deployment", img.ResourceName)
			case workload.ContainerTypeInit:
				initFound = true
				assert.Equal(t, "init-db", img.ContainerName)
				assert.Equal(t, "library/busybox", img.Ref.Repository)
				assert.Equal(t, "latest", img.Ref.Tag)
			}
		}
		assert.True(t, regularFound, "regular container not found")
		assert.True(t, initFound, "init container not found")
	})

	t.Run("sidecar container detected", func(t *testing.T) {
		cache := checker.NewResourceCache()
		pod := helpers.GeneratePod(
			helpers.WithName("sidecar-pod"),
			helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("myapp:v1"))),
			helpers.WithSidecarContainer(helpers.NewContainer("envoy", helpers.WithContainerImage("envoyproxy/envoy:v1.28"))),
		)
		cache.Add(podGVR, toUnstructured(t, pod))

		images := ExtractContainerImages(cache)
		require.Len(t, images, 2)

		var sidecarFound bool
		for _, img := range images {
			if img.ContainerType == workload.ContainerTypeSidecar {
				sidecarFound = true
				assert.Equal(t, "envoy", img.ContainerName)
				assert.Equal(t, "envoyproxy/envoy", img.Ref.Repository)
				assert.Equal(t, "v1.28", img.Ref.Tag)
			}
		}
		assert.True(t, sidecarFound, "sidecar container not found")
	})

	t.Run("empty cache returns empty slice", func(t *testing.T) {
		cache := checker.NewResourceCache()
		images := ExtractContainerImages(cache)
		assert.Empty(t, images)
	})

	t.Run("multiple resources", func(t *testing.T) {
		cache := checker.NewResourceCache()
		pod1 := helpers.GeneratePod(
			helpers.WithName("pod1"),
			helpers.WithContainer(helpers.NewContainer("c1", helpers.WithContainerImage("img1:v1"))),
		)
		pod2 := helpers.GeneratePod(
			helpers.WithName("pod2"),
			helpers.WithContainer(helpers.NewContainer("c2", helpers.WithContainerImage("img2:v2"))),
		)
		cache.Add(podGVR, toUnstructured(t, pod1))
		cache.Add(podGVR, toUnstructured(t, pod2))

		images := ExtractContainerImages(cache)
		assert.Len(t, images, 2)

		names := make(map[string]bool)
		for _, img := range images {
			names[img.ContainerName] = true
		}
		assert.True(t, names["c1"], "c1 not found")
		assert.True(t, names["c2"], "c2 not found")
	})

	t.Run("pull policy captured", func(t *testing.T) {
		cache := checker.NewResourceCache()
		c := helpers.NewContainer("app", helpers.WithContainerImage("nginx:latest"))
		c.ImagePullPolicy = corev1.PullAlways
		pod := helpers.GeneratePod(
			helpers.WithName("policy-pod"),
			helpers.WithContainer(c),
		)
		cache.Add(podGVR, toUnstructured(t, pod))

		images := ExtractContainerImages(cache)
		require.Len(t, images, 1)
		assert.Equal(t, "Always", images[0].PullPolicy)
	})

	t.Run("namespace preserved", func(t *testing.T) {
		cache := checker.NewResourceCache()
		pod := helpers.GeneratePod(
			helpers.WithName("ns-pod"),
			helpers.WithNamespace("production"),
			helpers.WithContainer(helpers.NewContainer("app", helpers.WithContainerImage("myapp:v1"))),
		)
		cache.Add(podGVR, toUnstructured(t, pod))

		images := ExtractContainerImages(cache)
		require.Len(t, images, 1)
		assert.Equal(t, "production", images[0].Namespace)
	})

	t.Run("digest-only image parsed correctly", func(t *testing.T) {
		cache := checker.NewResourceCache()
		pod := helpers.GeneratePod(
			helpers.WithName("digest-pod"),
			helpers.WithContainer(helpers.NewContainer("app",
				helpers.WithContainerImage("gcr.io/myproject/app@sha256:abcdef1234567890"))),
		)
		cache.Add(podGVR, toUnstructured(t, pod))

		images := ExtractContainerImages(cache)
		require.Len(t, images, 1)
		assert.Equal(t, "sha256:abcdef1234567890", images[0].Ref.Digest)
		assert.Equal(t, "", images[0].Ref.Tag)
		assert.Equal(t, "gcr.io", images[0].Ref.Registry)
		assert.False(t, images[0].Ref.IsMutableTag())
	})
}

func TestRegistryMatches(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		pattern  string
		want     bool
	}{
		{
			name:     "exact match",
			registry: "gcr.io",
			pattern:  "gcr.io",
			want:     true,
		},
		{
			name:     "case insensitive match",
			registry: "GCR.IO",
			pattern:  "gcr.io",
			want:     true,
		},
		{
			name:     "docker hub normalization: index.docker.io matches docker.io",
			registry: "index.docker.io",
			pattern:  "docker.io",
			want:     true,
		},
		{
			name:     "docker hub normalization: registry-1.docker.io matches docker.io",
			registry: "registry-1.docker.io",
			pattern:  "docker.io",
			want:     true,
		},
		{
			name:     "docker hub normalization: registry.hub.docker.com matches docker.io",
			registry: "registry.hub.docker.com",
			pattern:  "docker.io",
			want:     true,
		},
		{
			name:     "empty registry matches docker.io",
			registry: "",
			pattern:  "docker.io",
			want:     true,
		},
		{
			name:     "docker.io matches empty",
			registry: "docker.io",
			pattern:  "",
			want:     true,
		},
		{
			name:     "trailing slash stripped",
			registry: "gcr.io/",
			pattern:  "gcr.io",
			want:     true,
		},
		{
			name:     "different registries do not match",
			registry: "gcr.io",
			pattern:  "quay.io",
			want:     false,
		},
		{
			name:     "registry with port",
			registry: "localhost:5000",
			pattern:  "localhost:5000",
			want:     true,
		},
		{
			name:     "registry with port mismatch",
			registry: "localhost:5000",
			pattern:  "localhost:5001",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, registryMatches(tt.registry, tt.pattern))
		})
	}
}

func TestNormalizeRegistry(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"docker.io stays", "docker.io", "docker.io"},
		{"index.docker.io normalizes", "index.docker.io", "docker.io"},
		{"registry-1.docker.io normalizes", "registry-1.docker.io", "docker.io"},
		{"registry.hub.docker.com normalizes", "registry.hub.docker.com", "docker.io"},
		{"empty normalizes to docker.io", "", "docker.io"},
		{"trailing slash stripped", "gcr.io/", "gcr.io"},
		{"other registry unchanged", "quay.io", "quay.io"},
		{"ecr unchanged", "123456.dkr.ecr.us-east-1.amazonaws.com", "123456.dkr.ecr.us-east-1.amazonaws.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeRegistry(tt.input))
		})
	}
}
