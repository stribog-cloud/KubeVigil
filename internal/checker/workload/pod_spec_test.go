package workload

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
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

func TestExtractPodSpecs(t *testing.T) {
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	t.Run("extracts from Pod", func(t *testing.T) {
		cache := checker.NewResourceCache()
		pod := helpers.GeneratePod(helpers.WithName("test-pod"))
		cache.Add(podGVR, toUnstructured(t, pod))

		specs := ExtractPodSpecs(cache)
		require.Len(t, specs, 1)
		assert.Equal(t, "test-pod", specs[0].ResourceName)
		assert.Equal(t, "default", specs[0].Namespace)
		assert.Equal(t, "Pod", specs[0].Kind)
		require.Len(t, specs[0].Spec.Containers, 1)
	})

	t.Run("extracts from Deployment", func(t *testing.T) {
		cache := checker.NewResourceCache()
		dep := helpers.GenerateDeployment()
		cache.Add(deployGVR, toUnstructured(t, dep))

		specs := ExtractPodSpecs(cache)
		require.Len(t, specs, 1)
		assert.Equal(t, "test-deployment", specs[0].ResourceName)
		assert.Equal(t, "Deployment", specs[0].Kind)
	})

	t.Run("extracts from multiple resource types", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(podGVR, toUnstructured(t, helpers.GeneratePod()))
		cache.Add(deployGVR, toUnstructured(t, helpers.GenerateDeployment()))

		specs := ExtractPodSpecs(cache)
		assert.Len(t, specs, 2)
	})

	t.Run("empty cache returns empty", func(t *testing.T) {
		cache := checker.NewResourceCache()
		specs := ExtractPodSpecs(cache)
		assert.Empty(t, specs)
	})
}

func TestIterateContainers(t *testing.T) {
	t.Run("iterates regular containers", func(t *testing.T) {
		pod := helpers.GeneratePod()
		u := toUnstructured(t, pod)
		specs := extractFromUnstructured(u, "Pod")
		require.Len(t, specs, 1)

		var names []string
		IterateContainers(&specs[0], func(c corev1.Container, ct ContainerType, idx int) {
			names = append(names, c.Name)
			assert.Equal(t, ContainerTypeRegular, ct)
		})
		assert.Equal(t, []string{"app"}, names)
	})

	t.Run("iterates init containers", func(t *testing.T) {
		initC := helpers.NewContainer("init-db", helpers.WithContainerImage("busybox:latest"))
		pod := helpers.GeneratePod(helpers.WithInitContainer(initC))
		u := toUnstructured(t, pod)
		specs := extractFromUnstructured(u, "Pod")
		require.Len(t, specs, 1)

		var types []ContainerType
		IterateContainers(&specs[0], func(c corev1.Container, ct ContainerType, idx int) {
			types = append(types, ct)
		})
		assert.Contains(t, types, ContainerTypeInit)
		assert.Contains(t, types, ContainerTypeRegular)
	})

	t.Run("identifies sidecar containers", func(t *testing.T) {
		sidecar := helpers.NewContainer("envoy", helpers.WithContainerImage("envoy:1.28"))
		pod := helpers.GeneratePod(helpers.WithSidecarContainer(sidecar))
		u := toUnstructured(t, pod)
		specs := extractFromUnstructured(u, "Pod")
		require.Len(t, specs, 1)

		var types []ContainerType
		var names []string
		IterateContainers(&specs[0], func(c corev1.Container, ct ContainerType, idx int) {
			types = append(types, ct)
			names = append(names, c.Name)
		})
		assert.Contains(t, types, ContainerTypeSidecar)
		assert.Contains(t, names, "envoy")
	})
}
