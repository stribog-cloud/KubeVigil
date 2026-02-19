package checker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
var deployGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

func makeUnstructured(apiVersion, kind, name, namespace string) unstructured.Unstructured {
	obj := unstructured.Unstructured{}
	obj.SetAPIVersion(apiVersion)
	obj.SetKind(kind)
	obj.SetName(name)
	obj.SetNamespace(namespace)
	return obj
}

func TestNewResourceCache(t *testing.T) {
	cache := NewResourceCache()
	require.NotNil(t, cache)
	assert.Equal(t, 0, cache.Len())
	assert.Empty(t, cache.GVRs())
}

func TestResourceCache_Add_and_List(t *testing.T) {
	t.Run("add single resource", func(t *testing.T) {
		cache := NewResourceCache()
		pod := makeUnstructured("v1", "Pod", "nginx", "default")
		cache.Add(podGVR, pod)

		result := cache.List(podGVR)
		require.Len(t, result, 1)
		assert.Equal(t, "nginx", result[0].GetName())
		assert.Equal(t, 1, cache.Len())
	})

	t.Run("add multiple resources same GVR", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-c", "kube-system"))

		result := cache.List(podGVR)
		assert.Len(t, result, 3)
		assert.Equal(t, 3, cache.Len())
	})

	t.Run("add multiple GVRs", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(deployGVR, makeUnstructured("apps/v1", "Deployment", "deploy-a", "default"))

		pods := cache.List(podGVR)
		assert.Len(t, pods, 1)
		deploys := cache.List(deployGVR)
		assert.Len(t, deploys, 1)
		assert.Equal(t, 2, cache.Len())
	})

	t.Run("list unknown GVR returns nil", func(t *testing.T) {
		cache := NewResourceCache()
		result := cache.List(podGVR)
		assert.Nil(t, result)
	})
}

func TestResourceCache_ListNamespaced(t *testing.T) {
	cache := NewResourceCache()
	cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
	cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "default"))
	cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-c", "kube-system"))

	t.Run("returns resources in matching namespace", func(t *testing.T) {
		result := cache.ListNamespaced(podGVR, "default")
		assert.Len(t, result, 2)
	})

	t.Run("returns resources in other namespace", func(t *testing.T) {
		result := cache.ListNamespaced(podGVR, "kube-system")
		assert.Len(t, result, 1)
		assert.Equal(t, "pod-c", result[0].GetName())
	})

	t.Run("returns nil for unknown namespace", func(t *testing.T) {
		result := cache.ListNamespaced(podGVR, "nonexistent")
		assert.Nil(t, result)
	})

	t.Run("returns nil for unknown GVR", func(t *testing.T) {
		result := cache.ListNamespaced(deployGVR, "default")
		assert.Nil(t, result)
	})
}

func TestResourceCache_GVRs(t *testing.T) {
	cache := NewResourceCache()
	cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
	cache.Add(deployGVR, makeUnstructured("apps/v1", "Deployment", "deploy-a", "default"))

	gvrs := cache.GVRs()
	assert.Len(t, gvrs, 2)
	assert.Contains(t, gvrs, podGVR)
	assert.Contains(t, gvrs, deployGVR)
}

func TestGVRForKind(t *testing.T) {
	tests := []struct {
		name       string
		apiVersion string
		kind       string
		wantGVR    schema.GroupVersionResource
		wantErr    bool
	}{
		{
			name:       "v1 Pod",
			apiVersion: "v1",
			kind:       "Pod",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
		},
		{
			name:       "apps/v1 Deployment",
			apiVersion: "apps/v1",
			kind:       "Deployment",
			wantGVR:    schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		},
		{
			name:       "apps/v1 StatefulSet",
			apiVersion: "apps/v1",
			kind:       "StatefulSet",
			wantGVR:    schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"},
		},
		{
			name:       "apps/v1 DaemonSet",
			apiVersion: "apps/v1",
			kind:       "DaemonSet",
			wantGVR:    schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
		},
		{
			name:       "batch/v1 Job",
			apiVersion: "batch/v1",
			kind:       "Job",
			wantGVR:    schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"},
		},
		{
			name:       "batch/v1 CronJob",
			apiVersion: "batch/v1",
			kind:       "CronJob",
			wantGVR:    schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
		},
		{
			name:       "unknown kind derives GVR",
			apiVersion: "custom.io/v1beta1",
			kind:       "Widget",
			wantGVR:    schema.GroupVersionResource{Group: "custom.io", Version: "v1beta1", Resource: "widgets"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gvr, err := GVRForKind(tt.apiVersion, tt.kind)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantGVR, gvr)
		})
	}
}
