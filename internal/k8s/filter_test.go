package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

var rsGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}

func makeObj(apiVersion, kind, name, namespace string, owners []metav1.OwnerReference) unstructured.Unstructured {
	obj := unstructured.Unstructured{}
	obj.SetAPIVersion(apiVersion)
	obj.SetKind(kind)
	obj.SetName(name)
	obj.SetNamespace(namespace)
	if len(owners) > 0 {
		obj.SetOwnerReferences(owners)
	}
	return obj
}

func ownerRef(kind, name string) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{
		Kind:       kind,
		Name:       name,
		Controller: &controller,
	}
}

func TestFilterManagedResources(t *testing.T) {
	t.Run("removes all ReplicaSets", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(rsGVR, makeObj("apps/v1", "ReplicaSet", "nginx-abc123", "default", []metav1.OwnerReference{ownerRef("Deployment", "nginx")}))
		cache.Add(rsGVR, makeObj("apps/v1", "ReplicaSet", "redis-def456", "default", []metav1.OwnerReference{ownerRef("Deployment", "redis")}))
		cache.Add(deployGVR, makeObj("apps/v1", "Deployment", "nginx", "default", nil))

		count := FilterManagedResources(cache)
		assert.Equal(t, 2, count)
		assert.Nil(t, cache.List(rsGVR))
		assert.Len(t, cache.List(deployGVR), 1)
	})

	t.Run("removes Pods owned by ReplicaSet", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(podGVR, makeObj("v1", "Pod", "nginx-abc123-xyz", "default", []metav1.OwnerReference{ownerRef("ReplicaSet", "nginx-abc123")}))
		cache.Add(podGVR, makeObj("v1", "Pod", "standalone", "default", nil))

		count := FilterManagedResources(cache)
		assert.Equal(t, 1, count)
		pods := cache.List(podGVR)
		require.Len(t, pods, 1)
		assert.Equal(t, "standalone", pods[0].GetName())
	})

	t.Run("removes Pods owned by DaemonSet", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(podGVR, makeObj("v1", "Pod", "calico-node-abc", "kube-system", []metav1.OwnerReference{ownerRef("DaemonSet", "calico-node")}))

		count := FilterManagedResources(cache)
		assert.Equal(t, 1, count)
		assert.Empty(t, cache.List(podGVR))
	})

	t.Run("removes Pods owned by StatefulSet", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(podGVR, makeObj("v1", "Pod", "redis-0", "default", []metav1.OwnerReference{ownerRef("StatefulSet", "redis")}))

		count := FilterManagedResources(cache)
		assert.Equal(t, 1, count)
		assert.Empty(t, cache.List(podGVR))
	})

	t.Run("removes Pods owned by Job", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(podGVR, makeObj("v1", "Pod", "backup-xyz", "default", []metav1.OwnerReference{ownerRef("Job", "backup")}))

		count := FilterManagedResources(cache)
		assert.Equal(t, 1, count)
		assert.Empty(t, cache.List(podGVR))
	})

	t.Run("keeps standalone Pods", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(podGVR, makeObj("v1", "Pod", "debug", "default", nil))
		cache.Add(podGVR, makeObj("v1", "Pod", "standalone", "production", nil))

		count := FilterManagedResources(cache)
		assert.Equal(t, 0, count)
		assert.Len(t, cache.List(podGVR), 2)
	})

	t.Run("mixed: keeps standalone, removes managed", func(t *testing.T) {
		cache := checker.NewResourceCache()
		// Standalone pod — keep
		cache.Add(podGVR, makeObj("v1", "Pod", "debug", "default", nil))
		// Managed pod — remove
		cache.Add(podGVR, makeObj("v1", "Pod", "nginx-abc-xyz", "default", []metav1.OwnerReference{ownerRef("ReplicaSet", "nginx-abc")}))
		// ReplicaSets — remove all
		cache.Add(rsGVR, makeObj("apps/v1", "ReplicaSet", "nginx-abc", "default", []metav1.OwnerReference{ownerRef("Deployment", "nginx")}))
		// Deployment — keep
		cache.Add(deployGVR, makeObj("apps/v1", "Deployment", "nginx", "default", nil))

		count := FilterManagedResources(cache)
		assert.Equal(t, 2, count)

		pods := cache.List(podGVR)
		require.Len(t, pods, 1)
		assert.Equal(t, "debug", pods[0].GetName())

		assert.Nil(t, cache.List(rsGVR))
		assert.Len(t, cache.List(deployGVR), 1)
	})

	t.Run("empty cache returns zero", func(t *testing.T) {
		cache := checker.NewResourceCache()
		count := FilterManagedResources(cache)
		assert.Equal(t, 0, count)
	})

	t.Run("no pods or replicasets returns zero", func(t *testing.T) {
		cache := checker.NewResourceCache()
		cache.Add(deployGVR, makeObj("apps/v1", "Deployment", "nginx", "default", nil))

		count := FilterManagedResources(cache)
		assert.Equal(t, 0, count)
		assert.Len(t, cache.List(deployGVR), 1)
	})
}
