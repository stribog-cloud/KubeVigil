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
		// Core v1 types (Phase 2)
		{
			name:       "v1 ServiceAccount",
			apiVersion: "v1",
			kind:       "ServiceAccount",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"},
		},
		{
			name:       "v1 Service",
			apiVersion: "v1",
			kind:       "Service",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"},
		},
		{
			name:       "v1 Secret",
			apiVersion: "v1",
			kind:       "Secret",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"},
		},
		{
			name:       "v1 ConfigMap",
			apiVersion: "v1",
			kind:       "ConfigMap",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"},
		},
		{
			name:       "v1 LimitRange",
			apiVersion: "v1",
			kind:       "LimitRange",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "limitranges"},
		},
		{
			name:       "v1 ResourceQuota",
			apiVersion: "v1",
			kind:       "ResourceQuota",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"},
		},
		{
			name:       "v1 PersistentVolumeClaim",
			apiVersion: "v1",
			kind:       "PersistentVolumeClaim",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumeclaims"},
		},
		{
			name:       "v1 PersistentVolume",
			apiVersion: "v1",
			kind:       "PersistentVolume",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumes"},
		},
		{
			name:       "v1 Namespace",
			apiVersion: "v1",
			kind:       "Namespace",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"},
		},
		{
			name:       "v1 Node",
			apiVersion: "v1",
			kind:       "Node",
			wantGVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"},
		},
		// RBAC types (Phase 2)
		{
			name:       "rbac Role",
			apiVersion: "rbac.authorization.k8s.io/v1",
			kind:       "Role",
			wantGVR:    schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"},
		},
		{
			name:       "rbac ClusterRole",
			apiVersion: "rbac.authorization.k8s.io/v1",
			kind:       "ClusterRole",
			wantGVR:    schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"},
		},
		{
			name:       "rbac RoleBinding",
			apiVersion: "rbac.authorization.k8s.io/v1",
			kind:       "RoleBinding",
			wantGVR:    schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"},
		},
		{
			name:       "rbac ClusterRoleBinding",
			apiVersion: "rbac.authorization.k8s.io/v1",
			kind:       "ClusterRoleBinding",
			wantGVR:    schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"},
		},
		// Networking types (Phase 2) — irregular plurals
		{
			name:       "networking NetworkPolicy irregular plural",
			apiVersion: "networking.k8s.io/v1",
			kind:       "NetworkPolicy",
			wantGVR:    schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
		},
		{
			name:       "networking Ingress irregular plural",
			apiVersion: "networking.k8s.io/v1",
			kind:       "Ingress",
			wantGVR:    schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"},
		},
		// Storage types (Phase 2) — irregular plural for StorageClass
		{
			name:       "storage StorageClass irregular plural",
			apiVersion: "storage.k8s.io/v1",
			kind:       "StorageClass",
			wantGVR:    schema.GroupVersionResource{Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses"},
		},
		{
			name:       "storage CSIDriver",
			apiVersion: "storage.k8s.io/v1",
			kind:       "CSIDriver",
			wantGVR:    schema.GroupVersionResource{Group: "storage.k8s.io", Version: "v1", Resource: "csidrivers"},
		},
		// Policy (Phase 2)
		{
			name:       "policy PodDisruptionBudget",
			apiVersion: "policy/v1",
			kind:       "PodDisruptionBudget",
			wantGVR:    schema.GroupVersionResource{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"},
		},
		// Autoscaling (Phase 2)
		{
			name:       "autoscaling HorizontalPodAutoscaler",
			apiVersion: "autoscaling/v2",
			kind:       "HorizontalPodAutoscaler",
			wantGVR:    schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"},
		},
		// Scheduling (Phase 2) — irregular plural for PriorityClass
		{
			name:       "scheduling PriorityClass irregular plural",
			apiVersion: "scheduling.k8s.io/v1",
			kind:       "PriorityClass",
			wantGVR:    schema.GroupVersionResource{Group: "scheduling.k8s.io", Version: "v1", Resource: "priorityclasses"},
		},
		// API Extensions (Phase 2)
		{
			name:       "apiextensions CustomResourceDefinition",
			apiVersion: "apiextensions.k8s.io/v1",
			kind:       "CustomResourceDefinition",
			wantGVR:    schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"},
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

func TestResourceCache_Policies(t *testing.T) {
	t.Run("nil by default", func(t *testing.T) {
		cache := NewResourceCache()
		assert.Nil(t, cache.Policies())
	})

	t.Run("set and get policies", func(t *testing.T) {
		cache := NewResourceCache()
		p := &Policies{
			Images: ImagePolicies{
				AllowedRegistries: []string{"gcr.io"},
			},
		}
		cache.SetPolicies(p)
		assert.Equal(t, p, cache.Policies())
		assert.True(t, cache.Policies().HasAllowedRegistries())
		assert.False(t, cache.Policies().HasBlockedRegistries())
	})

	t.Run("overwrite policies", func(t *testing.T) {
		cache := NewResourceCache()
		p1 := &Policies{
			Images: ImagePolicies{
				AllowedRegistries: []string{"gcr.io"},
			},
		}
		cache.SetPolicies(p1)

		p2 := &Policies{
			Images: ImagePolicies{
				BlockedRegistries: []string{"docker.io"},
			},
		}
		cache.SetPolicies(p2)
		assert.Equal(t, p2, cache.Policies())
		assert.False(t, cache.Policies().HasAllowedRegistries())
		assert.True(t, cache.Policies().HasBlockedRegistries())
	})
}

func TestResourceCache_Remove(t *testing.T) {
	t.Run("remove existing resource", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "default"))

		removed := cache.Remove(podGVR, "default", "pod-a")
		assert.True(t, removed)
		result := cache.List(podGVR)
		require.Len(t, result, 1)
		assert.Equal(t, "pod-b", result[0].GetName())
		assert.Equal(t, 1, cache.Len())
	})

	t.Run("remove nonexistent resource", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))

		removed := cache.Remove(podGVR, "default", "nonexistent")
		assert.False(t, removed)
		assert.Equal(t, 1, cache.Len())
	})

	t.Run("remove from nonexistent namespace", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))

		removed := cache.Remove(podGVR, "other", "pod-a")
		assert.False(t, removed)
		assert.Equal(t, 1, cache.Len())
	})

	t.Run("remove from nonexistent GVR", func(t *testing.T) {
		cache := NewResourceCache()
		removed := cache.Remove(podGVR, "default", "pod-a")
		assert.False(t, removed)
	})

	t.Run("remove last resource in namespace cleans up empty slice", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "kube-system"))

		removed := cache.Remove(podGVR, "default", "pod-a")
		assert.True(t, removed)
		assert.Nil(t, cache.ListNamespaced(podGVR, "default"))
		assert.Len(t, cache.ListNamespaced(podGVR, "kube-system"), 1)
	})
}

func TestResourceCache_RemoveAll(t *testing.T) {
	t.Run("remove all resources of a GVR", func(t *testing.T) {
		cache := NewResourceCache()
		rsGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
		cache.Add(rsGVR, makeUnstructured("apps/v1", "ReplicaSet", "rs-a", "default"))
		cache.Add(rsGVR, makeUnstructured("apps/v1", "ReplicaSet", "rs-b", "kube-system"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))

		count := cache.RemoveAll(rsGVR)
		assert.Equal(t, 2, count)
		assert.Nil(t, cache.List(rsGVR))
		assert.Len(t, cache.List(podGVR), 1)
		assert.Equal(t, 1, cache.Len())
	})

	t.Run("remove all from nonexistent GVR", func(t *testing.T) {
		cache := NewResourceCache()
		count := cache.RemoveAll(podGVR)
		assert.Equal(t, 0, count)
	})
}

func TestPolicies_Helpers(t *testing.T) {
	t.Run("nil policies", func(t *testing.T) {
		var p *Policies
		assert.False(t, p.HasAllowedRegistries())
		assert.False(t, p.HasBlockedRegistries())
	})

	t.Run("empty policies", func(t *testing.T) {
		p := &Policies{}
		assert.False(t, p.HasAllowedRegistries())
		assert.False(t, p.HasBlockedRegistries())
	})

	t.Run("with allowed registries", func(t *testing.T) {
		p := &Policies{
			Images: ImagePolicies{
				AllowedRegistries: []string{"gcr.io", "us-docker.pkg.dev"},
			},
		}
		assert.True(t, p.HasAllowedRegistries())
		assert.False(t, p.HasBlockedRegistries())
	})

	t.Run("with blocked registries", func(t *testing.T) {
		p := &Policies{
			Images: ImagePolicies{
				BlockedRegistries: []string{"docker.io"},
			},
		}
		assert.False(t, p.HasAllowedRegistries())
		assert.True(t, p.HasBlockedRegistries())
	})

	t.Run("with both registries", func(t *testing.T) {
		p := &Policies{
			Images: ImagePolicies{
				AllowedRegistries: []string{"gcr.io"},
				BlockedRegistries: []string{"docker.io"},
			},
		}
		assert.True(t, p.HasAllowedRegistries())
		assert.True(t, p.HasBlockedRegistries())
	})
}

func TestResourceCache_CachedResult(t *testing.T) {
	t.Run("computes once and reuses", func(t *testing.T) {
		cache := NewResourceCache()
		callCount := 0
		compute := func() any {
			callCount++
			return []string{"a", "b", "c"}
		}

		result1 := cache.CachedResult("test-key", compute)
		result2 := cache.CachedResult("test-key", compute)

		assert.Equal(t, 1, callCount, "compute should be called exactly once")
		assert.Equal(t, result1, result2, "both calls should return same result")
		assert.Equal(t, []string{"a", "b", "c"}, result1.([]string))
	})

	t.Run("different keys compute independently", func(t *testing.T) {
		cache := NewResourceCache()

		r1 := cache.CachedResult("key-a", func() any { return "alpha" })
		r2 := cache.CachedResult("key-b", func() any { return "beta" })

		assert.Equal(t, "alpha", r1.(string))
		assert.Equal(t, "beta", r2.(string))
	})

	t.Run("nil result is cached", func(t *testing.T) {
		cache := NewResourceCache()
		callCount := 0
		compute := func() any {
			callCount++
			return nil
		}

		r1 := cache.CachedResult("nil-key", compute)
		r2 := cache.CachedResult("nil-key", compute)

		assert.Nil(t, r1)
		assert.Nil(t, r2)
		assert.Equal(t, 1, callCount)
	})

	t.Run("ClearCachedResults allows recomputation", func(t *testing.T) {
		cache := NewResourceCache()
		callCount := 0
		compute := func() any {
			callCount++
			return callCount
		}

		r1 := cache.CachedResult("counter", compute)
		assert.Equal(t, 1, r1.(int))

		cache.ClearCachedResults()

		r2 := cache.CachedResult("counter", compute)
		assert.Equal(t, 2, r2.(int))
		assert.Equal(t, 2, callCount)
	})
}

func TestResourceCache_Freeze(t *testing.T) {
	t.Run("frozen List returns precomputed slice with zero allocation", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-c", "kube-system"))

		cache.Freeze()

		result := cache.List(podGVR)
		require.Len(t, result, 3)

		// After freeze, List should return the exact same slice (pointer equality).
		result2 := cache.List(podGVR)
		assert.Equal(t, result, result2)
	})

	t.Run("frozen List returns nil for unknown GVR", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Freeze()

		result := cache.List(deployGVR)
		assert.Nil(t, result)
	})

	t.Run("unfrozen List still works normally", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "kube-system"))

		result := cache.List(podGVR)
		assert.Len(t, result, 2)
	})

	t.Run("Freeze is idempotent", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))

		cache.Freeze()
		cache.Freeze() // second freeze should not panic or change behavior

		result := cache.List(podGVR)
		require.Len(t, result, 1)
		assert.Equal(t, "pod-a", result[0].GetName())
	})

	t.Run("Add panics after Freeze", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Freeze()

		assert.Panics(t, func() {
			cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "default"))
		})
	})

	t.Run("frozen cache preserves all GVRs", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(deployGVR, makeUnstructured("apps/v1", "Deployment", "deploy-a", "default"))
		cache.Freeze()

		pods := cache.List(podGVR)
		assert.Len(t, pods, 1)
		deploys := cache.List(deployGVR)
		assert.Len(t, deploys, 1)
	})

	t.Run("frozen empty cache", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Freeze()

		result := cache.List(podGVR)
		assert.Nil(t, result)
	})

	t.Run("ListNamespaced still works after Freeze", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "kube-system"))
		cache.Freeze()

		result := cache.ListNamespaced(podGVR, "default")
		assert.Len(t, result, 1)
		assert.Equal(t, "pod-a", result[0].GetName())
	})

	t.Run("GVRs still works after Freeze", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(deployGVR, makeUnstructured("apps/v1", "Deployment", "deploy-a", "default"))
		cache.Freeze()

		gvrs := cache.GVRs()
		assert.Len(t, gvrs, 2)
		assert.Contains(t, gvrs, podGVR)
		assert.Contains(t, gvrs, deployGVR)
	})

	t.Run("Len still works after Freeze", func(t *testing.T) {
		cache := NewResourceCache()
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-a", "default"))
		cache.Add(podGVR, makeUnstructured("v1", "Pod", "pod-b", "kube-system"))
		cache.Freeze()

		assert.Equal(t, 2, cache.Len())
	})
}

func BenchmarkCacheListFrozen(b *testing.B) {
	cache := benchCache(b)
	cache.Freeze()
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		items := cache.List(gvr)
		_ = items
	}
}
