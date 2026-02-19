package checker

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// benchCache creates a ResourceCache with realistic data for benchmarking.
// It populates 48 resources across 4 GVRs and 4 namespaces (3 per combination).
func benchCache(b *testing.B) *ResourceCache {
	b.Helper()
	cache := NewResourceCache()
	gvrs := []schema.GroupVersionResource{
		{Group: "apps", Version: "v1", Resource: "deployments"},
		{Group: "apps", Version: "v1", Resource: "statefulsets"},
		{Group: "", Version: "v1", Resource: "pods"},
		{Group: "", Version: "v1", Resource: "services"},
	}
	namespaces := []string{"default", "production", "staging", "monitoring"}

	idx := 0
	for _, gvr := range gvrs {
		for _, ns := range namespaces {
			for j := 0; j < 3; j++ {
				obj := unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": gvr.Group + "/" + gvr.Version,
						"kind":       strings.TrimSuffix(gvr.Resource, "s"),
						"metadata": map[string]interface{}{
							"name":      fmt.Sprintf("resource-%d", idx),
							"namespace": ns,
						},
					},
				}
				if gvr.Group == "" {
					obj.Object["apiVersion"] = gvr.Version
				}
				cache.Add(gvr, obj)
				idx++
			}
		}
	}
	return cache
}

func BenchmarkCacheAdd(b *testing.B) {
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache := NewResourceCache()
		for j := 0; j < 50; j++ {
			obj := unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "apps/v1",
					"kind":       "Deployment",
					"metadata": map[string]interface{}{
						"name":      fmt.Sprintf("deploy-%d", j),
						"namespace": "default",
					},
				},
			}
			cache.Add(gvr, obj)
		}
	}
}

func BenchmarkCacheList(b *testing.B) {
	cache := benchCache(b)
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		items := cache.List(gvr)
		_ = items
	}
}

func BenchmarkCacheListNamespaced(b *testing.B) {
	cache := benchCache(b)
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		items := cache.ListNamespaced(gvr, "production")
		_ = items
	}
}

func BenchmarkCacheLen(b *testing.B) {
	cache := benchCache(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := cache.Len()
		_ = n
	}
}

func BenchmarkCacheGVRs(b *testing.B) {
	cache := benchCache(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gvrs := cache.GVRs()
		_ = gvrs
	}
}
