package checker

import (
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ResourceCache provides a shared, read-only, thread-safe cache of Kubernetes resources.
// It is populated once per scan before any checkers run, then read concurrently by all checkers.
type ResourceCache struct {
	mu        sync.RWMutex
	resources map[schema.GroupVersionResource]map[string][]unstructured.Unstructured
}

// NewResourceCache creates an empty ResourceCache.
func NewResourceCache() *ResourceCache {
	return &ResourceCache{
		resources: make(map[schema.GroupVersionResource]map[string][]unstructured.Unstructured),
	}
}

// Add inserts a resource into the cache. This should only be called during cache population,
// before checkers begin running.
func (c *ResourceCache) Add(gvr schema.GroupVersionResource, obj unstructured.Unstructured) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ns := obj.GetNamespace()
	if c.resources[gvr] == nil {
		c.resources[gvr] = make(map[string][]unstructured.Unstructured)
	}
	c.resources[gvr][ns] = append(c.resources[gvr][ns], obj)
}

// List returns all resources of the given type across all namespaces.
func (c *ResourceCache) List(gvr schema.GroupVersionResource) []unstructured.Unstructured {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nsByGVR := c.resources[gvr]
	if nsByGVR == nil {
		return nil
	}

	var result []unstructured.Unstructured
	for _, objs := range nsByGVR {
		result = append(result, objs...)
	}
	return result
}

// ListNamespaced returns all resources of the given type in a specific namespace.
func (c *ResourceCache) ListNamespaced(gvr schema.GroupVersionResource, namespace string) []unstructured.Unstructured {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nsByGVR := c.resources[gvr]
	if nsByGVR == nil {
		return nil
	}
	return nsByGVR[namespace]
}

// GVRs returns all GroupVersionResources that have been added to the cache.
func (c *ResourceCache) GVRs() []schema.GroupVersionResource {
	c.mu.RLock()
	defer c.mu.RUnlock()

	gvrs := make([]schema.GroupVersionResource, 0, len(c.resources))
	for gvr := range c.resources {
		gvrs = append(gvrs, gvr)
	}
	return gvrs
}

// Len returns the total number of resources across all types and namespaces.
func (c *ResourceCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, nsByGVR := range c.resources {
		for _, objs := range nsByGVR {
			count += len(objs)
		}
	}
	return count
}

// knownGVRs maps common apiVersion+kind pairs to their GVR for manifest parsing.
var knownGVRs = map[string]schema.GroupVersionResource{
	"v1/Pod":              {Group: "", Version: "v1", Resource: "pods"},
	"apps/v1/Deployment":  {Group: "apps", Version: "v1", Resource: "deployments"},
	"apps/v1/StatefulSet": {Group: "apps", Version: "v1", Resource: "statefulsets"},
	"apps/v1/DaemonSet":   {Group: "apps", Version: "v1", Resource: "daemonsets"},
	"apps/v1/ReplicaSet":  {Group: "apps", Version: "v1", Resource: "replicasets"},
	"batch/v1/Job":        {Group: "batch", Version: "v1", Resource: "jobs"},
	"batch/v1/CronJob":    {Group: "batch", Version: "v1", Resource: "cronjobs"},
}

// GVRForKind maps an apiVersion and kind from a manifest to its GroupVersionResource.
// Returns an error if the combination is not recognized.
func GVRForKind(apiVersion, kind string) (schema.GroupVersionResource, error) {
	key := apiVersion + "/" + kind
	if gvr, ok := knownGVRs[key]; ok {
		return gvr, nil
	}

	// Attempt to derive GVR from apiVersion and kind for unknown types.
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, fmt.Errorf("parsing apiVersion %q: %w", apiVersion, err)
	}
	resource := strings.ToLower(kind) + "s"
	return schema.GroupVersionResource{
		Group:    gv.Group,
		Version:  gv.Version,
		Resource: resource,
	}, nil
}
