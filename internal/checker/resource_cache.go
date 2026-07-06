package checker

import (
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// cachedEntry holds a lazily-computed result protected by sync.Once.
// Used by ResourceCache.CachedResult for deduplicating expensive computations
// (e.g., PodSpec extraction) across concurrent checkers.
type cachedEntry struct {
	once   sync.Once
	result any
}

// ResourceCache provides a shared, read-only, thread-safe cache of Kubernetes resources.
// It is populated once per scan before any checkers run, then read concurrently by all checkers.
// After population, call Freeze() to pre-compute flat lists for zero-allocation List() calls.
type ResourceCache struct {
	mu            sync.RWMutex
	resources     map[schema.GroupVersionResource]map[string][]unstructured.Unstructured
	policies      *Policies
	cachedResults sync.Map // map[string]*cachedEntry — lazy computed results
	frozen        bool
	flatLists     map[schema.GroupVersionResource][]unstructured.Unstructured
}

// NewResourceCache creates an empty ResourceCache.
func NewResourceCache() *ResourceCache {
	return &ResourceCache{
		resources: make(map[schema.GroupVersionResource]map[string][]unstructured.Unstructured),
	}
}

// Add inserts a resource into the cache. This should only be called during cache population,
// before checkers begin running. Panics if called after Freeze().
func (c *ResourceCache) Add(gvr schema.GroupVersionResource, obj unstructured.Unstructured) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.frozen {
		panic("ResourceCache.Add called after Freeze")
	}

	ns := obj.GetNamespace()
	if c.resources[gvr] == nil {
		c.resources[gvr] = make(map[string][]unstructured.Unstructured)
	}
	c.resources[gvr][ns] = append(c.resources[gvr][ns], obj)
}

// List returns all resources of the given type across all namespaces.
// After Freeze() has been called, this returns the pre-computed slice directly (zero allocation).
func (c *ResourceCache) List(gvr schema.GroupVersionResource) []unstructured.Unstructured {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.frozen {
		return c.flatLists[gvr]
	}

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

// Remove removes a specific resource from the cache by GVR, namespace, and name.
// Returns true if the resource was found and removed.
func (c *ResourceCache) Remove(gvr schema.GroupVersionResource, namespace, name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	nsByGVR := c.resources[gvr]
	if nsByGVR == nil {
		return false
	}
	objs := nsByGVR[namespace]
	for i, obj := range objs {
		if obj.GetName() == name {
			nsByGVR[namespace] = append(objs[:i], objs[i+1:]...)
			if len(nsByGVR[namespace]) == 0 {
				delete(nsByGVR, namespace)
			}
			return true
		}
	}
	return false
}

// RemoveAll removes all resources of a given GVR from the cache.
// Returns the number of resources removed.
func (c *ResourceCache) RemoveAll(gvr schema.GroupVersionResource) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	nsByGVR := c.resources[gvr]
	if nsByGVR == nil {
		return 0
	}
	count := 0
	for _, objs := range nsByGVR {
		count += len(objs)
	}
	delete(c.resources, gvr)
	return count
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

// SetPolicies sets the scan policies on the cache.
func (c *ResourceCache) SetPolicies(p *Policies) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policies = p
}

// Policies returns the scan policies, or nil if none configured.
func (c *ResourceCache) Policies() *Policies {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policies
}

// CachedResult returns a lazily-computed result for the given key. The compute function
// is called at most once per key, even under concurrent access from multiple checkers.
// This is used to deduplicate expensive operations like PodSpec extraction, which would
// otherwise be repeated by every workload checker.
func (c *ResourceCache) CachedResult(key string, compute func() any) any {
	entry, _ := c.cachedResults.LoadOrStore(key, &cachedEntry{})
	ce := entry.(*cachedEntry)
	ce.once.Do(func() {
		ce.result = compute()
	})
	return ce.result
}

// ClearCachedResults removes all cached computation results.
// This is intended for testing; in production, a new ResourceCache is created per scan.
func (c *ResourceCache) ClearCachedResults() {
	c.cachedResults = sync.Map{}
}

// Freeze pre-computes flat lists for all GVRs, enabling zero-allocation List() calls.
// After Freeze(), the cache is immutable: Add() will panic. Calling Freeze() multiple
// times is safe (idempotent). This should be called after all resources have been added
// and before checkers begin running.
func (c *ResourceCache) Freeze() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.flatLists = make(map[schema.GroupVersionResource][]unstructured.Unstructured, len(c.resources))
	for gvr, nsByGVR := range c.resources {
		var flat []unstructured.Unstructured
		for _, objs := range nsByGVR {
			flat = append(flat, objs...)
		}
		c.flatLists[gvr] = flat
	}
	c.frozen = true
}

// knownGVRs maps common apiVersion+kind pairs to their GVR for manifest parsing.
var knownGVRs = map[string]schema.GroupVersionResource{
	// Workloads (Phase 1)
	"v1/Pod":              {Group: "", Version: "v1", Resource: "pods"},
	"apps/v1/Deployment":  {Group: "apps", Version: "v1", Resource: "deployments"},
	"apps/v1/StatefulSet": {Group: "apps", Version: "v1", Resource: "statefulsets"},
	"apps/v1/DaemonSet":   {Group: "apps", Version: "v1", Resource: "daemonsets"},
	"apps/v1/ReplicaSet":  {Group: "apps", Version: "v1", Resource: "replicasets"},
	"batch/v1/Job":        {Group: "batch", Version: "v1", Resource: "jobs"},
	"batch/v1/CronJob":    {Group: "batch", Version: "v1", Resource: "cronjobs"},

	// Core v1 (Phase 2)
	"v1/ServiceAccount":        {Group: "", Version: "v1", Resource: "serviceaccounts"},
	"v1/Service":               {Group: "", Version: "v1", Resource: "services"},
	"v1/Secret":                {Group: "", Version: "v1", Resource: "secrets"},
	"v1/ConfigMap":             {Group: "", Version: "v1", Resource: "configmaps"},
	"v1/LimitRange":            {Group: "", Version: "v1", Resource: "limitranges"},
	"v1/ResourceQuota":         {Group: "", Version: "v1", Resource: "resourcequotas"},
	"v1/PersistentVolumeClaim": {Group: "", Version: "v1", Resource: "persistentvolumeclaims"},
	"v1/PersistentVolume":      {Group: "", Version: "v1", Resource: "persistentvolumes"},
	"v1/Namespace":             {Group: "", Version: "v1", Resource: "namespaces"},
	"v1/Node":                  {Group: "", Version: "v1", Resource: "nodes"},

	// RBAC (Phase 2)
	"rbac.authorization.k8s.io/v1/Role":               {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"},
	"rbac.authorization.k8s.io/v1/ClusterRole":        {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"},
	"rbac.authorization.k8s.io/v1/RoleBinding":        {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"},
	"rbac.authorization.k8s.io/v1/ClusterRoleBinding": {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"},

	// Networking (Phase 2)
	"networking.k8s.io/v1/NetworkPolicy": {Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	"networking.k8s.io/v1/Ingress":       {Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"},

	// Storage (Phase 2)
	"storage.k8s.io/v1/StorageClass": {Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses"},
	"storage.k8s.io/v1/CSIDriver":    {Group: "storage.k8s.io", Version: "v1", Resource: "csidrivers"},

	// Policy (Phase 2)
	"policy/v1/PodDisruptionBudget": {Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"},

	// Autoscaling (Phase 2)
	"autoscaling/v2/HorizontalPodAutoscaler": {Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"},

	// Scheduling (Phase 2)
	"scheduling.k8s.io/v1/PriorityClass": {Group: "scheduling.k8s.io", Version: "v1", Resource: "priorityclasses"},

	// API Extensions (Phase 2)
	"apiextensions.k8s.io/v1/CustomResourceDefinition": {Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"},

	// cert-manager (Phase 2)
	"cert-manager.io/v1/Certificate": {Group: "cert-manager.io", Version: "v1", Resource: "certificates"},

	// Deprecated (Phase 2 — detect lingering resources)
	"policy/v1beta1/PodSecurityPolicy": {Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"},

	// Storage snapshots (v1.3.0 Batch 5 — required for volumesnapshotclass-no-encryption;
	// the generic apiVersion+kind fallback below cannot pluralize "Class" correctly).
	"snapshot.storage.k8s.io/v1/VolumeSnapshotClass": {Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"},
}

// AllKnownGVRs returns every GroupVersionResource KubeVigil recognizes,
// deduplicated. It is the broad default resource set for custom policies that
// do not restrict themselves to specific kinds.
func AllKnownGVRs() []schema.GroupVersionResource {
	seen := make(map[schema.GroupVersionResource]struct{}, len(knownGVRs))
	out := make([]schema.GroupVersionResource, 0, len(knownGVRs))
	for _, gvr := range knownGVRs {
		if _, ok := seen[gvr]; ok {
			continue
		}
		seen[gvr] = struct{}{}
		out = append(out, gvr)
	}
	return out
}

// GVRsForKind returns the known GVRs whose kind matches the given kind name
// (e.g. "Deployment"), across all API groups KubeVigil knows. Returns an empty
// slice if the kind is unrecognized. Used by the custom-policy engine to
// resolve a policy's `match.kinds` into the resources it must scan.
func GVRsForKind(kind string) []schema.GroupVersionResource {
	suffix := "/" + kind
	var out []schema.GroupVersionResource
	seen := make(map[schema.GroupVersionResource]struct{})
	for key, gvr := range knownGVRs {
		if strings.HasSuffix(key, suffix) {
			if _, ok := seen[gvr]; ok {
				continue
			}
			seen[gvr] = struct{}{}
			out = append(out, gvr)
		}
	}
	return out
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
