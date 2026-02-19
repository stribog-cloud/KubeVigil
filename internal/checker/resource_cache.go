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
	policies  *Policies
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
