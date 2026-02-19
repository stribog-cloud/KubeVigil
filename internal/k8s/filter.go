package k8s

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// controllerKinds are owner kinds whose Pods should be filtered out.
// Pods owned by these controllers are duplicates of the controller's pod template.
var controllerKinds = map[string]bool{
	"ReplicaSet":  true,
	"DaemonSet":   true,
	"StatefulSet": true,
	"Job":         true,
}

var replicaSetGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}

// FilterManagedResources removes managed Pods and ReplicaSets from the cache.
// ReplicaSets are removed entirely — they always duplicate their parent Deployment.
// Pods with a controller ownerReference pointing to a ReplicaSet, DaemonSet,
// StatefulSet, or Job are removed. Standalone Pods (no controller owner) are kept.
// Returns the number of resources removed.
func FilterManagedResources(cache *checker.ResourceCache) int {
	removed := 0

	// Remove all ReplicaSets.
	rsCount := cache.RemoveAll(replicaSetGVR)
	removed += rsCount
	if rsCount > 0 {
		slog.Debug("filtered managed resources", "kind", "ReplicaSet", "count", rsCount)
	}

	// Remove Pods owned by controllers.
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	pods := cache.List(podGVR)
	for _, pod := range pods {
		owners := pod.GetOwnerReferences()
		for _, owner := range owners {
			if owner.Controller != nil && *owner.Controller && controllerKinds[owner.Kind] {
				if cache.Remove(podGVR, pod.GetNamespace(), pod.GetName()) {
					removed++
				}
				break
			}
		}
	}
	if removed-rsCount > 0 {
		slog.Debug("filtered managed resources", "kind", "Pod", "count", removed-rsCount)
	}

	return removed
}
