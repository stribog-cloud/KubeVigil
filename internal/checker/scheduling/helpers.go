// Package scheduling implements scheduling and availability security checkers.
// These checkers analyze tolerations, PriorityClasses, PodDisruptionBudgets,
// topology spread constraints, node affinity, and HPA configuration.
package scheduling

import (
	"encoding/json"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// GVR constants for scheduling-related resources.
var (
	// PodDisruptionBudgetGVR is the GroupVersionResource for policy/v1 PodDisruptionBudget objects.
	PodDisruptionBudgetGVR = schema.GroupVersionResource{
		Group: "policy", Version: "v1", Resource: "poddisruptionbudgets",
	}
	// HorizontalPodAutoscalerGVR is the GroupVersionResource for autoscaling/v2 HPA objects.
	HorizontalPodAutoscalerGVR = schema.GroupVersionResource{
		Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers",
	}
	// PriorityClassGVR is the GroupVersionResource for scheduling.k8s.io/v1 PriorityClass objects.
	PriorityClassGVR = schema.GroupVersionResource{
		Group: "scheduling.k8s.io", Version: "v1", Resource: "priorityclasses",
	}
)

// systemPriorityClasses are priority class names reserved for system components.
var systemPriorityClasses = map[string]bool{
	"system-cluster-critical": true,
	"system-node-critical":    true,
}

// controlPlaneTaintKeys are taint keys that indicate control-plane/master nodes.
var controlPlaneTaintKeys = map[string]bool{
	"node-role.kubernetes.io/control-plane": true,
	"node-role.kubernetes.io/master":        true,
}

// getReplicas extracts the spec.replicas field from an unstructured workload resource.
// Returns 1 as the default if the field is not set (Kubernetes default).
// Tries int64 first (live cluster data) then float64 (JSON-decoded manifests).
func getReplicas(obj *unstructured.Unstructured) int64 {
	if v, ok, err := unstructured.NestedInt64(obj.Object, "spec", "replicas"); err == nil && ok {
		return v
	}
	if v, ok, err := unstructured.NestedFloat64(obj.Object, "spec", "replicas"); err == nil && ok {
		return int64(v)
	}
	return 1
}

// extractHPATargetRef extracts the scaleTargetRef from an HPA.
func extractHPATargetRef(obj *unstructured.Unstructured) (kind, name, apiVersion string) {
	ref, found, err := unstructured.NestedMap(obj.Object, "spec", "scaleTargetRef")
	if err != nil || !found {
		return "", "", ""
	}
	kind, _, _ = unstructured.NestedString(ref, "kind")
	name, _, _ = unstructured.NestedString(ref, "name")
	apiVersion, _, _ = unstructured.NestedString(ref, "apiVersion")
	return kind, name, apiVersion
}

// extractPodSpec extracts a corev1.PodSpec from an unstructured workload resource.
func extractPodSpec(obj *unstructured.Unstructured) (*corev1.PodSpec, bool) {
	kind := obj.GetKind()
	var specMap map[string]interface{}
	var found bool

	switch kind {
	case "Pod":
		specMap, found, _ = unstructured.NestedMap(obj.Object, "spec")
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
		specMap, found, _ = unstructured.NestedMap(obj.Object, "spec", "template", "spec")
	case "Job":
		specMap, found, _ = unstructured.NestedMap(obj.Object, "spec", "template", "spec")
	case "CronJob":
		specMap, found, _ = unstructured.NestedMap(obj.Object, "spec", "jobTemplate", "spec", "template", "spec")
	default:
		return nil, false
	}

	if !found || specMap == nil {
		return nil, false
	}

	data, err := json.Marshal(specMap)
	if err != nil {
		slog.Debug("marshaling PodSpec", "kind", kind, "name", obj.GetName(), "error", err)
		return nil, false
	}

	var podSpec corev1.PodSpec
	if err := json.Unmarshal(data, &podSpec); err != nil {
		slog.Debug("unmarshaling PodSpec", "kind", kind, "name", obj.GetName(), "error", err)
		return nil, false
	}

	return &podSpec, true
}

// workloadHasRequests checks if the target workload has resource requests set on all containers.
func workloadHasRequests(cache *checker.ResourceCache, targetKind, targetName, namespace string) bool {
	gvr := gvrForKind(targetKind)
	if gvr.Resource == "" {
		return false
	}

	resources := cache.ListNamespaced(gvr, namespace)
	for i := range resources {
		obj := &resources[i]
		if obj.GetName() != targetName {
			continue
		}

		spec, ok := extractPodSpec(obj)
		if !ok {
			return false
		}

		for j := range spec.Containers {
			c := &spec.Containers[j]
			if c.Resources.Requests == nil {
				return false
			}
			if _, hasCPU := c.Resources.Requests[corev1.ResourceCPU]; !hasCPU {
				if _, hasMem := c.Resources.Requests[corev1.ResourceMemory]; !hasMem {
					return false
				}
			}
		}
		return true
	}
	return false
}

// gvrForKind maps a Kind string to its GVR.
func gvrForKind(kind string) schema.GroupVersionResource {
	switch kind {
	case "Deployment":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	case "StatefulSet":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
	case "DaemonSet":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
	case "ReplicaSet":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	default:
		return schema.GroupVersionResource{}
	}
}
