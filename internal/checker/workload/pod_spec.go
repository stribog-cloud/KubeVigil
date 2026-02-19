// Package workload implements Phase 1 workload security checkers.
package workload

import (
	"encoding/json"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// ContainerType identifies the type of container being inspected.
type ContainerType int

const (
	// ContainerTypeRegular is a standard container in spec.containers.
	ContainerTypeRegular ContainerType = iota
	// ContainerTypeInit is an init container in spec.initContainers.
	ContainerTypeInit
	// ContainerTypeSidecar is a native sidecar (K8s 1.28+): an initContainer with restartPolicy: Always.
	ContainerTypeSidecar
)

// String returns a human-readable name for the container type.
func (ct ContainerType) String() string {
	switch ct {
	case ContainerTypeRegular:
		return "container"
	case ContainerTypeInit:
		return "initContainer"
	case ContainerTypeSidecar:
		return "sidecarContainer"
	default:
		return fmt.Sprintf("ContainerType(%d)", int(ct))
	}
}

// PodSpecInfo bundles a PodSpec with its owning resource metadata.
type PodSpecInfo struct {
	// Spec is the extracted PodSpec.
	Spec corev1.PodSpec
	// ResourceName is the name of the owning resource (e.g., Deployment name).
	ResourceName string
	// Namespace is the namespace of the owning resource.
	Namespace string
	// Kind is the kind of the owning resource.
	Kind string
}

// workloadGVRs lists the GVRs that contain workload resources with PodSpecs.
var workloadGVRs = []schema.GroupVersionResource{
	{Group: "", Version: "v1", Resource: "pods"},
	{Group: "apps", Version: "v1", Resource: "deployments"},
	{Group: "apps", Version: "v1", Resource: "statefulsets"},
	{Group: "apps", Version: "v1", Resource: "daemonsets"},
	{Group: "apps", Version: "v1", Resource: "replicasets"},
	{Group: "batch", Version: "v1", Resource: "jobs"},
	{Group: "batch", Version: "v1", Resource: "cronjobs"},
}

// GVRs returns the list of GVRs that workload checkers require.
func GVRs() []schema.GroupVersionResource {
	result := make([]schema.GroupVersionResource, len(workloadGVRs))
	copy(result, workloadGVRs)
	return result
}

// ExtractPodSpecs extracts PodSpecInfo from all workload resources in the cache.
func ExtractPodSpecs(cache *checker.ResourceCache) []PodSpecInfo {
	var specs []PodSpecInfo

	for _, gvr := range workloadGVRs {
		resources := cache.List(gvr)
		kind := kindForGVR(gvr)
		for _, res := range resources {
			extracted := extractFromUnstructured(res, kind)
			specs = append(specs, extracted...)
		}
	}

	return specs
}

// extractFromUnstructured extracts PodSpecInfo from a single unstructured resource.
func extractFromUnstructured(obj unstructured.Unstructured, kind string) []PodSpecInfo {
	name := obj.GetName()
	namespace := obj.GetNamespace()

	podSpecMap, found := findPodSpecMap(obj.Object, kind)
	if !found {
		slog.Debug("could not extract PodSpec", "kind", kind, "name", name)
		return nil
	}

	// Marshal the podSpec map to JSON and unmarshal into a corev1.PodSpec.
	specJSON, err := json.Marshal(podSpecMap)
	if err != nil {
		slog.Debug("marshaling PodSpec", "kind", kind, "name", name, "error", err)
		return nil
	}

	var podSpec corev1.PodSpec
	if err := json.Unmarshal(specJSON, &podSpec); err != nil {
		slog.Debug("unmarshaling PodSpec", "kind", kind, "name", name, "error", err)
		return nil
	}

	return []PodSpecInfo{{
		Spec:         podSpec,
		ResourceName: name,
		Namespace:    namespace,
		Kind:         kind,
	}}
}

// findPodSpecMap navigates the unstructured object to find the PodSpec map.
// Different kinds have PodSpec at different paths.
func findPodSpecMap(obj map[string]interface{}, kind string) (map[string]interface{}, bool) {
	switch kind {
	case "Pod":
		return nestedMap(obj, "spec")
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
		return nestedMap(obj, "spec", "template", "spec")
	case "Job":
		return nestedMap(obj, "spec", "template", "spec")
	case "CronJob":
		return nestedMap(obj, "spec", "jobTemplate", "spec", "template", "spec")
	default:
		return nil, false
	}
}

// nestedMap retrieves a nested map from an unstructured object.
func nestedMap(obj map[string]interface{}, keys ...string) (map[string]interface{}, bool) {
	current := obj
	for _, key := range keys {
		val, ok := current[key]
		if !ok {
			return nil, false
		}
		nested, ok := val.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current = nested
	}
	return current, true
}

// IterateContainers calls fn for every container in the PodSpec, including
// regular containers, init containers, and native sidecars.
func IterateContainers(info *PodSpecInfo, fn func(c corev1.Container, ct ContainerType, idx int)) {
	for i := range info.Spec.Containers {
		fn(info.Spec.Containers[i], ContainerTypeRegular, i)
	}

	for i := range info.Spec.InitContainers {
		ct := ContainerTypeInit
		c := &info.Spec.InitContainers[i]
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			ct = ContainerTypeSidecar
		}
		fn(*c, ct, i)
	}
}

// kindForGVR maps a GVR to its Kind string.
func kindForGVR(gvr schema.GroupVersionResource) string {
	switch gvr.Resource {
	case "pods":
		return "Pod"
	case "deployments":
		return "Deployment"
	case "statefulsets":
		return "StatefulSet"
	case "daemonsets":
		return "DaemonSet"
	case "replicasets":
		return "ReplicaSet"
	case "jobs":
		return "Job"
	case "cronjobs":
		return "CronJob"
	default:
		return ""
	}
}
