package storage

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// podGVR is the GroupVersionResource for core/v1 Pod objects, used by tests
// that build workload PodSpecInfo via workload.ExtractPodSpecs.
var podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

// toUnstructured converts a typed Kubernetes object to an unstructured representation.
func toUnstructured(t *testing.T, obj interface{}) unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	var result unstructured.Unstructured
	require.NoError(t, json.Unmarshal(data, &result.Object))
	return result
}

// makePodWithSpec creates a Pod with the given name, namespace, and PodSpec.
func makePodWithSpec(t *testing.T, name, ns string, spec corev1.PodSpec) unstructured.Unstructured {
	t.Helper()
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: spec,
	}
	return toUnstructured(t, pod)
}

// makeVolumeSnapshotClass creates an unstructured VolumeSnapshotClass for testing.
func makeVolumeSnapshotClass(name string, params map[string]string) unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion":     "snapshot.storage.k8s.io/v1",
		"kind":           "VolumeSnapshotClass",
		"metadata":       map[string]any{"name": name},
		"driver":         "example.csi.k8s.io",
		"deletionPolicy": "Delete",
	}
	if params != nil {
		p := make(map[string]any, len(params))
		for k, v := range params {
			p[k] = v
		}
		obj["parameters"] = p
	} else {
		obj["parameters"] = map[string]any{}
	}
	return unstructured.Unstructured{Object: obj}
}

// makePVC creates an unstructured PVC for testing.
func makePVC(name, ns, storageClass string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec":       map[string]any{"storageClassName": storageClass},
	}}
}

// makeStorageClass creates an unstructured StorageClass for testing.
func makeStorageClass(name string, params map[string]string) unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "storage.k8s.io/v1",
		"kind":       "StorageClass",
		"metadata":   map[string]any{"name": name},
	}
	if params != nil {
		p := make(map[string]any, len(params))
		for k, v := range params {
			p[k] = v
		}
		obj["parameters"] = p
	}
	return unstructured.Unstructured{Object: obj}
}

// makePV creates an unstructured PersistentVolume for testing.
func makePV(name, reclaimPolicy, phase string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolume",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"persistentVolumeReclaimPolicy": reclaimPolicy},
		"status":     map[string]any{"phase": phase},
	}}
}

// makeCSIDriver creates an unstructured CSIDriver for testing.
func makeCSIDriver(name string, podInfoOnMount *bool) unstructured.Unstructured {
	spec := map[string]any{}
	if podInfoOnMount != nil {
		spec["podInfoOnMount"] = *podInfoOnMount
	}
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "storage.k8s.io/v1",
		"kind":       "CSIDriver",
		"metadata":   map[string]any{"name": name},
		"spec":       spec,
	}}
}

func boolPtr(v bool) *bool { return &v }
