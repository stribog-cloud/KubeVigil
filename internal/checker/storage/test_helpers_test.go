package storage

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

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
