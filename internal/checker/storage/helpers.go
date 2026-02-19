// Package storage implements storage security checkers.
// These checkers analyze PVC encryption, reclaim policies, CSI drivers,
// emptyDir volumes, and projected volume permissions.
package storage

import "k8s.io/apimachinery/pkg/runtime/schema"

// GVR constants for storage-related resources.
var (
	// PersistentVolumeClaimGVR is the GroupVersionResource for core/v1 PersistentVolumeClaim objects.
	PersistentVolumeClaimGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "persistentvolumeclaims",
	}
	// PersistentVolumeGVR is the GroupVersionResource for core/v1 PersistentVolume objects.
	PersistentVolumeGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "persistentvolumes",
	}
	// StorageClassGVR is the GroupVersionResource for storage.k8s.io/v1 StorageClass objects.
	StorageClassGVR = schema.GroupVersionResource{
		Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses",
	}
	// CSIDriverGVR is the GroupVersionResource for storage.k8s.io/v1 CSIDriver objects.
	CSIDriverGVR = schema.GroupVersionResource{
		Group: "storage.k8s.io", Version: "v1", Resource: "csidrivers",
	}
)
