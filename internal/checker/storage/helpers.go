// Package storage implements storage security checkers.
// These checkers analyze PVC encryption, reclaim policies, CSI drivers,
// emptyDir volumes, and projected volume permissions.
package storage

import "k8s.io/apimachinery/pkg/runtime/schema"

// GVR constants for storage-related resources.
var (
	PersistentVolumeClaimGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "persistentvolumeclaims",
	}
	PersistentVolumeGVR = schema.GroupVersionResource{
		Group: "", Version: "v1", Resource: "persistentvolumes",
	}
	StorageClassGVR = schema.GroupVersionResource{
		Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses",
	}
	CSIDriverGVR = schema.GroupVersionResource{
		Group: "storage.k8s.io", Version: "v1", Resource: "csidrivers",
	}
)
