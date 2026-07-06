// Package storage implements storage security checkers.
// These checkers analyze PVC encryption, reclaim policies, CSI drivers,
// emptyDir volumes, projected volume permissions, subPath mounts, inline
// CSI ephemeral volumes, generic ephemeral volumes, and VolumeSnapshotClass
// encryption.
package storage

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

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
	// VolumeSnapshotClassGVR is the GroupVersionResource for snapshot.storage.k8s.io/v1
	// VolumeSnapshotClass objects.
	VolumeSnapshotClassGVR = schema.GroupVersionResource{
		Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses",
	}
)

// containerFieldPath builds a JSON-style field path for a container field,
// mirroring the equivalent helper in the workload package.
func containerFieldPath(ct workload.ContainerType, idx int, field string) string {
	switch ct {
	case workload.ContainerTypeInit, workload.ContainerTypeSidecar:
		return fmt.Sprintf(".spec.initContainers[%d].%s", idx, field)
	default:
		return fmt.Sprintf(".spec.containers[%d].%s", idx, field)
	}
}
