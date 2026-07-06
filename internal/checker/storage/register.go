// Package storage implements storage security checks for Kubernetes persistent volumes and CSI drivers.
//
// It covers 9 checks spanning PVC encryption, reclaim policies, CSI driver configuration,
// emptyDir size limits, projected volume security, subPath symlink risk, inline CSI
// ephemeral volumes, generic ephemeral volume storage limits, and VolumeSnapshotClass
// encryption.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package storage

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&PVCNoEncryptionChecker{})
	checker.MustRegister(&PVCReclaimRetainChecker{})
	checker.MustRegister(&CSIDriverSecurityChecker{})
	checker.MustRegister(&EmptyDirSizeLimitChecker{})
	checker.MustRegister(&ProjectedVolumeSecurityChecker{})
	checker.MustRegister(&SubPathSymlinkRiskChecker{})
	checker.MustRegister(&CSIInlineEphemeralVolumeChecker{})
	checker.MustRegister(&GenericEphemeralVolumeNoLimitsChecker{})
	checker.MustRegister(&VolumeSnapshotClassNoEncryptionChecker{})
}
