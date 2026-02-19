// Package storage implements storage security checks for Kubernetes persistent volumes and CSI drivers.
//
// It covers 5 checks spanning PVC encryption, reclaim policies, CSI driver configuration,
// emptyDir size limits, and projected volume security.
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
}
