package storage

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&PVCNoEncryptionChecker{})
	checker.MustRegister(&PVCReclaimRetainChecker{})
	checker.MustRegister(&CSIDriverSecurityChecker{})
	checker.MustRegister(&EmptyDirSizeLimitChecker{})
	checker.MustRegister(&ProjectedVolumeSecurityChecker{})
}
