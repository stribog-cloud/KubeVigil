// Package cloud implements cloud provider security checks for Kubernetes clusters on managed platforms.
//
// It covers 4 checks spanning EKS IMDS access, GKE metadata concealment,
// AKS pod identity, and cloud provider detection.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package cloud

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&EKSIMDSAccessChecker{})
	checker.MustRegister(&GKEMetadataConcealmentChecker{})
	checker.MustRegister(&AKSPodIdentityChecker{})
	checker.MustRegister(&ProviderDetectionChecker{})
}
