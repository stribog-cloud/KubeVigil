package cloud

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&EKSIMDSAccessChecker{})
	checker.MustRegister(&GKEMetadataConcealmentChecker{})
	checker.MustRegister(&AKSPodIdentityChecker{})
	checker.MustRegister(&ProviderDetectionChecker{})
}
