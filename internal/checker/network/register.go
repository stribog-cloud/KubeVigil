package network

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&PolicyMissingChecker{})
	checker.MustRegister(&DefaultDenyChecker{})
	checker.MustRegister(&OverlyPermissiveChecker{})
	checker.MustRegister(&EgressUnrestrictedChecker{})
	checker.MustRegister(&IngressNoTLSChecker{})
	checker.MustRegister(&IngressWildcardHostChecker{})
	checker.MustRegister(&IngressClassMissingChecker{})
	checker.MustRegister(&ServiceTypeLoadBalancerChecker{})
	checker.MustRegister(&ServiceTypeNodePortChecker{})
	checker.MustRegister(&ExternalIPsChecker{})
	checker.MustRegister(&ServiceMeshMTLSChecker{})
	checker.MustRegister(&DNSSecurityChecker{})
}
