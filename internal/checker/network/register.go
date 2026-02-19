// Package network implements network security checks for Kubernetes network policies, ingresses, and services.
//
// It covers 12 checks spanning network policy enforcement, ingress TLS configuration,
// service exposure, DNS security, and service mesh mTLS.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
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
