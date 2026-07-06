// Package network implements network security checks for Kubernetes network policies, ingresses, and services.
//
// It covers 18 checks spanning network policy enforcement, ingress TLS configuration,
// service exposure, DNS security, service mesh mTLS, Gateway API listener/route hardening,
// and cloud instance-metadata egress protection.
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
	checker.MustRegister(&GatewayListenerNoTLSChecker{})
	checker.MustRegister(&GatewayAllowedRoutesAllNamespacesChecker{})
	checker.MustRegister(&HTTPRouteWildcardHostnameChecker{})
	checker.MustRegister(&EmptyNamespaceSelectorChecker{})
	checker.MustRegister(&ServiceExternalNameDanglingChecker{})
	checker.MustRegister(&MetadataServiceEgressChecker{})
}
