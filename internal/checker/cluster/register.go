// Package cluster implements cluster-level security checks for Kubernetes control plane and namespaces.
//
// It covers 10 checks spanning API server configuration, admission controllers, audit logging,
// etcd encryption, component versions, and resource quotas.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package cluster

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&NamespaceDefaultUsageChecker{})
	checker.MustRegister(&LimitRangeMissingChecker{})
	checker.MustRegister(&ResourceQuotaMissingChecker{})
	checker.MustRegister(&APIServerAnonymousChecker{})
	checker.MustRegister(&AuditLoggingChecker{})
	checker.MustRegister(&AdmissionControllersChecker{})
	checker.MustRegister(&EtcdEncryptionChecker{})
	checker.MustRegister(&KubeletConfigChecker{})
	checker.MustRegister(&ComponentVersionsChecker{})
	checker.MustRegister(&DeprecatedAPIUsageChecker{})
}
