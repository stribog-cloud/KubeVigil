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
