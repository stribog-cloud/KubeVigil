package workload

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&PrivilegedChecker{})
	checker.MustRegister(&CapabilitiesAddedChecker{})
	checker.MustRegister(&CapabilitiesNotDroppedChecker{})
	checker.MustRegister(&RunAsRootChecker{})
	checker.MustRegister(&RunAsHighUIDChecker{})
	checker.MustRegister(&RunAsGroupChecker{})
	checker.MustRegister(&ReadOnlyRootfsChecker{})
	checker.MustRegister(&ResourceLimitsMissingChecker{})
	checker.MustRegister(&ResourceRequestsMissingChecker{})
	checker.MustRegister(&ResourceLimitsRatioChecker{})
	checker.MustRegister(&EphemeralStorageLimitsChecker{})
	checker.MustRegister(&HostPIDChecker{})
	checker.MustRegister(&HostIPCChecker{})
	checker.MustRegister(&HostNetworkChecker{})
	checker.MustRegister(&HostPortsChecker{})
	checker.MustRegister(&HostPathVolumesChecker{})
	checker.MustRegister(&PrivilegeEscalationChecker{})
	checker.MustRegister(&SeccompProfileChecker{})
	checker.MustRegister(&AppArmorProfileChecker{})
	checker.MustRegister(&SELinuxOptionsChecker{})
	checker.MustRegister(&ProcMountChecker{})
	checker.MustRegister(&UnsafeSysctlsChecker{})
	checker.MustRegister(&RuntimeClassChecker{})
	checker.MustRegister(&ShareProcessNamespaceChecker{})
	checker.MustRegister(&EphemeralContainerPolicyChecker{})
}
