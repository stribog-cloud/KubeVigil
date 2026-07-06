// Package workload implements workload security checks for Kubernetes pods and containers.
//
// It covers 31 checks spanning container privileges, capabilities, security contexts,
// resource limits, host access, runtime policies, and pod-lifecycle hardening
// (user-namespace isolation, Windows HostProcess containers, termination and
// hostAliases hygiene, ephemeral-storage requests, and legacy service-account
// token volume mounts).
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
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
	checker.MustRegister(&HostUsersNotIsolatedChecker{})
	checker.MustRegister(&WindowsHostProcessChecker{})
	checker.MustRegister(&TerminationGracePeriodZeroChecker{})
	checker.MustRegister(&HostAliasesInjectionChecker{})
	checker.MustRegister(&EphemeralStorageRequestsMissingChecker{})
	checker.MustRegister(&ServiceAccountTokenManualVolumeMountChecker{})
}
