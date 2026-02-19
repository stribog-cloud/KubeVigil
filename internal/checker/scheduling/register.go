package scheduling

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&TolerationControlPlaneChecker{})
	checker.MustRegister(&TolerationAllChecker{})
	checker.MustRegister(&PriorityClassSystemChecker{})
	checker.MustRegister(&PriorityClassMissingChecker{})
	checker.MustRegister(&PodDisruptionBudgetChecker{})
	checker.MustRegister(&TopologySpreadChecker{})
	checker.MustRegister(&NodeAffinityUntrustedChecker{})
	checker.MustRegister(&HPAWithoutRequestsChecker{})
}
