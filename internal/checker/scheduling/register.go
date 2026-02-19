// Package scheduling implements scheduling security checks for Kubernetes pod placement and disruption.
//
// It covers 8 checks spanning tolerations, node affinity, priority classes,
// topology spread, PodDisruptionBudgets, and HPA resource alignment.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
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
