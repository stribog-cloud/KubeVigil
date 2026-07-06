// Package scheduling implements scheduling security checks for Kubernetes pod placement and disruption.
//
// It covers 11 checks spanning tolerations, node affinity, priority classes,
// topology spread, PodDisruptionBudgets, HPA resource alignment, Job deadline
// hygiene, and CronJob concurrency bounds.
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
	checker.MustRegister(&JobActiveDeadlineMissingChecker{})
	checker.MustRegister(&PriorityClassExcessiveValueChecker{})
	checker.MustRegister(&CronJobConcurrencyUnboundedChecker{})
}
