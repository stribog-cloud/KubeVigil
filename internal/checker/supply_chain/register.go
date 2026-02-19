// Package supply_chain implements supply chain security checks for Kubernetes workload lifecycle.
//
// It covers 5 checks spanning container runtime socket exposure, liveness/readiness/startup
// probe configuration, lifecycle hooks, and image age staleness.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package supply_chain

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&ContainerRuntimeSocketChecker{})
	checker.MustRegister(&LivenessReadinessProbesChecker{})
	checker.MustRegister(&StartupProbesChecker{})
	checker.MustRegister(&LifecycleHooksChecker{})
	checker.MustRegister(&ImageAgeChecker{})
}
