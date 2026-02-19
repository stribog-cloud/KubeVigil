package supply_chain

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&ContainerRuntimeSocketChecker{})
	checker.MustRegister(&LivenessReadinessProbesChecker{})
	checker.MustRegister(&StartupProbesChecker{})
	checker.MustRegister(&LifecycleHooksChecker{})
	checker.MustRegister(&ImageAgeChecker{})
}
