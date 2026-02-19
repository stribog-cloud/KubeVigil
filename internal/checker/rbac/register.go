package rbac

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&DefaultServiceAccountChecker{})
	checker.MustRegister(&AutomountTokenChecker{})
	checker.MustRegister(&TokenProjectionConfigChecker{})
	checker.MustRegister(&WildcardVerbsChecker{})
	checker.MustRegister(&WildcardResourcesChecker{})
	checker.MustRegister(&WildcardAPIGroupsChecker{})
	checker.MustRegister(&EscalationVerbsChecker{})
	checker.MustRegister(&SecretAccessChecker{})
	checker.MustRegister(&ExecAccessChecker{})
	checker.MustRegister(&LogAccessChecker{})
	checker.MustRegister(&ClusterAdminChecker{})
	checker.MustRegister(&UnusedRolesChecker{})
	checker.MustRegister(&GroupBindingsChecker{})
	checker.MustRegister(&SubjectExternalChecker{})
	checker.MustRegister(&CloudIAMBindingChecker{})
}
