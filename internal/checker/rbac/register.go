// Package rbac implements RBAC security checks for Kubernetes roles, bindings, and service accounts.
//
// It covers 15 checks spanning role permissions, cluster-admin usage, wildcard access,
// service account hygiene, and token projection.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
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
