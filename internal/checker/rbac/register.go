// Package rbac implements RBAC security checks for Kubernetes roles, bindings, and service accounts.
//
// It covers 22 checks spanning role permissions, cluster-admin usage, wildcard access,
// service account hygiene, token projection, and RBAC-based privilege-escalation vectors
// such as node-proxy access, CSR self-approval, admission webhook tampering, TokenRequest
// abuse, cross-namespace ServiceAccount trust, broad deletecollection grants, and
// ClusterRole aggregation label injection.
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
	checker.MustRegister(&NodeProxyAccessChecker{})
	checker.MustRegister(&CSRApprovalChecker{})
	checker.MustRegister(&WebhookTamperingChecker{})
	checker.MustRegister(&TokenRequestChecker{})
	checker.MustRegister(&CrossNamespaceServiceAccountChecker{})
	checker.MustRegister(&DeleteCollectionBroadChecker{})
	checker.MustRegister(&AggregationLabelInjectionChecker{})
}
