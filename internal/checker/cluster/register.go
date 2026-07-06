// Package cluster implements cluster-level security checks for Kubernetes control plane and namespaces.
//
// It covers 15 checks spanning API server configuration, admission controllers, audit logging,
// etcd encryption, component versions, resource quotas, and admission-webhook/API-aggregation
// hardening (fail-open webhooks, wildcard-scoped mutating webhooks, audit-only
// ValidatingAdmissionPolicy bindings, external webhook endpoints, and insecure APIService TLS).
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package cluster

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&NamespaceDefaultUsageChecker{})
	checker.MustRegister(&LimitRangeMissingChecker{})
	checker.MustRegister(&ResourceQuotaMissingChecker{})
	checker.MustRegister(&APIServerAnonymousChecker{})
	checker.MustRegister(&AuditLoggingChecker{})
	checker.MustRegister(&AdmissionControllersChecker{})
	checker.MustRegister(&EtcdEncryptionChecker{})
	checker.MustRegister(&KubeletConfigChecker{})
	checker.MustRegister(&ComponentVersionsChecker{})
	checker.MustRegister(&DeprecatedAPIUsageChecker{})
	checker.MustRegister(&ValidatingWebhookFailurePolicyIgnoreChecker{})
	checker.MustRegister(&MutatingWebhookWildcardScopeChecker{})
	checker.MustRegister(&ValidatingAdmissionPolicyAuditOnlyChecker{})
	checker.MustRegister(&WebhookExternalURLChecker{})
	checker.MustRegister(&APIServiceInsecureSkipVerifyChecker{})
}
