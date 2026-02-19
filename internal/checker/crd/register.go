// Package crd implements CRD and extension security checks for Kubernetes custom resources.
//
// It covers 4 checks spanning cert-manager certificate expiry and insecure configuration,
// CRD validation webhooks, and conversion webhook security.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package crd

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&ValidationMissingChecker{})
	checker.MustRegister(&ConversionWebhookChecker{})
	checker.MustRegister(&CertManagerExpiryChecker{})
	checker.MustRegister(&CertManagerInsecureChecker{})
}
