// Package crd implements CRD and extension security checks for Kubernetes custom resources.
//
// It covers 7 checks spanning cert-manager certificate expiry and insecure configuration,
// CRD validation webhooks, conversion webhook security, deprecated preserveUnknownFields,
// missing status subresources, and multi-version CRDs with no conversion strategy.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package crd

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&ValidationMissingChecker{})
	checker.MustRegister(&ConversionWebhookChecker{})
	checker.MustRegister(&CertManagerExpiryChecker{})
	checker.MustRegister(&CertManagerInsecureChecker{})
	checker.MustRegister(&PreserveUnknownFieldsChecker{})
	checker.MustRegister(&StatusSubresourceMissingChecker{})
	checker.MustRegister(&MultiversionNoConversionChecker{})
}
