package crd

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&ValidationMissingChecker{})
	checker.MustRegister(&ConversionWebhookChecker{})
	checker.MustRegister(&CertManagerExpiryChecker{})
	checker.MustRegister(&CertManagerInsecureChecker{})
}
