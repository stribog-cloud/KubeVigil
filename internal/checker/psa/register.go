// Package psa implements Pod Security Admission checks for Kubernetes namespaces and workloads.
//
// It covers 6 checks spanning PSA label enforcement, baseline and restricted profile violations,
// version pinning, and legacy PodSecurityPolicy migration detection.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package psa

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&LabelsMissingChecker{})
	checker.MustRegister(&ModeAuditOnlyChecker{})
	checker.MustRegister(&BaselineViolationsChecker{})
	checker.MustRegister(&RestrictedViolationsChecker{})
	checker.MustRegister(&VersionPinningChecker{})
	checker.MustRegister(&PSPStillPresentChecker{})
}
