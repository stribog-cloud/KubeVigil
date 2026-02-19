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
