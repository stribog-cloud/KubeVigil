package image

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&TagLatestChecker{})
	checker.MustRegister(&TagMissingChecker{})
	checker.MustRegister(&NoDigestChecker{})
	checker.MustRegister(&PullPolicyChecker{})
	checker.MustRegister(&RegistryAllowlistChecker{})
	checker.MustRegister(&RegistryBlocklistChecker{})
	checker.MustRegister(&SignatureVerificationChecker{})
	checker.MustRegister(&SBOMAttestationChecker{})
	checker.MustRegister(&ProvenanceChecker{})
}
