// Package image implements container image security checks for Kubernetes workloads.
//
// It covers 9 checks spanning tag policies, digest pinning, registry allowlists/blocklists,
// provenance verification, SBOM attestation, and image signatures.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
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
