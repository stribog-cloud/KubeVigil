// Package secrets implements secret management checks for Kubernetes secrets and configmaps.
//
// It covers 12 checks spanning secrets in env vars, envFrom, configmaps,
// manifests, and workload annotations/labels; encryption at rest; rotation
// staleness; immutability and TLS key strength hardening; legacy
// ServiceAccount token Secrets; and external secret sync.
// All checkers implement the [checker.Checker] interface and are registered
// via [Register].
package secrets

import "github.com/stribog-cloud/kubevigil/internal/checker"

func init() {
	checker.MustRegister(&InEnvChecker{})
	checker.MustRegister(&UnencryptedChecker{})
	checker.MustRegister(&InConfigMapChecker{})
	checker.MustRegister(&DefaultTypeChecker{})
	checker.MustRegister(&StaleChecker{})
	checker.MustRegister(&HardcodedManifestsChecker{})
	checker.MustRegister(&ExternalSecretsSyncChecker{})
	checker.MustRegister(&ImmutableMissingChecker{})
	checker.MustRegister(&EnvFromBulkChecker{})
	checker.MustRegister(&ServiceAccountTokenSecretLegacyChecker{})
	checker.MustRegister(&TLSWeakKeyChecker{})
	checker.MustRegister(&InAnnotationsChecker{})
}
