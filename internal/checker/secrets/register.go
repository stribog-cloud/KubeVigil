// Package secrets implements secret management checks for Kubernetes secrets and configmaps.
//
// It covers 7 checks spanning secrets in env vars, configmaps, and manifests,
// encryption at rest, rotation staleness, and external secret sync.
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
}
