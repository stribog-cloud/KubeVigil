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
