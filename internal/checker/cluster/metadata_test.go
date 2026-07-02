package cluster

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestClusterCheckersMetadata(t *testing.T) {
	checkers := []checker.Checker{
		&AdmissionControllersChecker{},
		&APIServerAnonymousChecker{},
		&AuditLoggingChecker{},
		&ComponentVersionsChecker{},
		&DeprecatedAPIUsageChecker{},
		&EtcdEncryptionChecker{},
		&KubeletConfigChecker{},
		&LimitRangeMissingChecker{},
		&NamespaceDefaultUsageChecker{},
		&ResourceQuotaMissingChecker{},
	}

	for _, c := range checkers {
		t.Run(c.Name(), func(t *testing.T) {
			assert.NotEmpty(t, c.Description())
			assert.NotEmpty(t, c.Categories())
			assert.NotEmpty(t, c.SupportedModes())
			assert.NotEmpty(t, c.RequiredResources())
		})
	}
}
