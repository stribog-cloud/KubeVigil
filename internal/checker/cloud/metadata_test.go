package cloud

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestCloudCheckersMetadata(t *testing.T) {
	checkers := []checker.Checker{
		&AKSPodIdentityChecker{},
		&ProviderDetectionChecker{},
		&EKSIMDSAccessChecker{},
		&GKEMetadataConcealmentChecker{},
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
