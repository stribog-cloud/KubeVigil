package checker_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"

	_ "github.com/stribog-cloud/kubevigil/internal/checker/cloud"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cluster"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/crd"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/image"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/network"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/psa"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/rbac"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/scheduling"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/secrets"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/storage"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/supply_chain"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
)

// TestRegisteredCheckerMetadata exercises metadata methods for every registered checker
// inside the coverage measurement boundary (internal/).
func TestRegisteredCheckerMetadata(t *testing.T) {
	checkers := checker.DefaultRegistry().All()
	require.NotEmpty(t, checkers)

	empty := checker.NewResourceCache()

	for _, c := range checkers {
		if strings.HasPrefix(c.Name(), "__test-") {
			continue
		}
		t.Run(c.Name(), func(t *testing.T) {
			assert.NotEmpty(t, c.Name())
			assert.NotEmpty(t, c.Description())
			assert.NotEmpty(t, c.Categories())
			assert.NotEmpty(t, c.SupportedModes())
			assert.NotEmpty(t, c.RequiredResources())

			findings, err := c.Run(context.Background(), empty)
			require.NoError(t, err)
			assert.Empty(t, findings)

			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = c.Run(cancelled, empty)
			assert.Error(t, err)
		})
	}
}
