package checker

import (
	"context"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var kebabCaseRe = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// RunCheckerContractTests runs the standard contract test suite against a set of checkers.
// It verifies each checker meets the Checker interface contract:
//   - Name() returns a non-empty kebab-case string
//   - Description() returns a non-empty string
//   - Categories() returns at least one valid category
//   - SupportedModes() returns at least one valid mode
//   - RequiredResources() returns valid GVRs
//   - Run() with empty ResourceCache returns no findings and no error
//   - Run() with cancelled context returns an error
func RunCheckerContractTests(t *testing.T, checkers []Checker) {
	t.Helper()

	for _, c := range checkers {
		c := c
		t.Run(c.Name(), func(t *testing.T) {
			t.Parallel()

			name := c.Name()
			assert.NotEmpty(t, name, "Name() must not be empty")
			assert.Regexp(t, kebabCaseRe, name, "Name() must be kebab-case")

			assert.NotEmpty(t, c.Description(), "Description() must not be empty")

			cats := c.Categories()
			assert.NotEmpty(t, cats, "Categories() must return at least one category")

			modes := c.SupportedModes()
			assert.NotEmpty(t, modes, "SupportedModes() must return at least one mode")

			gvrs := c.RequiredResources()
			assert.NotEmpty(t, gvrs, "RequiredResources() must return at least one GVR")
			for _, gvr := range gvrs {
				assert.NotEmpty(t, gvr.Resource, "GVR Resource must not be empty")
				assert.NotEmpty(t, gvr.Version, "GVR Version must not be empty")
			}

			emptyCache := NewResourceCache()
			findings, err := c.Run(context.Background(), emptyCache)
			require.NoError(t, err, "Run() with empty cache should not error")
			assert.Empty(t, findings, "Run() with empty cache should return no findings")

			cancelledCtx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = c.Run(cancelledCtx, emptyCache)
			assert.Error(t, err, "Run() with cancelled context should return error")
		})
	}
}
