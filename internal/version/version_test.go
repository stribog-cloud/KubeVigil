package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultValues(t *testing.T) {
	assert.Equal(t, "dev", Version, "default Version should be 'dev'")
	assert.Equal(t, "unknown", Commit, "default Commit should be 'unknown'")
	assert.Equal(t, "unknown", Date, "default Date should be 'unknown'")
}

func TestVersionNotEmpty(t *testing.T) {
	assert.NotEmpty(t, Version)
	assert.NotEmpty(t, Commit)
	assert.NotEmpty(t, Date)
}
