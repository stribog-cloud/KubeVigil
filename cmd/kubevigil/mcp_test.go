package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunMCPServer_ConfigError(t *testing.T) {
	saveAndRestoreFlags(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("{{invalid"), 0o644))
	flagConfig = bad

	err := runMCPServer(mcpCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading config")
}

func TestRunMCPServer_InvalidConfigPath(t *testing.T) {
	saveAndRestoreFlags(t)
	flagConfig = "/nonexistent/kubevigil-config.yaml"

	err := runMCPServer(mcpCmd, nil)
	require.Error(t, err)
}
