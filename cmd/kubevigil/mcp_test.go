package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestRunMCPServer_ExplicitWorkspaceRootConfigError(t *testing.T) {
	saveAndRestoreFlags(t)
	mcpWorkspaceRoot = t.TempDir()
	flagConfig = "/nonexistent/kubevigil-config.yaml"

	err := runMCPServer(mcpCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading config")
}

func TestRunMCPServer_WorkspaceRootRelativePathConfigError(t *testing.T) {
	saveAndRestoreFlags(t)
	sub := "ws-subdir"
	require.NoError(t, os.Mkdir(sub, 0o755))
	t.Cleanup(func() { _ = os.Remove(sub) })
	mcpWorkspaceRoot = sub
	flagConfig = "/nonexistent/kubevigil-config.yaml"

	err := runMCPServer(mcpCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading config")
}

func TestResolveMCPWorkspaceRoot_WarnsWhenUnset(t *testing.T) {
	t.Setenv("KUBEVIGIL_WORKSPACE_ROOT", "")

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = origStderr
		_ = r.Close()
	})
	setupLogging()

	got, rootErr := resolveMCPWorkspaceRoot("")
	require.NoError(t, rootErr)
	require.NotEmpty(t, got)

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "falling back to process cwd") {
		t.Fatalf("expected cwd fallback warning on stderr, got: %q", buf.String())
	}
}

func TestResolveMCPWorkspaceRoot_UsesExplicitPath(t *testing.T) {
	root := t.TempDir()
	got, err := resolveMCPWorkspaceRoot(root)
	require.NoError(t, err)
	want, _ := filepath.Abs(root)
	assert.Equal(t, want, got)
}

func TestRunMCPServer_DefaultWorkspaceRootFromEnv(t *testing.T) {
	saveAndRestoreFlags(t)
	root := t.TempDir()
	t.Setenv("KUBEVIGIL_WORKSPACE_ROOT", root)
	mcpWorkspaceRoot = ""
	flagConfig = "/nonexistent/kubevigil-config.yaml"

	err := runMCPServer(mcpCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading config")
}
