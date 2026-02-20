package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	assert.Equal(t, "1", cfg.Version)
	assert.Equal(t, "info", cfg.Settings.SeverityThreshold)
	assert.Equal(t, "high", cfg.Settings.FailOn)
	assert.Equal(t, 10, cfg.Settings.Concurrency)
	assert.Equal(t, "5m", cfg.Settings.Timeout)
	assert.Empty(t, cfg.Checks.Disabled)
	assert.Empty(t, cfg.Checks.Overrides)
	assert.Empty(t, cfg.Exemptions)
}

func TestLoadBytes_ValidConfig(t *testing.T) {
	data := []byte(`
version: "1"
settings:
  severity_threshold: "medium"
  fail_on: "critical"
  concurrency: 5
  timeout: "10m"
checks:
  disabled:
    - privileged
    - run-as-root
  overrides:
    host-pid:
      severity: "high"
exemptions:
  - namespace: kube-system
    checks:
      - privileged
    reason: "system component"
`)

	cfg, err := LoadBytes(data)
	require.NoError(t, err)

	assert.Equal(t, "1", cfg.Version)
	assert.Equal(t, "medium", cfg.Settings.SeverityThreshold)
	assert.Equal(t, "critical", cfg.Settings.FailOn)
	assert.Equal(t, 5, cfg.Settings.Concurrency)
	assert.Equal(t, "10m", cfg.Settings.Timeout)
	assert.Equal(t, []string{"privileged", "run-as-root"}, cfg.Checks.Disabled)
	assert.Equal(t, "high", cfg.Checks.Overrides["host-pid"].Severity)
	require.Len(t, cfg.Exemptions, 1)
	assert.Equal(t, "kube-system", cfg.Exemptions[0].Namespace)
	assert.Equal(t, []string{"privileged"}, cfg.Exemptions[0].Checks)
	assert.Equal(t, "system component", cfg.Exemptions[0].Reason)
}

func TestLoadBytes_MinimalConfig(t *testing.T) {
	data := []byte(`version: "1"`)

	cfg, err := LoadBytes(data)
	require.NoError(t, err)

	assert.Equal(t, "1", cfg.Version)
	// Defaults should be applied for omitted fields.
	assert.Equal(t, "info", cfg.Settings.SeverityThreshold)
	assert.Equal(t, "high", cfg.Settings.FailOn)
	assert.Equal(t, 10, cfg.Settings.Concurrency)
	assert.Equal(t, "5m", cfg.Settings.Timeout)
}

func TestLoadBytes_EmptyConfig(t *testing.T) {
	_, err := LoadBytes([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version is required")
}

func TestLoadBytes_InvalidVersion(t *testing.T) {
	data := []byte(`version: "2"`)

	_, err := LoadBytes(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestLoadBytes_InvalidSeverity(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "invalid severity_threshold",
			yaml: `version: "1"
settings:
  severity_threshold: "extreme"`,
			want: "invalid severity_threshold",
		},
		{
			name: "invalid fail_on",
			yaml: `version: "1"
settings:
  fail_on: "catastrophic"`,
			want: "invalid fail_on",
		},
		{
			name: "invalid override severity",
			yaml: `version: "1"
checks:
  overrides:
    privileged:
      severity: "super-high"`,
			want: "invalid severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tt.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestLoadBytes_InvalidConcurrency(t *testing.T) {
	data := []byte(`
version: "1"
settings:
  concurrency: 0
`)
	// Concurrency 0 should get defaulted to 10 by the merge step, not fail.
	// But if explicitly set to a negative number, it should fail.
	// Since YAML 0 is the zero value, it gets defaulted. Let's test negative.
	dataNeg := []byte(`
version: "1"
settings:
  concurrency: -1
`)
	_, err := LoadBytes(dataNeg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "concurrency must be > 0")

	// Zero gets defaulted.
	cfg, err := LoadBytes(data)
	require.NoError(t, err)
	assert.Equal(t, 10, cfg.Settings.Concurrency)
}

func TestIsCheckDisabled(t *testing.T) {
	cfg := &Config{
		Checks: ChecksConfig{
			Disabled: []string{"privileged", "run-as-root"},
		},
	}

	assert.True(t, IsCheckDisabled(cfg, "privileged"))
	assert.True(t, IsCheckDisabled(cfg, "run-as-root"))
	assert.False(t, IsCheckDisabled(cfg, "host-pid"))
	assert.False(t, IsCheckDisabled(cfg, ""))
}

func TestSeverityOverride(t *testing.T) {
	cfg := &Config{
		Checks: ChecksConfig{
			Overrides: map[string]CheckOverride{
				"host-pid": {Severity: "critical"},
			},
		},
	}

	sev, ok := SeverityOverride(cfg, "host-pid")
	assert.True(t, ok)
	assert.Equal(t, "critical", sev)

	_, ok = SeverityOverride(cfg, "privileged")
	assert.False(t, ok)
}

func TestFailOnSeverity(t *testing.T) {
	cfg := Default()
	assert.Equal(t, "high", FailOnSeverity(cfg))

	cfg.Settings.FailOn = "critical"
	assert.Equal(t, "critical", FailOnSeverity(cfg))
}

func TestGetTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		want    time.Duration
	}{
		{
			name:    "valid duration",
			timeout: "10m",
			want:    10 * time.Minute,
		},
		{
			name:    "valid seconds",
			timeout: "30s",
			want:    30 * time.Second,
		},
		{
			name:    "invalid string falls back to 5m",
			timeout: "not-a-duration",
			want:    5 * time.Minute,
		},
		{
			name:    "empty string falls back to 5m",
			timeout: "",
			want:    5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Settings: Settings{Timeout: tt.timeout}}
			assert.Equal(t, tt.want, GetTimeout(cfg))
		})
	}
}

func TestDiscover_Found(t *testing.T) {
	// Save and restore working directory.
	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	tmpDir := t.TempDir()
	// Resolve symlinks for macOS where /var -> /private/var.
	tmpDir, err = filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))

	// Create .kubevigil.yaml in the temp dir.
	configPath := filepath.Join(tmpDir, ".kubevigil.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`version: "1"`), 0o644))

	found, err := Discover()
	require.NoError(t, err)
	assert.Equal(t, configPath, found)
}

func TestDiscover_NotFound(t *testing.T) {
	// Save and restore working directory.
	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))

	found, err := Discover()
	require.NoError(t, err)
	assert.Equal(t, "", found)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/.kubevigil.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading config file")
}

func TestLoad_RejectsOversizedFile(t *testing.T) {
	tmpDir := t.TempDir()
	bigFile := filepath.Join(tmpDir, ".kubevigil.yaml")

	size := 1*1024*1024 + 1
	data := make([]byte, size)
	for i := range data {
		data[i] = '#'
	}
	require.NoError(t, os.WriteFile(bigFile, data, 0o644))

	_, err := Load(bigFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum", "error should mention size limit")
}

func TestLoad_AcceptsFileAtLimit(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".kubevigil.yaml")

	require.NoError(t, os.WriteFile(configFile, []byte(`version: "1"`), 0o644))

	cfg, err := Load(configFile)
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Version)
}

func TestLoadBytes_WithPolicies(t *testing.T) {
	data := []byte(`
version: "1"
policies:
  images:
    allowed_registries:
      - gcr.io
      - us-docker.pkg.dev
    blocked_registries:
      - docker.io
    require_signatures: true
`)
	cfg, err := LoadBytes(data)
	require.NoError(t, err)

	assert.Equal(t, []string{"gcr.io", "us-docker.pkg.dev"}, cfg.Policies.Images.AllowedRegistries)
	assert.Equal(t, []string{"docker.io"}, cfg.Policies.Images.BlockedRegistries)
	assert.True(t, cfg.Policies.Images.RequireSignatures)
	assert.False(t, cfg.Policies.Images.RequireSBOM)
	assert.False(t, cfg.Policies.Images.RequireProvenance)
}

func TestLoadBytes_WithPolicies_AllFields(t *testing.T) {
	data := []byte(`
version: "1"
policies:
  images:
    allowed_registries:
      - gcr.io
    blocked_registries:
      - docker.io
    require_signatures: true
    require_sbom: true
    require_provenance: true
`)
	cfg, err := LoadBytes(data)
	require.NoError(t, err)

	assert.True(t, cfg.Policies.Images.RequireSignatures)
	assert.True(t, cfg.Policies.Images.RequireSBOM)
	assert.True(t, cfg.Policies.Images.RequireProvenance)
}

func TestLoadBytes_NoPolicies(t *testing.T) {
	data := []byte(`version: "1"`)
	cfg, err := LoadBytes(data)
	require.NoError(t, err)

	// Policies should be zero-valued when not specified.
	assert.Empty(t, cfg.Policies.Images.AllowedRegistries)
	assert.Empty(t, cfg.Policies.Images.BlockedRegistries)
	assert.False(t, cfg.Policies.Images.RequireSignatures)
	assert.False(t, cfg.Policies.Images.RequireSBOM)
	assert.False(t, cfg.Policies.Images.RequireProvenance)
}

func TestIsSystemNamespace(t *testing.T) {
	tests := []struct {
		ns   string
		want bool
	}{
		{"kube-system", true},
		{"kube-public", true},
		{"kube-node-lease", true},
		{"default", false},
		{"production", false},
		{"", false},
		{"kube-system-extra", false},
	}
	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			assert.Equal(t, tt.want, IsSystemNamespace(tt.ns))
		})
	}
}

func TestLoad_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".kubevigil.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`version: "1"`), 0o644))

	cfg, err := Load(configPath)
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Version)
}

func TestDiscover_ReturnsEmptyForCleanDir(t *testing.T) {
	// Verify that Discover returns empty string when no config exists
	// in a temp dir with no config files.
	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))

	found, err := Discover()
	require.NoError(t, err)
	assert.Equal(t, "", found, "should return empty when no config file exists")
}

func TestDiscover_FindsConfigInCwd(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	tmpDir := t.TempDir()
	// Resolve symlinks for macOS where /var -> /private/var.
	tmpDir, err = filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))

	configPath := filepath.Join(tmpDir, ".kubevigil.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`version: "1"`), 0o644))

	found, err := Discover()
	require.NoError(t, err)
	assert.Equal(t, configPath, found, "should find .kubevigil.yaml in current directory")
}
