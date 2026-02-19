// Package config handles loading, validating, and querying KubeVigil configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// validSeverities is the set of accepted severity strings.
var validSeverities = map[string]bool{
	"info":     true,
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

// Config is the top-level configuration for KubeVigil.
type Config struct {
	// Version is the config file format version.
	Version string `yaml:"version"`
	// Settings contains global scan settings.
	Settings Settings `yaml:"settings"`
	// Checks configures which checks to run and severity overrides.
	Checks ChecksConfig `yaml:"checks"`
	// Exemptions lists resources that should be skipped during scanning.
	Exemptions []Exemption `yaml:"exemptions"`
}

// Settings contains global scan settings.
type Settings struct {
	// SeverityThreshold is the minimum severity to report.
	SeverityThreshold string `yaml:"severity_threshold"`
	// FailOn is the minimum severity that causes a non-zero exit code.
	FailOn string `yaml:"fail_on"`
	// Concurrency is the maximum number of checks to run in parallel.
	Concurrency int `yaml:"concurrency"`
	// Timeout is the maximum duration for the scan (e.g., "5m", "30s").
	Timeout string `yaml:"timeout"`
}

// ChecksConfig configures which checks to run and their overrides.
type ChecksConfig struct {
	// Disabled is a list of check IDs to skip.
	Disabled []string `yaml:"disabled"`
	// Overrides maps check IDs to per-check overrides.
	Overrides map[string]CheckOverride `yaml:"overrides"`
}

// CheckOverride holds per-check configuration overrides.
type CheckOverride struct {
	// Severity overrides the default severity for this check.
	Severity string `yaml:"severity"`
}

// Default returns a Config with sensible default values.
func Default() *Config {
	return &Config{
		Version: "1",
		Settings: Settings{
			SeverityThreshold: "info",
			FailOn:            "high",
			Concurrency:       10,
			Timeout:           "5m",
		},
	}
}

// Load reads and parses a config file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes parses YAML config data, merges with defaults for zero values, and validates.
func LoadBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Merge defaults for zero values.
	defaults := Default()
	if cfg.Settings.SeverityThreshold == "" {
		cfg.Settings.SeverityThreshold = defaults.Settings.SeverityThreshold
	}
	if cfg.Settings.FailOn == "" {
		cfg.Settings.FailOn = defaults.Settings.FailOn
	}
	if cfg.Settings.Concurrency == 0 {
		cfg.Settings.Concurrency = defaults.Settings.Concurrency
	}
	if cfg.Settings.Timeout == "" {
		cfg.Settings.Timeout = defaults.Settings.Timeout
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Discover searches standard locations for a KubeVigil config file.
// It checks: cwd/.kubevigil.yaml, ~/.config/kubevigil/kubevigil.yaml, ~/.kubevigil.yaml.
// Returns the path of the first file found, or "" if none exist.
func Discover() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home directory: %w", err)
	}

	candidates := []string{
		filepath.Join(cwd, ".kubevigil.yaml"),
		filepath.Join(home, ".config", "kubevigil", "kubevigil.yaml"),
		filepath.Join(home, ".kubevigil.yaml"),
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", nil
}

// IsCheckDisabled returns true if the named check is in the disabled list.
func IsCheckDisabled(cfg *Config, name string) bool {
	for _, d := range cfg.Checks.Disabled {
		if d == name {
			return true
		}
	}
	return false
}

// SeverityOverride returns the overridden severity string for a check, if configured.
func SeverityOverride(cfg *Config, name string) (string, bool) {
	if override, ok := cfg.Checks.Overrides[name]; ok && override.Severity != "" {
		return override.Severity, true
	}
	return "", false
}

// FailOnSeverity returns the configured fail-on severity string.
func FailOnSeverity(cfg *Config) string {
	return cfg.Settings.FailOn
}

// GetTimeout parses the configured timeout string into a time.Duration.
// Returns 5 minutes if the string is invalid.
func GetTimeout(cfg *Config) time.Duration {
	d, err := time.ParseDuration(cfg.Settings.Timeout)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// validate checks that the config is well-formed.
func validate(cfg *Config) error {
	if cfg.Version == "" {
		return fmt.Errorf("config validation: version is required")
	}
	if cfg.Version != "1" {
		return fmt.Errorf("config validation: unsupported version %q (expected \"1\")", cfg.Version)
	}
	if !validSeverities[strings.ToLower(cfg.Settings.SeverityThreshold)] {
		return fmt.Errorf("config validation: invalid severity_threshold %q", cfg.Settings.SeverityThreshold)
	}
	if !validSeverities[strings.ToLower(cfg.Settings.FailOn)] {
		return fmt.Errorf("config validation: invalid fail_on %q", cfg.Settings.FailOn)
	}
	if cfg.Settings.Concurrency <= 0 {
		return fmt.Errorf("config validation: concurrency must be > 0, got %d", cfg.Settings.Concurrency)
	}
	for name, override := range cfg.Checks.Overrides {
		if override.Severity != "" && !validSeverities[strings.ToLower(override.Severity)] {
			return fmt.Errorf("config validation: invalid severity %q for check override %q", override.Severity, name)
		}
	}
	return nil
}
