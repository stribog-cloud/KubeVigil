package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestHasFailures(t *testing.T) {
	tests := []struct {
		name     string
		findings []checker.Finding
		failOn   string
		want     bool
	}{
		{
			name:     "empty findings returns false",
			findings: nil,
			failOn:   "high",
			want:     false,
		},
		{
			name: "medium finding below high threshold returns false",
			findings: []checker.Finding{
				{Checker: "test-check", Severity: checker.SeverityMedium},
			},
			failOn: "high",
			want:   false,
		},
		{
			name: "high finding at high threshold returns true",
			findings: []checker.Finding{
				{Checker: "test-check", Severity: checker.SeverityHigh},
			},
			failOn: "high",
			want:   true,
		},
		{
			name: "critical finding above high threshold returns true",
			findings: []checker.Finding{
				{Checker: "test-check", Severity: checker.SeverityCritical},
			},
			failOn: "high",
			want:   true,
		},
		{
			name: "invalid failOn severity returns false",
			findings: []checker.Finding{
				{Checker: "test-check", Severity: checker.SeverityCritical},
			},
			failOn: "invalid",
			want:   false,
		},
		{
			name: "info finding at info threshold returns true",
			findings: []checker.Finding{
				{Checker: "test-check", Severity: checker.SeverityInfo},
			},
			failOn: "info",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasFailures(tt.findings, tt.failOn)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("empty flagConfig returns default config", func(t *testing.T) {
		orig := flagConfig
		defer func() { flagConfig = orig }()

		flagConfig = ""
		cfg, err := loadConfig()
		require.NoError(t, err)
		assert.NotNil(t, cfg)
	})

	t.Run("nonexistent path returns error", func(t *testing.T) {
		orig := flagConfig
		defer func() { flagConfig = orig }()

		flagConfig = "/nonexistent/path.yaml"
		_, err := loadConfig()
		assert.Error(t, err)
	})

	t.Run("valid config file loads successfully", func(t *testing.T) {
		orig := flagConfig
		defer func() { flagConfig = orig }()

		dir := t.TempDir()
		path := filepath.Join(dir, ".kubevigil.yaml")
		err := os.WriteFile(path, []byte("version: \"1\"\nsettings:\n  fail_on: high\n"), 0o644)
		require.NoError(t, err)

		flagConfig = path
		cfg, err := loadConfig()
		require.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, "high", cfg.Settings.FailOn)
	})
}

func TestResolveContextName(t *testing.T) {
	t.Run("explicit context returned as-is", func(t *testing.T) {
		got := resolveContextName("", "my-context")
		assert.Equal(t, "my-context", got)
	})

	t.Run("empty explicit context does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			_ = resolveContextName("", "")
		})
	})
}

func TestFormatCategories(t *testing.T) {
	tests := []struct {
		name       string
		categories []checker.Category
		want       string
	}{
		{
			name:       "empty slice",
			categories: nil,
			want:       "",
		},
		{
			name:       "single category",
			categories: []checker.Category{checker.CategoryWorkload},
			want:       "Workload",
		},
		{
			name:       "multiple categories",
			categories: []checker.Category{checker.CategoryWorkload, checker.CategoryImage},
			want:       "Workload, Image",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCategories(tt.categories)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatModes(t *testing.T) {
	tests := []struct {
		name  string
		modes []checker.ScanMode
		want  string
	}{
		{
			name:  "empty slice",
			modes: nil,
			want:  "",
		},
		{
			name:  "single mode",
			modes: []checker.ScanMode{checker.ScanModeLive},
			want:  "Live",
		},
		{
			name:  "multiple modes",
			modes: []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest},
			want:  "Live, Manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatModes(tt.modes)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSetupLogging(t *testing.T) {
	t.Run("verbose false does not panic", func(t *testing.T) {
		orig := flagVerbose
		defer func() { flagVerbose = orig }()

		flagVerbose = false
		assert.NotPanics(t, func() {
			setupLogging()
		})
	})

	t.Run("verbose true does not panic", func(t *testing.T) {
		orig := flagVerbose
		defer func() { flagVerbose = orig }()

		flagVerbose = true
		assert.NotPanics(t, func() {
			setupLogging()
		})
	})
}

func TestExecute(t *testing.T) {
	t.Run("no args returns success", func(t *testing.T) {
		code := execute()
		assert.Equal(t, 0, code)
	})
}
