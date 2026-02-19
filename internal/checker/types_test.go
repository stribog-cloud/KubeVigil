package checker

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
	}{
		{name: "Info", severity: SeverityInfo, want: "Info"},
		{name: "Low", severity: SeverityLow, want: "Low"},
		{name: "Medium", severity: SeverityMedium, want: "Medium"},
		{name: "High", severity: SeverityHigh, want: "High"},
		{name: "Critical", severity: SeverityCritical, want: "Critical"},
		{name: "Unknown", severity: Severity(99), want: "Severity(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.severity.String())
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Severity
		wantErr bool
	}{
		// All valid lowercase inputs.
		{name: "info", input: "info", want: SeverityInfo},
		{name: "low", input: "low", want: SeverityLow},
		{name: "medium", input: "medium", want: SeverityMedium},
		{name: "high", input: "high", want: SeverityHigh},
		{name: "critical", input: "critical", want: SeverityCritical},

		// Case insensitivity.
		{name: "INFO uppercase", input: "INFO", want: SeverityInfo},
		{name: "Critical mixed", input: "Critical", want: SeverityCritical},
		{name: "HIGH uppercase", input: "HIGH", want: SeverityHigh},
		{name: "Low capitalized", input: "Low", want: SeverityLow},
		{name: "mEdIuM mixed", input: "mEdIuM", want: SeverityMedium},

		// Invalid.
		{name: "unknown", input: "unknown", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "number", input: "42", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSeverity(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSeverity_JSON_Roundtrip(t *testing.T) {
	// A wrapper struct so we marshal an object, not a bare string.
	type wrapper struct {
		S Severity `json:"severity"`
	}

	allSeverities := []struct {
		severity Severity
		jsonStr  string
	}{
		{SeverityInfo, `"Info"`},
		{SeverityLow, `"Low"`},
		{SeverityMedium, `"Medium"`},
		{SeverityHigh, `"High"`},
		{SeverityCritical, `"Critical"`},
	}

	for _, tc := range allSeverities {
		t.Run("Marshal_"+tc.severity.String(), func(t *testing.T) {
			data, err := json.Marshal(tc.severity)
			require.NoError(t, err)
			assert.Equal(t, tc.jsonStr, string(data))
		})

		t.Run("Roundtrip_"+tc.severity.String(), func(t *testing.T) {
			w := wrapper{S: tc.severity}
			data, err := json.Marshal(w)
			require.NoError(t, err)

			var got wrapper
			err = json.Unmarshal(data, &got)
			require.NoError(t, err)
			assert.Equal(t, tc.severity, got.S)
		})
	}

	t.Run("Unmarshal_invalid_string", func(t *testing.T) {
		var s Severity
		err := json.Unmarshal([]byte(`"bogus"`), &s)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown severity")
	})

	t.Run("Unmarshal_non_string", func(t *testing.T) {
		var s Severity
		err := json.Unmarshal([]byte(`42`), &s)
		assert.Error(t, err)
	})
}

func TestSeverity_YAML_Roundtrip(t *testing.T) {
	type wrapper struct {
		S Severity `yaml:"severity"`
	}

	allSeverities := []struct {
		severity Severity
		yamlStr  string
	}{
		{SeverityInfo, "Info"},
		{SeverityLow, "Low"},
		{SeverityMedium, "Medium"},
		{SeverityHigh, "High"},
		{SeverityCritical, "Critical"},
	}

	for _, tc := range allSeverities {
		t.Run("MarshalYAML_"+tc.severity.String(), func(t *testing.T) {
			val, err := tc.severity.MarshalYAML()
			require.NoError(t, err)
			assert.Equal(t, tc.yamlStr, val)
		})

		t.Run("Roundtrip_"+tc.severity.String(), func(t *testing.T) {
			w := wrapper{S: tc.severity}
			data, err := yaml.Marshal(w)
			require.NoError(t, err)

			var got wrapper
			err = yaml.Unmarshal(data, &got)
			require.NoError(t, err)
			assert.Equal(t, tc.severity, got.S)
		})
	}

	t.Run("UnmarshalYAML_invalid_string", func(t *testing.T) {
		var w wrapper
		err := yaml.Unmarshal([]byte("severity: bogus\n"), &w)
		assert.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// ScanMode
// ---------------------------------------------------------------------------

func TestScanMode_String(t *testing.T) {
	tests := []struct {
		name string
		mode ScanMode
		want string
	}{
		{name: "Live", mode: ScanModeLive, want: "Live"},
		{name: "Manifest", mode: ScanModeManifest, want: "Manifest"},
		{name: "Unknown", mode: ScanMode(99), want: "ScanMode(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.mode.String())
		})
	}
}

func TestParseScanMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ScanMode
		wantErr bool
	}{
		// Valid lowercase.
		{name: "live", input: "live", want: ScanModeLive},
		{name: "manifest", input: "manifest", want: ScanModeManifest},

		// Case insensitivity.
		{name: "Live capitalized", input: "Live", want: ScanModeLive},
		{name: "MANIFEST uppercase", input: "MANIFEST", want: ScanModeManifest},
		{name: "LiVe mixed", input: "LiVe", want: ScanModeLive},

		// Invalid.
		{name: "unknown", input: "unknown", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseScanMode(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unknown scan mode")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestScanMode_JSON_Roundtrip(t *testing.T) {
	type wrapper struct {
		M ScanMode `json:"mode"`
	}

	allModes := []struct {
		mode    ScanMode
		jsonStr string
	}{
		{ScanModeLive, `"Live"`},
		{ScanModeManifest, `"Manifest"`},
	}

	for _, tc := range allModes {
		t.Run("Marshal_"+tc.mode.String(), func(t *testing.T) {
			data, err := json.Marshal(tc.mode)
			require.NoError(t, err)
			assert.Equal(t, tc.jsonStr, string(data))
		})

		t.Run("Roundtrip_"+tc.mode.String(), func(t *testing.T) {
			w := wrapper{M: tc.mode}
			data, err := json.Marshal(w)
			require.NoError(t, err)

			var got wrapper
			err = json.Unmarshal(data, &got)
			require.NoError(t, err)
			assert.Equal(t, tc.mode, got.M)
		})
	}

	t.Run("Unmarshal_invalid_string", func(t *testing.T) {
		var m ScanMode
		err := json.Unmarshal([]byte(`"bogus"`), &m)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown scan mode")
	})

	t.Run("Unmarshal_non_string", func(t *testing.T) {
		var m ScanMode
		err := json.Unmarshal([]byte(`99`), &m)
		assert.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

func TestCategory_String(t *testing.T) {
	tests := []struct {
		name     string
		category Category
		want     string
	}{
		{name: "Workload", category: CategoryWorkload, want: "Workload"},
		{name: "Lifecycle", category: CategoryLifecycle, want: "Lifecycle"},
		{name: "Image", category: CategoryImage, want: "Image"},
		{name: "RBAC", category: CategoryRBAC, want: "RBAC"},
		{name: "Secrets", category: CategorySecrets, want: "Secrets"},
		{name: "Network", category: CategoryNetwork, want: "Network"},
		{name: "PSS", category: CategoryPSS, want: "PodSecurityStandards"},
		{name: "Storage", category: CategoryStorage, want: "Storage"},
		{name: "Scheduling", category: CategoryScheduling, want: "Scheduling"},
		{name: "ClusterConfig", category: CategoryClusterConfig, want: "ClusterConfig"},
		{name: "SupplyChain", category: CategorySupplyChain, want: "SupplyChain"},
		{name: "CRD", category: CategoryCRD, want: "CRD"},
		{name: "CloudProvider", category: CategoryCloudProvider, want: "CloudProvider"},
		{name: "Unknown", category: Category(99), want: "Category(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.category.String())
		})
	}
}

func TestCategoryDisplayName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// All 13 known mappings.
		{name: "Workload", input: "Workload", want: "Workload"},
		{name: "Lifecycle", input: "Lifecycle", want: "Lifecycle"},
		{name: "Image", input: "Image", want: "Image"},
		{name: "RBAC", input: "RBAC", want: "RBAC"},
		{name: "Secrets", input: "Secrets", want: "Secrets"},
		{name: "Network", input: "Network", want: "Network"},
		{name: "PodSecurityStandards", input: "PodSecurityStandards", want: "Pod Security Standards"},
		{name: "Storage", input: "Storage", want: "Storage"},
		{name: "Scheduling", input: "Scheduling", want: "Scheduling"},
		{name: "ClusterConfig", input: "ClusterConfig", want: "Cluster Configuration"},
		{name: "SupplyChain", input: "SupplyChain", want: "Supply Chain"},
		{name: "CRD", input: "CRD", want: "CRD"},
		{name: "CloudProvider", input: "CloudProvider", want: "Cloud Provider"},

		// Unknown category is returned unchanged (passthrough).
		{name: "UnknownCategory", input: "UnknownCategory", want: "UnknownCategory"},
		{name: "empty string", input: "", want: ""},
		{name: "arbitrary string", input: "FooBar", want: "FooBar"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, CategoryDisplayName(tc.input))
		})
	}
}

// ---------------------------------------------------------------------------
// Iota value sanity checks
// ---------------------------------------------------------------------------

func TestSeverity_IotaValues(t *testing.T) {
	// Verify the iota ordering so that comparisons like s > SeverityMedium work.
	assert.Equal(t, Severity(0), SeverityInfo)
	assert.Equal(t, Severity(1), SeverityLow)
	assert.Equal(t, Severity(2), SeverityMedium)
	assert.Equal(t, Severity(3), SeverityHigh)
	assert.Equal(t, Severity(4), SeverityCritical)

	// Ordering: Info < Low < Medium < High < Critical.
	assert.True(t, SeverityInfo < SeverityLow)
	assert.True(t, SeverityLow < SeverityMedium)
	assert.True(t, SeverityMedium < SeverityHigh)
	assert.True(t, SeverityHigh < SeverityCritical)
}

func TestScanMode_IotaValues(t *testing.T) {
	assert.Equal(t, ScanMode(0), ScanModeLive)
	assert.Equal(t, ScanMode(1), ScanModeManifest)
}

func TestCategory_IotaValues(t *testing.T) {
	assert.Equal(t, Category(0), CategoryWorkload)
	assert.Equal(t, Category(1), CategoryLifecycle)
	assert.Equal(t, Category(2), CategoryImage)
	assert.Equal(t, Category(3), CategoryRBAC)
	assert.Equal(t, Category(4), CategorySecrets)
	assert.Equal(t, Category(5), CategoryNetwork)
	assert.Equal(t, Category(6), CategoryPSS)
	assert.Equal(t, Category(7), CategoryStorage)
	assert.Equal(t, Category(8), CategoryScheduling)
	assert.Equal(t, Category(9), CategoryClusterConfig)
	assert.Equal(t, Category(10), CategorySupplyChain)
	assert.Equal(t, Category(11), CategoryCRD)
	assert.Equal(t, Category(12), CategoryCloudProvider)
}
