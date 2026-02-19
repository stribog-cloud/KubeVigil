package fix

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestRiskLevelConstants(t *testing.T) {
	tests := []struct {
		name     string
		level    RiskLevel
		expected string
	}{
		{name: "safe", level: RiskLevelSafe, expected: "safe"},
		{name: "moderate", level: RiskLevelModerate, expected: "moderate"},
		{name: "aggressive", level: RiskLevelAggressive, expected: "aggressive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.level))
		})
	}
}

func TestParseRiskLevel(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  RiskLevel
		expectErr bool
	}{
		{name: "safe lowercase", input: "safe", expected: RiskLevelSafe},
		{name: "moderate lowercase", input: "moderate", expected: RiskLevelModerate},
		{name: "aggressive lowercase", input: "aggressive", expected: RiskLevelAggressive},
		{name: "safe uppercase", input: "SAFE", expected: RiskLevelSafe},
		{name: "moderate mixed case", input: "Moderate", expected: RiskLevelModerate},
		{name: "aggressive mixed case", input: "AGGRESSIVE", expected: RiskLevelAggressive},
		{name: "empty string", input: "", expectErr: true},
		{name: "invalid value", input: "extreme", expectErr: true},
		{name: "typo", input: "saf", expectErr: true},
		{name: "manual_only not a risk level", input: "manual_only", expectErr: true},
		{name: "likely_safe not a risk level", input: "likely_safe", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRiskLevel(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unknown risk level")
				assert.Contains(t, err.Error(), "valid: safe, moderate, aggressive")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

func TestAllowsSafety(t *testing.T) {
	tests := []struct {
		name     string
		risk     RiskLevel
		safety   checker.FixSafety
		expected bool
	}{
		// Safe risk level
		{name: "safe allows safe", risk: RiskLevelSafe, safety: checker.FixSafe, expected: true},
		{name: "safe denies likely_safe", risk: RiskLevelSafe, safety: checker.FixLikelySafe, expected: false},
		{name: "safe denies potentially_breaking", risk: RiskLevelSafe, safety: checker.FixPotentiallyBreaking, expected: false},
		{name: "safe denies manual_only", risk: RiskLevelSafe, safety: checker.FixManualOnly, expected: false},

		// Moderate risk level
		{name: "moderate allows safe", risk: RiskLevelModerate, safety: checker.FixSafe, expected: true},
		{name: "moderate allows likely_safe", risk: RiskLevelModerate, safety: checker.FixLikelySafe, expected: true},
		{name: "moderate denies potentially_breaking", risk: RiskLevelModerate, safety: checker.FixPotentiallyBreaking, expected: false},
		{name: "moderate denies manual_only", risk: RiskLevelModerate, safety: checker.FixManualOnly, expected: false},

		// Aggressive risk level
		{name: "aggressive allows safe", risk: RiskLevelAggressive, safety: checker.FixSafe, expected: true},
		{name: "aggressive allows likely_safe", risk: RiskLevelAggressive, safety: checker.FixLikelySafe, expected: true},
		{name: "aggressive allows potentially_breaking", risk: RiskLevelAggressive, safety: checker.FixPotentiallyBreaking, expected: true},
		{name: "aggressive denies manual_only", risk: RiskLevelAggressive, safety: checker.FixManualOnly, expected: false},

		// Unknown safety value
		{name: "safe denies unknown safety", risk: RiskLevelSafe, safety: checker.FixSafety("unknown"), expected: false},
		{name: "aggressive denies unknown safety", risk: RiskLevelAggressive, safety: checker.FixSafety("unknown"), expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.risk.AllowsSafety(tt.safety)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestResultJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		result Result
	}{
		{
			name: "applied fix with all fields",
			result: Result{
				FilePath:    "/manifests/deploy.yaml",
				Resource:    "nginx",
				Namespace:   "default",
				Kind:        "Deployment",
				CheckID:     "privileged",
				Safety:      checker.FixSafe,
				Description: "Set privileged to false",
				Impact:      "None",
				Applied:     true,
			},
		},
		{
			name: "skipped fix",
			result: Result{
				FilePath:    "/manifests/ds.yaml",
				Resource:    "calico-node",
				Namespace:   "kube-system",
				Kind:        "DaemonSet",
				CheckID:     "privileged",
				Safety:      checker.FixSafe,
				Description: "Set privileged to false",
				Applied:     false,
				SkipReason:  "system namespace",
			},
		},
		{
			name: "minimal fields",
			result: Result{
				FilePath: "/manifests/pod.yaml",
				Resource: "test",
				Kind:     "Pod",
				CheckID:  "read-only-root-fs",
				Safety:   checker.FixLikelySafe,
				Applied:  true,
			},
		},
		{
			name: "cluster-scoped resource no namespace",
			result: Result{
				FilePath:    "/manifests/cr.yaml",
				Resource:    "admin-binding",
				Kind:        "ClusterRoleBinding",
				CheckID:     "cluster-admin-binding",
				Safety:      checker.FixManualOnly,
				Description: "Review cluster-admin binding",
				Applied:     false,
				SkipReason:  "manual only",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.result)
			require.NoError(t, err)

			var got Result
			err = json.Unmarshal(data, &got)
			require.NoError(t, err)

			assert.Equal(t, tt.result, got)
		})
	}
}

func TestResultJSONOmitsEmptyFields(t *testing.T) {
	result := Result{
		FilePath: "/manifests/pod.yaml",
		Resource: "test",
		Kind:     "Pod",
		CheckID:  "privileged",
		Safety:   checker.FixSafe,
		Applied:  true,
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "namespace", "empty namespace should be omitted")
	assert.NotContains(t, raw, "impact", "empty impact should be omitted")
	assert.NotContains(t, raw, "skip_reason", "empty skip_reason should be omitted")
}

func TestSummaryJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		summary Summary
	}{
		{
			name: "successful fix run",
			summary: Summary{
				FilesScanned:  10,
				FilesModified: 3,
				FilesFailed:   0,
				TotalFindings: 5,
				Applied:       5,
				Skipped:       0,
				ByRisk: map[checker.FixSafety]int{
					checker.FixSafe:       3,
					checker.FixLikelySafe: 2,
				},
				SkipReasons: map[string]int{},
				Results: []Result{
					{
						FilePath: "/manifests/deploy.yaml",
						Resource: "nginx",
						Kind:     "Deployment",
						CheckID:  "privileged",
						Safety:   checker.FixSafe,
						Applied:  true,
					},
				},
				BackupDir: "/tmp/kubevigil-backup-20240101",
			},
		},
		{
			name: "partial failure with errors",
			summary: Summary{
				FilesScanned:  5,
				FilesModified: 2,
				FilesFailed:   1,
				TotalFindings: 4,
				Applied:       3,
				Skipped:       1,
				ByRisk: map[checker.FixSafety]int{
					checker.FixSafe: 3,
				},
				SkipReasons: map[string]int{
					"risk level too high": 1,
				},
				Results: []Result{
					{
						FilePath: "/manifests/deploy.yaml",
						Resource: "nginx",
						Kind:     "Deployment",
						CheckID:  "privileged",
						Safety:   checker.FixSafe,
						Applied:  true,
					},
				},
				Errors: []FileError{
					{
						FilePath: "/manifests/broken.yaml",
						Err:      "malformed YAML at line 15",
					},
				},
				BackupDir: "/tmp/kubevigil-backup-20240102",
			},
		},
		{
			name: "nothing to do",
			summary: Summary{
				FilesScanned:  3,
				FilesModified: 0,
				FilesFailed:   0,
				TotalFindings: 0,
				Applied:       0,
				Skipped:       0,
				ByRisk:        map[checker.FixSafety]int{},
				SkipReasons:   map[string]int{},
				Results:       []Result{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.summary)
			require.NoError(t, err)

			var got Summary
			err = json.Unmarshal(data, &got)
			require.NoError(t, err)

			assert.Equal(t, tt.summary, got)
		})
	}
}

func TestSummaryJSONOmitsEmptyErrors(t *testing.T) {
	summary := Summary{
		FilesScanned: 1,
		Results:      []Result{},
		ByRisk:       map[checker.FixSafety]int{},
		SkipReasons:  map[string]int{},
	}

	data, err := json.Marshal(summary)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "errors", "empty errors slice should be omitted")
	assert.NotContains(t, raw, "backup_dir", "empty backup_dir should be omitted")
}

func TestFileErrorJSONRoundTrip(t *testing.T) {
	fixErr := FileError{
		FilePath: "/manifests/broken.yaml",
		Err:      "permission denied",
	}

	data, err := json.Marshal(fixErr)
	require.NoError(t, err)

	var got FileError
	err = json.Unmarshal(data, &got)
	require.NoError(t, err)

	assert.Equal(t, fixErr, got)
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, RiskLevelSafe, cfg.RiskLevel, "default risk level should be safe")
	assert.Equal(t, 10, cfg.BulkThreshold, "default bulk threshold should be 10")
	assert.False(t, cfg.Apply, "apply should be false by default")
	assert.False(t, cfg.DryRun, "dry_run should be false by default")
	assert.False(t, cfg.Verify, "verify should be false by default")
	assert.False(t, cfg.Yes, "yes should be false by default")
	assert.False(t, cfg.AllowSystemNamespaces, "allow_system_namespaces should be false by default")
	assert.Empty(t, cfg.BackupDir, "backup_dir should be empty by default")
	assert.Nil(t, cfg.Checks, "checks should be nil by default")
	assert.Nil(t, cfg.Severities, "severities should be nil by default")
	assert.Nil(t, cfg.Namespaces, "namespaces should be nil by default")
	assert.Nil(t, cfg.ExcludeNamespaces, "exclude_namespaces should be nil by default")
	assert.Nil(t, cfg.AdditionalSystemNamespaces, "additional_system_namespaces should be nil by default")
}

func TestConfigJSONRoundTrip(t *testing.T) {
	cfg := Config{
		RiskLevel:                  RiskLevelAggressive,
		Apply:                      true,
		DryRun:                     false,
		Verify:                     true,
		Yes:                        true,
		AllowSystemNamespaces:      true,
		BulkThreshold:              20,
		BackupDir:                  "/tmp/kubevigil-backups/",
		Checks:                     []string{"privileged", "host-network"},
		Severities:                 []string{"Critical", "High"},
		Namespaces:                 []string{"default", "production"},
		ExcludeNamespaces:          []string{"kube-system"},
		AdditionalSystemNamespaces: []string{"custom-infra", "vault"},
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var got Config
	err = json.Unmarshal(data, &got)
	require.NoError(t, err)

	assert.Equal(t, cfg, got)
}

func TestExitCodeConstants(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected int
	}{
		{name: "success", code: ExitFixSuccess, expected: 0},
		{name: "verify failed", code: ExitFixVerifyFailed, expected: 1},
		{name: "error", code: ExitFixError, expected: 2},
		{name: "config error", code: ExitFixConfigError, expected: 3},
		{name: "nothing to do", code: ExitFixNothingToDo, expected: 4},
		{name: "partial success", code: ExitFixPartialSuccess, expected: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code)
		})
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	codes := []int{
		ExitFixSuccess,
		ExitFixVerifyFailed,
		ExitFixError,
		ExitFixConfigError,
		ExitFixNothingToDo,
		ExitFixPartialSuccess,
	}

	seen := make(map[int]bool)
	for _, code := range codes {
		assert.False(t, seen[code], "duplicate exit code: %d", code)
		seen[code] = true
	}
}

func TestAllowsSafetyManualOnlyNeverAllowed(t *testing.T) {
	// Manual-only should never be allowed regardless of risk level.
	levels := []RiskLevel{RiskLevelSafe, RiskLevelModerate, RiskLevelAggressive}
	for _, level := range levels {
		assert.False(t, level.AllowsSafety(checker.FixManualOnly),
			"manual_only should never be allowed at risk level %s", level)
	}
}

func TestAllowsSafetySafeAlwaysAllowed(t *testing.T) {
	// Safe fixes should always be allowed regardless of risk level.
	levels := []RiskLevel{RiskLevelSafe, RiskLevelModerate, RiskLevelAggressive}
	for _, level := range levels {
		assert.True(t, level.AllowsSafety(checker.FixSafe),
			"safe should always be allowed at risk level %s", level)
	}
}

func TestFindingFingerprint_Deterministic(t *testing.T) {
	finding := &checker.Finding{
		Checker:   "privileged",
		Kind:      "Deployment",
		Resource:  "web-app",
		Namespace: "production",
		FieldPath: ".spec.containers[0].securityContext.privileged",
	}

	fp1 := FindingFingerprint(finding)
	fp2 := FindingFingerprint(finding)

	assert.Equal(t, fp1, fp2, "fingerprint should be deterministic")
	assert.Len(t, fp1, 12, "fingerprint should be 12 hex chars")
}

func TestFindingFingerprint_UniqueForDifferentFindings(t *testing.T) {
	f1 := &checker.Finding{
		Checker:   "privileged",
		Kind:      "Deployment",
		Resource:  "web-app",
		Namespace: "production",
		FieldPath: ".spec.containers[0].securityContext.privileged",
	}
	f2 := &checker.Finding{
		Checker:   "privilege-escalation",
		Kind:      "Deployment",
		Resource:  "web-app",
		Namespace: "production",
		FieldPath: ".spec.containers[0].securityContext.allowPrivilegeEscalation",
	}

	fp1 := FindingFingerprint(f1)
	fp2 := FindingFingerprint(f2)

	assert.NotEqual(t, fp1, fp2, "different findings should have different fingerprints")
}

func TestFindingFingerprint_DifferentNamespace(t *testing.T) {
	f1 := &checker.Finding{
		Checker:   "privileged",
		Kind:      "Deployment",
		Resource:  "web-app",
		Namespace: "production",
	}
	f2 := &checker.Finding{
		Checker:   "privileged",
		Kind:      "Deployment",
		Resource:  "web-app",
		Namespace: "staging",
	}

	assert.NotEqual(t, FindingFingerprint(f1), FindingFingerprint(f2),
		"same check+resource in different namespaces should have different fingerprints")
}

func TestRiskLevelsAreAdditive(t *testing.T) {
	// Moderate includes everything safe includes.
	safeSafeties := []checker.FixSafety{checker.FixSafe}
	for _, safety := range safeSafeties {
		if RiskLevelSafe.AllowsSafety(safety) {
			assert.True(t, RiskLevelModerate.AllowsSafety(safety),
				"moderate should include everything safe allows: %s", safety)
		}
	}

	// Aggressive includes everything moderate includes.
	moderateSafeties := []checker.FixSafety{checker.FixSafe, checker.FixLikelySafe}
	for _, safety := range moderateSafeties {
		if RiskLevelModerate.AllowsSafety(safety) {
			assert.True(t, RiskLevelAggressive.AllowsSafety(safety),
				"aggressive should include everything moderate allows: %s", safety)
		}
	}
}
