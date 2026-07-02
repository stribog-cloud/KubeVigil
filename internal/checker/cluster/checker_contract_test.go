package cluster

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// Contract tests assert stable checker metadata (not vacuous NotEmpty) per audit F9.
func TestClusterCheckers_MetadataContract(t *testing.T) {
	tests := []struct {
		name     string
		checker  checker.Checker
		category checker.Category
		modes    []checker.ScanMode
	}{
		{
			name:     "admission-controllers",
			checker:  &AdmissionControllersChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive},
		},
		{
			name:     "api-server-anonymous",
			checker:  &APIServerAnonymousChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive},
		},
		{
			name:     "audit-logging",
			checker:  &AuditLoggingChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive},
		},
		{
			name:     "component-versions",
			checker:  &ComponentVersionsChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive},
		},
		{
			name:     "deprecated-api-usage",
			checker:  &DeprecatedAPIUsageChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest},
		},
		{
			name:     "etcd-encryption",
			checker:  &EtcdEncryptionChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive},
		},
		{
			name:     "kubelet-config",
			checker:  &KubeletConfigChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive},
		},
		{
			name:     "limit-range-missing",
			checker:  &LimitRangeMissingChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest},
		},
		{
			name:     "namespace-default-usage",
			checker:  &NamespaceDefaultUsageChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest},
		},
		{
			name:     "resource-quota-missing",
			checker:  &ResourceQuotaMissingChecker{},
			category: checker.CategoryClusterConfig,
			modes:    []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.name, tt.checker.Name())
			desc := tt.checker.Description()
			if assert.Greater(t, len(desc), 15, "description too short") {
				assert.Contains(t, desc, " ") // full sentence, not a stub
			}
			assert.Equal(t, []checker.Category{tt.category}, tt.checker.Categories())
			assert.Equal(t, tt.modes, tt.checker.SupportedModes())
			assert.NotEmpty(t, tt.checker.RequiredResources())
		})
	}
}
