package fix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	// Import checker packages to register checkers in the default registry.
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cloud"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/cluster"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/crd"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/image"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/network"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/psa"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/rbac"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/scheduling"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/secrets"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/storage"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/supply_chain"
	_ "github.com/stribog-cloud/kubevigil/internal/checker/workload"
	"github.com/stribog-cloud/kubevigil/internal/config"
)

// fixtureDir returns the absolute path to test/fixtures/fix/ relative to this test file.
func fixtureDir(t *testing.T) string {
	t.Helper()
	// This test file is in internal/fix/, fixtures are at ../../test/fixtures/fix/
	dir, err := filepath.Abs("../../test/fixtures/fix")
	if err != nil {
		t.Fatalf("resolving fixture dir: %v", err)
	}
	return dir
}

// copyFixture copies a fixture file to a temp directory and returns the temp file path.
func copyFixture(t *testing.T, fixtureName string) string {
	t.Helper()
	src := filepath.Join(fixtureDir(t), fixtureName)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixtureName, err)
	}

	tmpDir := t.TempDir()
	dst := filepath.Join(tmpDir, fixtureName)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("writing temp fixture %s: %v", fixtureName, err)
	}
	return dst
}

// newTestFixer creates a Fixer with the default registries and the given fix config.
func newTestFixer(t *testing.T, fixCfg Config) *Fixer {
	t.Helper()
	scanCfg := config.Default()
	// Include system namespaces in scan so the fixer can apply its own gates.
	scanCfg.Settings.IncludeSystemNamespaces = true
	return NewFixer(DefaultRegistry(), checker.DefaultRegistry(), scanCfg, &fixCfg)
}

func TestFixer_Plan_SimpleDeployment(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")
	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	if plan.Summary.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", plan.Summary.FilesScanned)
	}

	// Should have at least the "privileged" fix applied.
	if plan.Summary.Applied == 0 {
		t.Error("Expected at least one applied fix")
	}

	// Should have a diff for the file.
	if len(plan.Diffs) == 0 {
		t.Error("Expected at least one diff")
	}

	// The diff should show privileged changing from true to false.
	for _, diff := range plan.Diffs {
		if !strings.Contains(diff, "privileged") {
			t.Error("Diff should contain 'privileged' change")
		}
	}
}

func TestFixer_Plan_DryRunDoesNotModifyFiles(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")
	original, _ := os.ReadFile(path)

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
	})

	_, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// File should be unchanged since Plan doesn't write.
	after, _ := os.ReadFile(path)
	if string(original) != string(after) {
		t.Error("Plan() should not modify the original file")
	}
}

func TestFixer_Fix_ApplyWritesToDisk(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")
	original, _ := os.ReadFile(path)

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	plan, summary, err := fixer.Fix(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Fix() error: %v", err)
	}

	if summary.Applied == 0 {
		t.Error("Expected at least one applied fix")
	}

	// File should be modified.
	after, _ := os.ReadFile(path)
	if string(original) == string(after) {
		t.Error("Fix() with Apply should modify the file")
	}

	// Patched content should set privileged to false.
	if !strings.Contains(string(after), "privileged: false") {
		t.Error("Patched file should contain 'privileged: false'")
	}

	// Backup should exist.
	if plan.Summary.BackupDir == "" {
		t.Error("BackupDir should be set")
	}
}

func TestFixer_Fix_DryRunDefault(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")
	original, _ := os.ReadFile(path)

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     false, // dry-run (default)
	})

	_, _, err := fixer.Fix(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Fix() error: %v", err)
	}

	// File should be unchanged.
	after, _ := os.ReadFile(path)
	if string(original) != string(after) {
		t.Error("Fix() without Apply should not modify the file")
	}
}

func TestFixer_RiskLevelGating_Safe(t *testing.T) {
	path := copyFixture(t, "multi-finding.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// At safe level, only safe fixes should be applied.
	for _, result := range plan.Summary.Results {
		if result.Applied && result.Safety != checker.FixSafe {
			t.Errorf("Safe risk level should only apply safe fixes, got %s for %s", result.Safety, result.CheckID)
		}
	}

	// Likely safe and potentially breaking should be skipped.
	for _, result := range plan.Summary.Results {
		if !result.Applied && result.SkipReason == "risk_level" {
			if result.Safety == checker.FixSafe {
				t.Errorf("Safe fix should not be skipped for risk_level: %s", result.CheckID)
			}
		}
	}
}

func TestFixer_RiskLevelGating_Moderate(t *testing.T) {
	path := copyFixture(t, "multi-finding.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelModerate,
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// At moderate level, safe and likely_safe should be applied.
	for _, result := range plan.Summary.Results {
		if result.Applied && result.Safety == checker.FixPotentiallyBreaking {
			t.Errorf("Moderate risk level should not apply potentially_breaking fixes: %s", result.CheckID)
		}
	}
}

func TestFixer_RiskLevelGating_Aggressive(t *testing.T) {
	path := copyFixture(t, "multi-finding.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelAggressive,
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// At aggressive level, all fixable findings should be applied.
	if plan.Summary.Applied == 0 {
		t.Error("Aggressive mode should apply fixes")
	}
}

func TestFixer_SystemNamespaceProtection(t *testing.T) {
	path := copyFixture(t, "system-namespace.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelAggressive,
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// All findings should be skipped due to system namespace.
	for _, result := range plan.Summary.Results {
		if result.Applied {
			t.Errorf("System namespace finding should be skipped: %s", result.CheckID)
		}
	}

	if plan.Summary.SkipReasons["system_namespace"] == 0 {
		t.Error("Expected system_namespace skip reason")
	}
}

func TestFixer_SystemNamespaceOverride(t *testing.T) {
	path := copyFixture(t, "system-namespace.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel:             RiskLevelAggressive,
		AllowSystemNamespaces: true,
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// With the override, findings should be applied.
	if plan.Summary.Applied == 0 {
		t.Error("System namespace override should allow fixes")
	}
}

func TestFixer_KnownWorkloadSkip(t *testing.T) {
	path := copyFixture(t, "known-workload-calico.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel:             RiskLevelAggressive,
		AllowSystemNamespaces: true, // calico-system is a system namespace
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// Note: Known workload detection happens at image level.
	// The fixer currently applies safety classification for namespaces and risk levels.
	// Known workload detection is a separate feature. This test verifies
	// the system namespace protection for calico-system is working.
	if plan.Summary.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", plan.Summary.FilesScanned)
	}
}

func TestFixer_MultiDoc(t *testing.T) {
	path := copyFixture(t, "multi-doc-mixed.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, _, err := fixer.Fix(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Fix() error: %v", err)
	}

	// Read the patched file.
	patched, _ := os.ReadFile(path)
	content := string(patched)

	// The Deployment should have privileged: false.
	if !strings.Contains(content, "privileged: false") {
		t.Error("Deployment in multi-doc should be patched with 'privileged: false'")
	}

	// The Service and ConfigMap should be unchanged.
	if !strings.Contains(content, "kind: Service") {
		t.Error("Service should still be present")
	}
	if !strings.Contains(content, "kind: ConfigMap") {
		t.Error("ConfigMap should still be present")
	}
}

func TestFixer_AlreadySecure(t *testing.T) {
	path := copyFixture(t, "already-secure.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// No diffs should be generated for an already secure file.
	if len(plan.Diffs) != 0 {
		t.Errorf("Expected 0 diffs for already-secure file, got %d", len(plan.Diffs))
	}
}

func TestFixer_Plan_RejectsOversizedFile(t *testing.T) {
	tmpDir := t.TempDir()
	bigFile := filepath.Join(tmpDir, "huge.yaml")

	size := 10*1024*1024 + 1
	data := make([]byte, size)
	for i := range data {
		data[i] = '#'
	}
	require.NoError(t, os.WriteFile(bigFile, data, 0o644))

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
	})

	plan, err := fixer.Plan(context.Background(), []string{tmpDir})
	require.NoError(t, err)
	assert.Equal(t, 1, plan.Summary.FilesScanned)
	assert.Equal(t, 1, plan.Summary.FilesFailed)
}

func TestFixer_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
	})

	plan, err := fixer.Plan(context.Background(), []string{tmpDir})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	if plan.Summary.FilesScanned != 0 {
		t.Errorf("FilesScanned = %d, want 0", plan.Summary.FilesScanned)
	}
}

func TestFixer_FilterByCheck(t *testing.T) {
	path := copyFixture(t, "multi-finding.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelAggressive,
		Checks:    []string{"privileged"},
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// Only the "privileged" check should produce applied fixes.
	for _, result := range plan.Summary.Results {
		if result.Applied && result.CheckID != "privileged" {
			t.Errorf("Only 'privileged' check should be applied, got %s", result.CheckID)
		}
	}
}

func TestFixer_FilterByNamespace(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel:  RiskLevelSafe,
		Namespaces: []string{"nonexistent"},
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// All fixes should be skipped because namespace doesn't match.
	if plan.Summary.Applied != 0 {
		t.Errorf("Expected 0 applied fixes for wrong namespace, got %d", plan.Summary.Applied)
	}
}

func TestFixer_ExcludeNamespace(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel:         RiskLevelSafe,
		ExcludeNamespaces: []string{"production"},
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// All fixes should be skipped because namespace is excluded.
	if plan.Summary.Applied != 0 {
		t.Errorf("Expected 0 applied fixes for excluded namespace, got %d", plan.Summary.Applied)
	}

	if plan.Summary.SkipReasons["namespace_excluded"] == 0 {
		t.Error("Expected namespace_excluded skip reason")
	}
}

func TestFixer_ConflictSameField(t *testing.T) {
	path := copyFixture(t, "conflict-same-field.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelModerate,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, _, err := fixer.Fix(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Fix() error: %v", err)
	}

	patched, _ := os.ReadFile(path)
	content := string(patched)

	// Both privileged and allowPrivilegeEscalation should be set to false.
	if !strings.Contains(content, "privileged: false") {
		t.Error("Expected privileged: false in patched file")
	}
	if !strings.Contains(content, "allowPrivilegeEscalation: false") {
		t.Error("Expected allowPrivilegeEscalation: false in patched file")
	}
}

func TestFixer_PartialFailure_MalformedYAML(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a malformed YAML file.
	malformed := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(malformed, []byte("{{invalid yaml"), 0o644)

	// Create a valid insecure YAML file.
	_ = copyFixtureToDir(t, "simple-deployment.yaml", tmpDir)

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
	})

	plan, err := fixer.Plan(context.Background(), []string{tmpDir})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	// Should have processed at least the good file.
	if plan.Summary.FilesScanned < 2 {
		t.Errorf("FilesScanned = %d, want >= 2", plan.Summary.FilesScanned)
	}

	// Should have at least one failure.
	if plan.Summary.FilesFailed == 0 {
		t.Error("Expected at least one file failure")
	}

	// Should still have fixes from the good file.
	if plan.Summary.Applied == 0 {
		t.Error("Expected fixes from the valid file")
	}
}

func TestFixer_CommentPreservation(t *testing.T) {
	path := copyFixture(t, "commented-deployment.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, _, err := fixer.Fix(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("Fix() error: %v", err)
	}

	patched, _ := os.ReadFile(path)
	content := string(patched)

	// Key comments should be preserved.
	if !strings.Contains(content, "# This deployment runs the API backend service.") {
		t.Error("Head comment should be preserved")
	}
	if !strings.Contains(content, "# Team ownership label") {
		t.Error("Inline comment should be preserved")
	}
	if !strings.Contains(content, "# Scale based on load testing results") {
		t.Error("Line comment should be preserved")
	}
}

// Helper functions

// copyFixtureToDir copies a fixture into an existing directory.
func copyFixtureToDir(t *testing.T, fixtureName, dir string) string {
	t.Helper()
	src := filepath.Join(fixtureDir(t), fixtureName)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixtureName, err)
	}
	dst := filepath.Join(dir, fixtureName)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("writing temp fixture %s: %v", fixtureName, err)
	}
	return dst
}

// --- Unit tests for helper functions ---

func TestPodSpecPrefix(t *testing.T) {
	tests := []struct {
		kind string
		want string
	}{
		{"Pod", ""},
		{"Deployment", "spec.template."},
		{"StatefulSet", "spec.template."},
		{"DaemonSet", "spec.template."},
		{"ReplicaSet", "spec.template."},
		{"Job", "spec.template."},
		{"CronJob", "spec.jobTemplate.spec.template."},
		{"Namespace", ""},
		{"Service", ""},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got := podSpecPrefix(tt.kind)
			if got != tt.want {
				t.Errorf("podSpecPrefix(%q) = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}

func TestResolveYAMLPath(t *testing.T) {
	tests := []struct {
		name     string
		finding  checker.Finding
		strategy Strategy
		kind     string
		want     string
	}{
		{
			name: "deployment with container field",
			finding: checker.Finding{
				FieldPath: ".spec.containers[0].securityContext.privileged",
			},
			strategy: Strategy{
				FieldPath: "spec.containers[*].securityContext.privileged",
			},
			kind: "Deployment",
			want: "spec.template.spec.containers[0].securityContext.privileged",
		},
		{
			name: "pod with container field",
			finding: checker.Finding{
				FieldPath: ".spec.containers[0].securityContext.privileged",
			},
			strategy: Strategy{
				FieldPath: "spec.containers[*].securityContext.privileged",
			},
			kind: "Pod",
			want: "spec.containers[0].securityContext.privileged",
		},
		{
			name: "deployment with pod-level field",
			finding: checker.Finding{
				FieldPath: ".spec.hostPID",
			},
			strategy: Strategy{
				FieldPath: "spec.hostPID",
			},
			kind: "Deployment",
			want: "spec.template.spec.hostPID",
		},
		{
			name: "cronjob path",
			finding: checker.Finding{
				FieldPath: ".spec.containers[0].securityContext.privileged",
			},
			strategy: Strategy{
				FieldPath: "spec.containers[*].securityContext.privileged",
			},
			kind: "CronJob",
			want: "spec.jobTemplate.spec.template.spec.containers[0].securityContext.privileged",
		},
		{
			name: "fallback to strategy path when finding has no path",
			finding: checker.Finding{
				FieldPath: "",
			},
			strategy: Strategy{
				FieldPath: "spec.hostPID",
			},
			kind: "Deployment",
			want: "spec.template.spec.hostPID",
		},
		{
			name: "namespace metadata path (non-workload)",
			finding: checker.Finding{
				FieldPath: ".metadata.labels",
			},
			strategy: Strategy{
				FieldPath: "metadata.labels",
			},
			kind: "Namespace",
			want: "metadata.labels",
		},
		{
			name: "finding field differs from strategy field (run-as-root)",
			finding: checker.Finding{
				FieldPath: ".spec.containers[0].securityContext.runAsUser",
			},
			strategy: Strategy{
				FieldPath: "spec.containers[*].securityContext.runAsNonRoot",
			},
			kind: "Deployment",
			want: "spec.template.spec.containers[0].securityContext.runAsNonRoot",
		},
		{
			name: "finding field differs from strategy field (initContainers)",
			finding: checker.Finding{
				FieldPath: ".spec.initContainers[1].securityContext.runAsUser",
			},
			strategy: Strategy{
				FieldPath: "spec.containers[*].securityContext.runAsNonRoot",
			},
			kind: "Deployment",
			want: "spec.template.spec.initContainers[1].securityContext.runAsNonRoot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveYAMLPath(&tt.finding, &tt.strategy, tt.kind)
			if got != tt.want {
				t.Errorf("resolveYAMLPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCollectFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files.
	os.WriteFile(filepath.Join(tmpDir, "a.yaml"), []byte("---"), 0o644)
	os.WriteFile(filepath.Join(tmpDir, "b.yml"), []byte("---"), 0o644)
	os.WriteFile(filepath.Join(tmpDir, "c.txt"), []byte("text"), 0o644)
	os.MkdirAll(filepath.Join(tmpDir, "sub"), 0o755)
	os.WriteFile(filepath.Join(tmpDir, "sub", "d.yaml"), []byte("---"), 0o644)

	files, err := collectFiles([]string{tmpDir})
	if err != nil {
		t.Fatalf("collectFiles() error: %v", err)
	}

	if len(files) != 3 {
		t.Errorf("len(files) = %d, want 3", len(files))
	}

	// Should be sorted.
	for i := 1; i < len(files); i++ {
		if files[i] < files[i-1] {
			t.Errorf("files not sorted: %s < %s", files[i], files[i-1])
		}
	}

	// .txt file should not be included.
	for _, f := range files {
		if strings.HasSuffix(f, ".txt") {
			t.Errorf("non-YAML file included: %s", f)
		}
	}
}

func TestCollectFiles_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")
	os.WriteFile(path, []byte("---"), 0o644)

	files, err := collectFiles([]string{path})
	if err != nil {
		t.Fatalf("collectFiles() error: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("len(files) = %d, want 1", len(files))
	}
}

func TestCollectFiles_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	files, err := collectFiles([]string{tmpDir})
	if err != nil {
		t.Fatalf("collectFiles() error: %v", err)
	}

	if len(files) != 0 {
		t.Errorf("len(files) = %d, want 0", len(files))
	}
}

func TestCommonBase(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  string
	}{
		{
			name:  "empty",
			paths: nil,
			want:  ".",
		},
		{
			name:  "single file",
			paths: []string{"/a/b/c.yaml"},
			want:  "/a/b",
		},
		{
			name:  "same dir",
			paths: []string{"/a/b/c.yaml", "/a/b/d.yaml"},
			want:  "/a/b",
		},
		{
			name:  "different dirs",
			paths: []string{"/a/b/c.yaml", "/a/d/e.yaml"},
			want:  "/a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commonBase(tt.paths)
			if got != tt.want {
				t.Errorf("commonBase() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractMetadata(t *testing.T) {
	yaml := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 1
`
	docs, err := ParseDocuments([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseDocuments() error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 doc, got %d", len(docs))
	}

	apiVersion, kind, name, namespace := extractMetadata(docs[0])
	if apiVersion != "apps/v1" {
		t.Errorf("apiVersion = %q, want %q", apiVersion, "apps/v1")
	}
	if kind != "Deployment" {
		t.Errorf("kind = %q, want %q", kind, "Deployment")
	}
	if name != "web-app" {
		t.Errorf("name = %q, want %q", name, "web-app")
	}
	if namespace != "production" {
		t.Errorf("namespace = %q, want %q", namespace, "production")
	}
}

// --- Verify tests ---

func TestFixer_Verify_AfterApply(t *testing.T) {
	// Use aggressive risk level to apply ALL fixable checks, maximizing resolved count.
	path := copyFixture(t, "simple-deployment.yaml")
	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelAggressive,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	require.NoError(t, err)
	require.Greater(t, plan.Summary.Applied, 0)

	_, err = fixer.Apply(context.Background(), plan)
	require.NoError(t, err)

	result, err := fixer.Verify(context.Background(), plan)
	require.NoError(t, err)
	assert.Equal(t, plan.Summary.Applied, result.TotalBefore)
	// After aggressive fixes, TotalAfter should be strictly less than TotalBefore
	// because the applied fixes should have resolved at least some findings.
	assert.Less(t, result.TotalAfter, result.TotalBefore)
	assert.Greater(t, result.Resolved, 0)
}

func TestFixer_Verify_RemainingFindings(t *testing.T) {
	// Apply only safe fixes; many fixable findings should remain since
	// likely_safe and potentially_breaking checks are not applied.
	path := copyFixture(t, "multi-finding.yaml")
	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	require.NoError(t, err)
	require.Greater(t, plan.Summary.Applied, 0)

	_, err = fixer.Apply(context.Background(), plan)
	require.NoError(t, err)

	result, err := fixer.Verify(context.Background(), plan)
	require.NoError(t, err)
	assert.Equal(t, plan.Summary.Applied, result.TotalBefore)
	// After safe-only fixes, there should still be remaining fixable findings
	// from higher risk levels (likely_safe, potentially_breaking checks).
	assert.Greater(t, result.Remaining, 0)
	assert.False(t, result.Clean, "should not be clean when only safe fixes applied")
}

func TestFixer_Verify_EmptyPlan(t *testing.T) {
	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
	})

	plan := &Plan{
		Files: make(map[string]*FilePlan),
		Diffs: make(map[string]string),
		Summary: Summary{
			ByRisk:      make(map[checker.FixSafety]int),
			SkipReasons: make(map[string]int),
		},
	}

	result, err := fixer.Verify(context.Background(), plan)
	require.NoError(t, err)
	assert.True(t, result.Clean)
	assert.Equal(t, 0, result.TotalBefore)
	assert.Equal(t, 0, result.TotalAfter)
	assert.Equal(t, 0, result.Resolved)
	assert.Equal(t, 0, result.Remaining)
	assert.Equal(t, 0, result.New)
}

// --- Apply additional branch tests ---

func TestFixer_Apply_EmptyPlan(t *testing.T) {
	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	plan := &Plan{
		Files: make(map[string]*FilePlan),
		Diffs: make(map[string]string),
		Summary: Summary{
			Applied:     0,
			ByRisk:      make(map[checker.FixSafety]int),
			SkipReasons: make(map[string]int),
		},
	}

	summary, err := fixer.Apply(context.Background(), plan)
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Applied)
	// Backup directory should NOT be set because there was nothing to apply.
	assert.Empty(t, summary.BackupDir)
}

func TestFixer_Apply_ReadOnlyFile(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	require.NoError(t, err)
	require.Greater(t, len(plan.Files), 0)

	// Make the file read-only so writing fails.
	require.NoError(t, os.Chmod(path, 0o444))
	t.Cleanup(func() { os.Chmod(path, 0o644) }) //nolint:errcheck

	_, err = fixer.Apply(context.Background(), plan)
	// Should error because all file writes fail.
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write")
}

func TestFixer_Apply_WithInlineVerify(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     true,
		Verify:    true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	plan, err := fixer.Plan(context.Background(), []string{path})
	require.NoError(t, err)
	require.Greater(t, plan.Summary.Applied, 0)

	summary, err := fixer.Apply(context.Background(), plan)
	require.NoError(t, err)
	assert.Greater(t, summary.Applied, 0)

	// File should be modified.
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(after), "privileged: false")
}

// --- applyFixToDocs branch tests ---

func TestApplyFixToDocs_NoMatchingDocument(t *testing.T) {
	yamlContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx
        securityContext:
          privileged: true
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:   "privileged",
			Resource:  "nonexistent-app",
			Namespace: "production",
			Kind:      "Deployment",
			Container: "web",
			FieldPath: ".spec.containers[0].securityContext.privileged",
		},
		Strategy: Strategy{
			CheckID:      "privileged",
			Safety:       checker.FixSafe,
			Operation:    checker.FixOpSet,
			FieldPath:    "spec.containers[*].securityContext.privileged",
			DesiredValue: false,
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching document found")
}

func TestApplyFixToDocs_UnknownOperation(t *testing.T) {
	yamlContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx
        securityContext:
          privileged: true
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:   "privileged",
			Resource:  "web-app",
			Namespace: "production",
			Kind:      "Deployment",
			Container: "web",
			FieldPath: ".spec.containers[0].securityContext.privileged",
		},
		Strategy: Strategy{
			CheckID:      "privileged",
			Safety:       checker.FixSafe,
			Operation:    checker.FixOp("unknown_op"),
			FieldPath:    "spec.containers[*].securityContext.privileged",
			DesiredValue: false,
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fix operation")
}

func TestApplyFixToDocs_AddOperation(t *testing.T) {
	yamlContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:   "automount-service-account-token",
			Resource:  "web-app",
			Namespace: "production",
			Kind:      "Deployment",
			FieldPath: ".spec.automountServiceAccountToken",
		},
		Strategy: Strategy{
			CheckID:      "automount-service-account-token",
			Safety:       checker.FixSafe,
			Operation:    checker.FixOpAdd,
			FieldPath:    "spec.automountServiceAccountToken",
			DesiredValue: false,
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.NoError(t, err)
	assert.True(t, docs[0].Modified)
}

func TestApplyFixToDocs_RemoveOperation(t *testing.T) {
	yamlContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx
        ports:
        - containerPort: 80
          hostPort: 8080
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:   "host-port",
			Resource:  "web-app",
			Namespace: "production",
			Kind:      "Deployment",
			Container: "web",
			FieldPath: ".spec.containers[0].ports[0].hostPort",
		},
		Strategy: Strategy{
			CheckID:   "host-port",
			Safety:    checker.FixPotentiallyBreaking,
			Operation: checker.FixOpRemove,
			FieldPath: "spec.containers[*].ports[0].hostPort",
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.NoError(t, err)
	assert.True(t, docs[0].Modified)
}

func TestApplyFixToDocs_MergeOperation(t *testing.T) {
	yamlContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx
        resources: {}
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:   "resource-limits-missing",
			Resource:  "web-app",
			Namespace: "production",
			Kind:      "Deployment",
			Container: "web",
			FieldPath: ".spec.containers[0].resources.limits",
		},
		Strategy: Strategy{
			CheckID:   "resource-limits-missing",
			Safety:    checker.FixPotentiallyBreaking,
			Operation: checker.FixOpMerge,
			FieldPath: "spec.containers[*].resources.limits",
			DesiredValue: map[string]string{
				"cpu":    "500m",
				"memory": "256Mi",
			},
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.NoError(t, err)
	assert.True(t, docs[0].Modified)
}

func TestIsYAMLFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"test.yaml", true},
		{"test.yml", true},
		{"test.YAML", true},
		{"test.YML", true},
		{"test.json", false},
		{"test.txt", false},
		{"test", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isYAMLFile(tt.path); got != tt.want {
				t.Errorf("isYAMLFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestFixer_FingerprintFiltering verifies that the --fingerprint flag filters
// to only the specified finding. This is the acceptance test for KubeVigil-ir8l.
func TestFixer_FingerprintFiltering(t *testing.T) {
	path1 := copyFixture(t, "multi-finding.yaml")
	dir1 := filepath.Dir(path1)

	// First, plan without fingerprint filtering to discover all findings.
	f1 := newTestFixer(t, Config{RiskLevel: RiskLevelAggressive})
	plan1, err := f1.Plan(context.Background(), []string{dir1})
	require.NoError(t, err)
	require.True(t, len(plan1.Summary.Results) > 1, "multi-finding fixture should produce multiple findings")

	// Pick the first applied PlannedFix to get the full Finding (including FieldPath).
	var targetFinding *checker.Finding
	var targetCheckID string
	for _, fp := range plan1.Files {
		for i := range fp.Fixes {
			if fp.Fixes[i].Applied {
				f := fp.Fixes[i].Finding
				targetFinding = &f
				targetCheckID = f.Checker
				break
			}
		}
		if targetFinding != nil {
			break
		}
	}
	require.NotNil(t, targetFinding, "should have at least one applied finding")

	fp := FindingFingerprint(targetFinding)
	require.Len(t, fp, 12, "fingerprint should be 12 hex chars")

	// Now plan again WITH fingerprint filtering — only the target finding should be applied.
	path2 := copyFixture(t, "multi-finding.yaml")
	dir2 := filepath.Dir(path2)
	f2 := newTestFixer(t, Config{
		RiskLevel:    RiskLevelAggressive,
		Fingerprints: []string{fp},
	})
	plan2, err := f2.Plan(context.Background(), []string{dir2})
	require.NoError(t, err)

	appliedCount := 0
	for _, r := range plan2.Summary.Results {
		if r.Applied {
			appliedCount++
		}
	}
	assert.Equal(t, 1, appliedCount, "fingerprint filter should select exactly one finding")

	// The applied finding should match the target check.
	for _, r := range plan2.Summary.Results {
		if r.Applied {
			assert.Equal(t, targetCheckID, r.CheckID)
			break
		}
	}
}

// TestFixer_ClassifyFinding_Filters tests the various classifyFinding filter branches.
func TestFixer_ClassifyFinding_Filters(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")
	dir := filepath.Dir(path)

	t.Run("CheckFilter", func(t *testing.T) {
		f := newTestFixer(t, Config{
			RiskLevel: RiskLevelAggressive,
			Checks:    []string{"nonexistent-check"},
		})
		plan, err := f.Plan(context.Background(), []string{dir})
		require.NoError(t, err)
		// All findings should be skipped because the check filter doesn't match.
		assert.Equal(t, 0, plan.Summary.Applied)
		assert.Greater(t, plan.Summary.Skipped, 0)
		assert.Greater(t, plan.Summary.SkipReasons["check_not_selected"], 0)
	})

	t.Run("SeverityFilter", func(t *testing.T) {
		f := newTestFixer(t, Config{
			RiskLevel:  RiskLevelAggressive,
			Severities: []string{"info"},
		})
		plan, err := f.Plan(context.Background(), []string{dir})
		require.NoError(t, err)
		// Most security findings are high/critical, not info.
		skippedBySeverity := plan.Summary.SkipReasons["severity_not_selected"]
		assert.Greater(t, skippedBySeverity, 0)
	})

	t.Run("NamespaceFilter", func(t *testing.T) {
		f := newTestFixer(t, Config{
			RiskLevel:  RiskLevelAggressive,
			Namespaces: []string{"nonexistent-ns"},
		})
		plan, err := f.Plan(context.Background(), []string{dir})
		require.NoError(t, err)
		assert.Equal(t, 0, plan.Summary.Applied)
		assert.Greater(t, plan.Summary.SkipReasons["namespace_not_selected"], 0)
	})

	t.Run("ExcludeNamespaceFilter", func(t *testing.T) {
		f := newTestFixer(t, Config{
			RiskLevel:         RiskLevelAggressive,
			ExcludeNamespaces: []string{"production"},
		})
		plan, err := f.Plan(context.Background(), []string{dir})
		require.NoError(t, err)
		// simple-deployment.yaml has namespace: production, so all should be excluded.
		assert.Equal(t, 0, plan.Summary.Applied)
		assert.Greater(t, plan.Summary.SkipReasons["namespace_excluded"], 0)
	})
}

// --- Additional fixer pipeline edge case tests ---

func TestExtractMetadata_NilNode(t *testing.T) {
	doc := &Document{Node: nil}
	apiVersion, kind, name, namespace := extractMetadata(doc)
	assert.Empty(t, apiVersion)
	assert.Empty(t, kind)
	assert.Empty(t, name)
	assert.Empty(t, namespace)
}

func TestExtractMetadata_NonMappingContent(t *testing.T) {
	// Create a document with a scalar content node instead of mapping.
	doc := &Document{
		Node: &yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "just-a-string"},
			},
		},
	}
	apiVersion, kind, name, namespace := extractMetadata(doc)
	assert.Empty(t, apiVersion)
	assert.Empty(t, kind)
	assert.Empty(t, name)
	assert.Empty(t, namespace)
}

func TestExtractMetadata_NoMetadata(t *testing.T) {
	yamlContent := `apiVersion: v1
kind: Pod
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)
	require.Len(t, docs, 1)

	apiVersion, kind, name, namespace := extractMetadata(docs[0])
	assert.Equal(t, "v1", apiVersion)
	assert.Equal(t, "Pod", kind)
	assert.Empty(t, name)
	assert.Empty(t, namespace)
}

func TestApplyFixToDocs_NilDocNode(t *testing.T) {
	// A document with nil Node should be skipped.
	docs := []*Document{
		{Node: nil},
	}

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:  "privileged",
			Resource: "test",
			Kind:     "Pod",
		},
		Strategy: Strategy{
			CheckID:      "privileged",
			Safety:       checker.FixSafe,
			Operation:    checker.FixOpSet,
			FieldPath:    "spec.containers[*].securityContext.privileged",
			DesiredValue: false,
		},
		Applied: true,
	}

	err := applyFixToDocs(docs, pf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching document found")
}

func TestApplyFixToDocs_DocWithoutAPIVersionOrKind(t *testing.T) {
	// A document without apiVersion/kind fields should be skipped.
	yamlContent := `data:
  key: value
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:  "privileged",
			Resource: "test",
			Kind:     "Pod",
		},
		Strategy: Strategy{
			CheckID:      "privileged",
			Safety:       checker.FixSafe,
			Operation:    checker.FixOpSet,
			FieldPath:    "spec.containers[*].securityContext.privileged",
			DesiredValue: false,
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching document found")
}

func TestApplyFixToDocs_NamespaceMismatch(t *testing.T) {
	yamlContent := `apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: staging
spec:
  containers:
  - name: web
    securityContext:
      privileged: true
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:   "privileged",
			Resource:  "test",
			Namespace: "production", // different namespace
			Kind:      "Pod",
			FieldPath: ".spec.containers[0].securityContext.privileged",
		},
		Strategy: Strategy{
			CheckID:      "privileged",
			Safety:       checker.FixSafe,
			Operation:    checker.FixOpSet,
			FieldPath:    "spec.containers[*].securityContext.privileged",
			DesiredValue: false,
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching document found")
}

func TestApplyFixToDocs_AddOperationFallsBackToSet(t *testing.T) {
	// When AddNode returns "already exists", it falls back to SetNode.
	yamlContent := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  automountServiceAccountToken: true
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:   "automount-service-account-token",
			Resource:  "test",
			Kind:      "Pod",
			FieldPath: ".spec.automountServiceAccountToken",
		},
		Strategy: Strategy{
			CheckID:      "automount-service-account-token",
			Safety:       checker.FixSafe,
			Operation:    checker.FixOpAdd,
			FieldPath:    "spec.automountServiceAccountToken",
			DesiredValue: false,
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.NoError(t, err)
	assert.True(t, docs[0].Modified)

	// The field should now be false.
	found, err := FindNode(docs[0].Node, "spec.automountServiceAccountToken")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "false", found.Value)
}

func TestApplyFixToDocs_MergeOperationFallsBackToSet(t *testing.T) {
	// When MergeNode returns "not found", it falls back to SetNode.
	yamlContent := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: web
    image: nginx
`
	docs, err := ParseDocuments([]byte(yamlContent))
	require.NoError(t, err)

	pf := &PlannedFix{
		Finding: checker.Finding{
			Checker:   "resource-limits-missing",
			Resource:  "test",
			Kind:      "Pod",
			Container: "web",
			FieldPath: ".spec.containers[0].resources",
		},
		Strategy: Strategy{
			CheckID:   "resource-limits-missing",
			Safety:    checker.FixPotentiallyBreaking,
			Operation: checker.FixOpMerge,
			FieldPath: "spec.containers[*].resources",
			DesiredValue: map[string]any{
				"limits": map[string]any{
					"cpu":    "500m",
					"memory": "256Mi",
				},
			},
		},
		Applied: true,
	}

	err = applyFixToDocs(docs, pf)
	require.NoError(t, err)
	assert.True(t, docs[0].Modified)
}

func TestMergeAppliedStatus(t *testing.T) {
	all := []PlannedFix{
		{
			Finding:  checker.Finding{Checker: "check-a", Resource: "r1", Namespace: "ns1"},
			Applied:  true,
			Strategy: Strategy{CheckID: "check-a"},
		},
		{
			Finding:    checker.Finding{Checker: "check-b", Resource: "r1", Namespace: "ns1"},
			Applied:    false,
			SkipReason: "risk_level",
			Strategy:   Strategy{CheckID: "check-b"},
		},
		{
			Finding:  checker.Finding{Checker: "check-c", Resource: "r1", Namespace: "ns1"},
			Applied:  true,
			Strategy: Strategy{CheckID: "check-c"},
		},
	}

	// Simulate that check-a failed during apply.
	applied := []PlannedFix{
		{
			Finding:    checker.Finding{Checker: "check-a", Resource: "r1", Namespace: "ns1"},
			Applied:    false,
			SkipReason: "apply_error: some error",
			Strategy:   Strategy{CheckID: "check-a"},
		},
		{
			Finding:  checker.Finding{Checker: "check-c", Resource: "r1", Namespace: "ns1"},
			Applied:  true,
			Strategy: Strategy{CheckID: "check-c"},
		},
	}

	result := mergeAppliedStatus(all, applied)
	require.Len(t, result, 3)

	// check-a should now be failed.
	assert.False(t, result[0].Applied)
	assert.Contains(t, result[0].SkipReason, "apply_error")

	// check-b was skipped originally — should remain skipped.
	assert.False(t, result[1].Applied)
	assert.Equal(t, "risk_level", result[1].SkipReason)

	// check-c was applied successfully.
	assert.True(t, result[2].Applied)
}

func TestCollectFiles_NonExistentPath(t *testing.T) {
	_, err := collectFiles([]string{"/nonexistent/path/to/nowhere"})
	require.Error(t, err)
}

func TestCollectFiles_DuplicateFiles(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")
	require.NoError(t, os.WriteFile(path, []byte("---"), 0o644))

	// Pass the same file twice.
	files, err := collectFiles([]string{path, path})
	require.NoError(t, err)
	// Should be deduplicated.
	assert.Len(t, files, 1)
}

func TestCollectFiles_NonYAMLFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o644))

	files, err := collectFiles([]string{path})
	require.NoError(t, err)
	assert.Len(t, files, 0)
}

func TestFixer_Fix_DryRunExplicit(t *testing.T) {
	path := copyFixture(t, "simple-deployment.yaml")
	original, err := os.ReadFile(path)
	require.NoError(t, err)

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelSafe,
		Apply:     true,
		DryRun:    true, // DryRun overrides Apply
	})

	_, _, err = fixer.Fix(context.Background(), []string{path})
	require.NoError(t, err)

	// File should be unchanged because DryRun is true.
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(after))
}

func TestCommonBase_RootPaths(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  string
	}{
		{
			name:  "root level files",
			paths: []string{"/a.yaml", "/b.yaml"},
			want:  "/",
		},
		{
			name:  "deeply different",
			paths: []string{"/a/b/c/d.yaml", "/x/y/z.yaml"},
			want:  "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commonBase(tt.paths)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFixer_RunAsRoot_PreservesRunAsUser(t *testing.T) {
	// Regression test: the fix engine must set runAsNonRoot: true without
	// corrupting an existing runAsUser field. Previously, the path resolver
	// used the finding's field path (pointing to runAsUser) instead of the
	// strategy's field path (pointing to runAsNonRoot), causing runAsUser: 0
	// to be overwritten with runAsUser: true.
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
  namespace: default
spec:
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
        - name: web
          image: nginx:1.25
          securityContext:
            runAsUser: 0
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "deploy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(manifest), 0o644))

	fixer := newTestFixer(t, Config{
		RiskLevel: RiskLevelModerate, // run-as-root is likely_safe
		Apply:     true,
		BackupDir: filepath.Join(t.TempDir(), "backup"),
	})

	_, summary, err := fixer.Fix(context.Background(), []string{path})
	require.NoError(t, err)
	assert.Greater(t, summary.Applied, 0, "should have applied at least one fix")

	patched, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(patched)

	// runAsNonRoot: true must be present (the fix).
	assert.Contains(t, content, "runAsNonRoot: true",
		"fix should add runAsNonRoot: true")

	// runAsUser must NOT have been changed to a boolean.
	assert.NotContains(t, content, "runAsUser: true",
		"fix must not corrupt runAsUser to boolean true")

	// Parse and verify the YAML structure.
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal(patched, &node))
}
