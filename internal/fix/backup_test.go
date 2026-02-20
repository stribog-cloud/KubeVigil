package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDefaultBackupDirFormat(t *testing.T) {
	tests := []struct {
		name       string
		sourcePath string
	}{
		{name: "simple path", sourcePath: "/manifests"},
		{name: "nested path", sourcePath: "/home/user/k8s/manifests"},
		{name: "relative path", sourcePath: "./manifests"},
		{name: "trailing slash stripped by caller", sourcePath: "/manifests/apps"},
	}

	pattern := regexp.MustCompile(`\.kubevigil-backup-\d{8}T\d{6}$`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DefaultBackupDir(tt.sourcePath)

			if !strings.HasPrefix(got, tt.sourcePath+".kubevigil-backup-") {
				t.Errorf("DefaultBackupDir(%q) = %q, want prefix %q", tt.sourcePath, got, tt.sourcePath+".kubevigil-backup-")
			}

			if !pattern.MatchString(got) {
				t.Errorf("DefaultBackupDir(%q) = %q, does not match expected timestamp pattern", tt.sourcePath, got)
			}
		})
	}
}

func TestBackupFileSingle(t *testing.T) {
	// Setup: create a source directory with a single file.
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	content := []byte("apiVersion: v1\nkind: Pod\n")
	srcFile := filepath.Join(srcDir, "pod.yaml")
	if err := os.WriteFile(srcFile, content, 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	if err := BackupFile(srcFile, srcDir, backupDir); err != nil {
		t.Fatalf("BackupFile() error = %v", err)
	}

	// Verify the backed-up file exists and has the same content.
	backedUp := filepath.Join(backupDir, "pod.yaml")
	got, err := os.ReadFile(backedUp)
	if err != nil {
		t.Fatalf("reading backed-up file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("backed-up content = %q, want %q", string(got), string(content))
	}
}

func TestBackupFileMultiple(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	files := map[string]string{
		"deploy.yaml":  "kind: Deployment\n",
		"service.yaml": "kind: Service\n",
		"pod.yaml":     "kind: Pod\n",
	}

	var filePaths []string
	for name, content := range files {
		path := filepath.Join(srcDir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		filePaths = append(filePaths, path)
	}

	if err := CreateBackup(filePaths, srcDir, backupDir); err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}

	for name, wantContent := range files {
		backedUp := filepath.Join(backupDir, name)
		got, err := os.ReadFile(backedUp)
		if err != nil {
			t.Errorf("reading backed-up file %s: %v", name, err)
			continue
		}
		if string(got) != wantContent {
			t.Errorf("backed-up %s content = %q, want %q", name, string(got), wantContent)
		}
	}
}

func TestBackupFileNestedDirectories(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	// Create nested directory structure.
	nestedDir := filepath.Join(srcDir, "apps", "frontend")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("creating nested dir: %v", err)
	}

	content := []byte("kind: Deployment\nmetadata:\n  name: frontend\n")
	srcFile := filepath.Join(nestedDir, "deploy.yaml")
	if err := os.WriteFile(srcFile, content, 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	if err := BackupFile(srcFile, srcDir, backupDir); err != nil {
		t.Fatalf("BackupFile() error = %v", err)
	}

	backedUp := filepath.Join(backupDir, "apps", "frontend", "deploy.yaml")
	got, err := os.ReadFile(backedUp)
	if err != nil {
		t.Fatalf("reading backed-up file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("backed-up content = %q, want %q", string(got), string(content))
	}
}

func TestBackupFilePreservesPermissions(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	srcFile := filepath.Join(srcDir, "secret.yaml")
	if err := os.WriteFile(srcFile, []byte("kind: Secret\n"), 0o600); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	if err := BackupFile(srcFile, srcDir, backupDir); err != nil {
		t.Fatalf("BackupFile() error = %v", err)
	}

	backedUp := filepath.Join(backupDir, "secret.yaml")
	info, err := os.Stat(backedUp)
	if err != nil {
		t.Fatalf("stat backed-up file: %v", err)
	}

	// The backed-up file should have the same permissions as the source.
	srcInfo, err := os.Stat(srcFile)
	if err != nil {
		t.Fatalf("stat source file: %v", err)
	}

	if info.Mode().Perm() != srcInfo.Mode().Perm() {
		t.Errorf("backed-up permissions = %o, want %o", info.Mode().Perm(), srcInfo.Mode().Perm())
	}
}

func TestBackupFileMissingSource(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	nonexistent := filepath.Join(srcDir, "does-not-exist.yaml")

	err := BackupFile(nonexistent, srcDir, backupDir)
	if err == nil {
		t.Fatal("BackupFile() with missing source should return error, got nil")
	}
}

func TestGenerateRestoreInstructionsContent(t *testing.T) {
	backupDir := t.TempDir()
	sourceBase := "/home/user/manifests"
	files := []string{
		"/home/user/manifests/deploy.yaml",
		"/home/user/manifests/apps/service.yaml",
	}

	if err := GenerateRestoreInstructions(backupDir, sourceBase, files); err != nil {
		t.Fatalf("GenerateRestoreInstructions() error = %v", err)
	}

	restorePath := filepath.Join(backupDir, "RESTORE.md")
	data, err := os.ReadFile(restorePath)
	if err != nil {
		t.Fatalf("reading RESTORE.md: %v", err)
	}
	content := string(data)

	// Verify headers are present.
	requiredStrings := []string{
		"# KubeVigil Fix Backup",
		"Restore Instructions",
		"Source:",
		sourceBase,
		"Quick Restore",
		"Individual File Restore",
		"Backup File",
		"Original Location",
		"Restore Commands",
	}
	for _, s := range requiredStrings {
		if !strings.Contains(content, s) {
			t.Errorf("RESTORE.md missing required string: %q", s)
		}
	}

	// Verify file paths appear in the content.
	if !strings.Contains(content, "deploy.yaml") {
		t.Error("RESTORE.md missing deploy.yaml reference")
	}
	if !strings.Contains(content, filepath.Join("apps", "service.yaml")) {
		t.Error("RESTORE.md missing apps/service.yaml reference")
	}

	// Verify cp commands are present.
	if !strings.Contains(content, "cp ") {
		t.Error("RESTORE.md missing cp restore commands")
	}
}

func TestCreateBackupCreatesDirectory(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := filepath.Join(t.TempDir(), "new-backup-dir")

	// The backupDir should not exist yet.
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
		t.Fatal("expected backup directory to not exist before CreateBackup")
	}

	srcFile := filepath.Join(srcDir, "test.yaml")
	if err := os.WriteFile(srcFile, []byte("test content"), 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	if err := CreateBackup([]string{srcFile}, srcDir, backupDir); err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}

	// Verify the backup directory was created.
	info, err := os.Stat(backupDir)
	if err != nil {
		t.Fatalf("stat backup directory: %v", err)
	}
	if !info.IsDir() {
		t.Error("backup path exists but is not a directory")
	}
}

func TestCreateBackupEmptyFileList(t *testing.T) {
	backupDir := filepath.Join(t.TempDir(), "empty-backup")

	if err := CreateBackup([]string{}, "/some/source", backupDir); err != nil {
		t.Fatalf("CreateBackup() with empty file list should not error, got: %v", err)
	}

	// Verify the backup directory was still created.
	info, err := os.Stat(backupDir)
	if err != nil {
		t.Fatalf("stat backup directory: %v", err)
	}
	if !info.IsDir() {
		t.Error("backup path exists but is not a directory")
	}
}

func TestCreateBackupStopsOnError(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	// Create one valid file and one that doesn't exist.
	validFile := filepath.Join(srcDir, "valid.yaml")
	if err := os.WriteFile(validFile, []byte("valid"), 0o644); err != nil {
		t.Fatalf("writing valid file: %v", err)
	}
	missingFile := filepath.Join(srcDir, "missing.yaml")

	// Order matters: put the missing file first to verify early failure.
	err := CreateBackup([]string{missingFile, validFile}, srcDir, backupDir)
	if err == nil {
		t.Fatal("CreateBackup() should return error when a file copy fails")
	}
}

func TestBackupFileContentExactMatch(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	// Use content with special characters, comments, and multi-line.
	content := []byte(`# This is a comment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx # inline comment
  namespace: default
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:1.25
          ports:
            - containerPort: 80
`)

	srcFile := filepath.Join(srcDir, "deploy.yaml")
	if err := os.WriteFile(srcFile, content, 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	if err := BackupFile(srcFile, srcDir, backupDir); err != nil {
		t.Fatalf("BackupFile() error = %v", err)
	}

	backedUp := filepath.Join(backupDir, "deploy.yaml")
	got, err := os.ReadFile(backedUp)
	if err != nil {
		t.Fatalf("reading backed-up file: %v", err)
	}

	if string(got) != string(content) {
		t.Errorf("backed-up content does not exactly match source\ngot:\n%s\nwant:\n%s", string(got), string(content))
	}
}

func TestGenerateRestoreInstructionsEmptyFiles(t *testing.T) {
	backupDir := t.TempDir()

	if err := GenerateRestoreInstructions(backupDir, "/source", []string{}); err != nil {
		t.Fatalf("GenerateRestoreInstructions() with empty files should not error, got: %v", err)
	}

	restorePath := filepath.Join(backupDir, "RESTORE.md")
	data, err := os.ReadFile(restorePath)
	if err != nil {
		t.Fatalf("reading RESTORE.md: %v", err)
	}

	if !strings.Contains(string(data), "# KubeVigil Fix Backup") {
		t.Error("RESTORE.md missing header even with empty file list")
	}
}

func TestCreateBackupWithNestedDirStructure(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := filepath.Join(t.TempDir(), "deep-backup")

	// Create a multi-level nested structure.
	dirs := []string{
		filepath.Join(srcDir, "base"),
		filepath.Join(srcDir, "overlays", "prod"),
		filepath.Join(srcDir, "overlays", "staging"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("creating dir %s: %v", d, err)
		}
	}

	fileContents := map[string]string{
		filepath.Join(srcDir, "base", "kustomization.yaml"):                "resources:\n- deploy.yaml\n",
		filepath.Join(srcDir, "base", "deploy.yaml"):                       "kind: Deployment\n",
		filepath.Join(srcDir, "overlays", "prod", "patch.yaml"):            "kind: Deployment\n# prod patch\n",
		filepath.Join(srcDir, "overlays", "staging", "kustomization.yaml"): "resources:\n- ../../base\n",
	}

	var filePaths []string
	for path, content := range fileContents {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		filePaths = append(filePaths, path)
	}

	if err := CreateBackup(filePaths, srcDir, backupDir); err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}

	// Verify all files were backed up with correct content.
	for srcPath, wantContent := range fileContents {
		relPath, err := filepath.Rel(srcDir, srcPath)
		if err != nil {
			t.Fatalf("computing relative path: %v", err)
		}
		backedUp := filepath.Join(backupDir, relPath)
		got, err := os.ReadFile(backedUp)
		if err != nil {
			t.Errorf("reading backed-up file %s: %v", relPath, err)
			continue
		}
		if string(got) != wantContent {
			t.Errorf("backed-up %s content = %q, want %q", relPath, string(got), wantContent)
		}
	}
}

func TestGenerateRestoreInstructionsHasTimestamp(t *testing.T) {
	backupDir := t.TempDir()

	if err := GenerateRestoreInstructions(backupDir, "/src", []string{"/src/a.yaml"}); err != nil {
		t.Fatalf("GenerateRestoreInstructions() error = %v", err)
	}

	restorePath := filepath.Join(backupDir, "RESTORE.md")
	data, err := os.ReadFile(restorePath)
	if err != nil {
		t.Fatalf("reading RESTORE.md: %v", err)
	}

	if !strings.Contains(string(data), "Backup created:") {
		t.Error("RESTORE.md missing 'Backup created:' timestamp line")
	}

	// Check for a date-like pattern (YYYY-MM-DD or similar).
	datePattern := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	if !datePattern.Match(data) {
		t.Error("RESTORE.md does not contain a date-formatted timestamp")
	}
}

func TestGenerateRestoreInstructionsTableFormat(t *testing.T) {
	backupDir := t.TempDir()
	sourceBase := "/manifests"
	files := []string{
		"/manifests/deploy.yaml",
		"/manifests/svc.yaml",
	}

	if err := GenerateRestoreInstructions(backupDir, sourceBase, files); err != nil {
		t.Fatalf("GenerateRestoreInstructions() error = %v", err)
	}

	restorePath := filepath.Join(backupDir, "RESTORE.md")
	data, err := os.ReadFile(restorePath)
	if err != nil {
		t.Fatalf("reading RESTORE.md: %v", err)
	}
	content := string(data)

	// Verify table headers.
	if !strings.Contains(content, "| Backup File") {
		t.Error("RESTORE.md missing table header '| Backup File'")
	}
	if !strings.Contains(content, "| Original Location") {
		t.Error("RESTORE.md missing table header '| Original Location'")
	}

	// Verify table separator.
	if !strings.Contains(content, "|---") {
		t.Error("RESTORE.md missing table separator")
	}

	// Verify each file appears in a table row.
	for _, f := range files {
		relPath, _ := filepath.Rel(sourceBase, f)
		backupPath := filepath.Join(backupDir, relPath)
		sourcePath := filepath.Join(sourceBase, relPath)
		tableRow := fmt.Sprintf("| %s | %s |", backupPath, sourcePath)
		if !strings.Contains(content, tableRow) {
			t.Errorf("RESTORE.md missing table row for %s", relPath)
		}
	}
}

// --- Additional backup edge case tests for coverage ---

func TestCreateBackup_BackupDirCreationFailure(t *testing.T) {
	// Create a file where the backup dir should be — os.MkdirAll should fail.
	parent := t.TempDir()
	blockingFile := filepath.Join(parent, "backup")
	if err := os.WriteFile(blockingFile, []byte("I am a file, not a dir"), 0o644); err != nil {
		t.Fatalf("creating blocking file: %v", err)
	}

	// Trying to create a dir nested under the blocking file should fail.
	badBackupDir := filepath.Join(blockingFile, "nested")
	err := CreateBackup([]string{"/some/file.yaml"}, "/some", badBackupDir)
	if err == nil {
		t.Fatal("CreateBackup() with impossible backup dir should error")
	}
	if !strings.Contains(err.Error(), "creating backup directory") {
		t.Errorf("expected 'creating backup directory' error, got: %v", err)
	}
}

func TestBackupFile_SourceFileDoesNotExist(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	nonexistent := filepath.Join(srcDir, "nonexistent.yaml")
	err := BackupFile(nonexistent, srcDir, backupDir)
	if err == nil {
		t.Fatal("BackupFile() with nonexistent source should error")
	}
	// Should contain "stat source file" error.
	if !strings.Contains(err.Error(), "stat source file") {
		t.Errorf("expected 'stat source file' error, got: %v", err)
	}
}

func TestBackupFile_DestinationDirCreationFailure(t *testing.T) {
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "test.yaml")
	if err := os.WriteFile(srcFile, []byte("content"), 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	// Create a file where the backup subdirectory should be.
	parent := t.TempDir()
	blockingFile := filepath.Join(parent, "sub")
	if err := os.WriteFile(blockingFile, []byte("not a dir"), 0o644); err != nil {
		t.Fatalf("creating blocking file: %v", err)
	}

	// BackupFile will try to create the destination subdirectory inside blockingFile.
	backupDir := filepath.Join(blockingFile, "backup")
	err := BackupFile(srcFile, srcDir, backupDir)
	if err == nil {
		t.Fatal("BackupFile() with impossible backup subdir should error")
	}
}

func TestBackupFile_ReadError(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	// Create a file that exists but cannot be read.
	srcFile := filepath.Join(srcDir, "unreadable.yaml")
	if err := os.WriteFile(srcFile, []byte("content"), 0o000); err != nil {
		t.Fatalf("writing source file: %v", err)
	}
	t.Cleanup(func() { os.Chmod(srcFile, 0o644) }) //nolint:errcheck

	err := BackupFile(srcFile, srcDir, backupDir)
	if err == nil {
		t.Fatal("BackupFile() with unreadable source should error")
	}
	if !strings.Contains(err.Error(), "reading source file") {
		t.Errorf("expected 'reading source file' error, got: %v", err)
	}
}

func TestBackupFile_WriteError(t *testing.T) {
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "test.yaml")
	if err := os.WriteFile(srcFile, []byte("content"), 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	// Create a backup dir that is read-only.
	backupDir := filepath.Join(t.TempDir(), "readonly")
	if err := os.MkdirAll(backupDir, 0o555); err != nil {
		t.Fatalf("creating readonly backup dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(backupDir, 0o755) }) //nolint:errcheck

	err := BackupFile(srcFile, srcDir, backupDir)
	if err == nil {
		t.Fatal("BackupFile() with readonly backup dir should error")
	}
	if !strings.Contains(err.Error(), "writing backup file") {
		t.Errorf("expected 'writing backup file' error, got: %v", err)
	}
}

func TestBackupFile_SpecialCharactersInName(t *testing.T) {
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	// File with spaces and special characters.
	srcFile := filepath.Join(srcDir, "my deploy (v2).yaml")
	content := []byte("kind: Deployment\nmetadata:\n  name: special\n")
	if err := os.WriteFile(srcFile, content, 0o644); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	if err := BackupFile(srcFile, srcDir, backupDir); err != nil {
		t.Fatalf("BackupFile() error = %v", err)
	}

	backedUp := filepath.Join(backupDir, "my deploy (v2).yaml")
	got, err := os.ReadFile(backedUp)
	if err != nil {
		t.Fatalf("reading backed-up file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("backed-up content mismatch for special char filename")
	}
}

func TestGenerateRestoreInstructions_WriteError(t *testing.T) {
	// Create a read-only directory where RESTORE.md cannot be written.
	backupDir := filepath.Join(t.TempDir(), "readonly")
	if err := os.MkdirAll(backupDir, 0o555); err != nil {
		t.Fatalf("creating readonly dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(backupDir, 0o755) }) //nolint:errcheck

	err := GenerateRestoreInstructions(backupDir, "/source", []string{"/source/a.yaml"})
	if err == nil {
		t.Fatal("GenerateRestoreInstructions() with readonly dir should error")
	}
	if !strings.Contains(err.Error(), "writing RESTORE.md") {
		t.Errorf("expected 'writing RESTORE.md' error, got: %v", err)
	}
}

func TestBackupFile_RejectsPathTraversal(t *testing.T) {
	// If srcPath is outside sourceBase, filepath.Rel produces a ".." path.
	// BackupFile must reject this to prevent writing outside the backup directory.
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	// Create a file in a sibling directory (outside sourceBase).
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "sensitive.yaml")
	if err := os.WriteFile(outsideFile, []byte("sensitive data"), 0o644); err != nil {
		t.Fatalf("writing outside file: %v", err)
	}

	err := BackupFile(outsideFile, srcDir, backupDir)
	if err == nil {
		t.Fatal("BackupFile() should reject path traversal, got nil")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Errorf("error should mention path traversal, got: %v", err)
	}
}

func TestGenerateRestoreInstructions_RelPathError(t *testing.T) {
	// When Rel() cannot compute a relative path, it falls back to filepath.Base().
	// This is hard to trigger in practice but the code has a fallback path.
	// We can test with a normal case and verify the output is correct.
	backupDir := t.TempDir()

	// Files not under sourceBase — Rel() should still work on most systems, but
	// the code handles the error by using filepath.Base().
	err := GenerateRestoreInstructions(backupDir, "/source/base", []string{"/source/base/deploy.yaml"})
	if err != nil {
		t.Fatalf("GenerateRestoreInstructions() error = %v", err)
	}

	restorePath := filepath.Join(backupDir, "RESTORE.md")
	data, err := os.ReadFile(restorePath)
	if err != nil {
		t.Fatalf("reading RESTORE.md: %v", err)
	}
	if !strings.Contains(string(data), "deploy.yaml") {
		t.Error("RESTORE.md should reference deploy.yaml")
	}
}
