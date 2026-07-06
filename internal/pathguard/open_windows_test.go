//go:build windows

package pathguard

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// These tests exist to give the Windows-only openConfinedAt implementation
// real runtime coverage on a Windows runner. The cross-platform tests in
// pathguard_test.go / pathguard_open_test.go also exercise it, but these
// assert the Windows-specific behaviors without depending on symlink-creation
// privilege (which is not guaranteed on every Windows environment).

func TestWindows_OpenRegularWithinRoot_ReadsNestedFile(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b", "pod.yaml")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("apiVersion: v1\nkind: Pod\n")
	if err := os.WriteFile(nested, content, 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := OpenRegularWithinRoot(root, filepath.Join("a", "b", "pod.yaml"))
	if err != nil {
		t.Fatalf("OpenRegularWithinRoot() error = %v", err)
	}
	defer f.Close()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch: got %q", got)
	}
}

func TestWindows_OpenRegularWithinRoot_RejectsDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "manifests"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenRegularWithinRoot(root, "manifests"); err == nil {
		t.Fatal("expected error opening a directory as a regular file")
	}
}

func TestWindows_OpenRegularWithinRoot_RejectsEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := OpenRegularWithinRoot(root, filepath.Join("..", "escape.yaml")); err == nil {
		t.Fatal("expected error for path escaping the workspace root")
	}
}
