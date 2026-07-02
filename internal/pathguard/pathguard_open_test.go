package pathguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularWithinRoot_AcceptsAbsolutePathInsideRoot(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "abs.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := OpenRegularWithinRoot(root, manifest)
	if err != nil {
		t.Fatalf("OpenRegularWithinRoot() error = %v", err)
	}
	_ = f.Close()
}

func TestOpenRegularWithinRoot_RejectsDotDotRelativePath(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside-open2.yaml")
	if err := os.WriteFile(outside, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	_, err := OpenRegularWithinRoot(root, "../"+filepath.Base(outside))
	if err == nil {
		t.Fatal("expected error for .. traversal")
	}
}
