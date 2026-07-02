package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePathWithinRoot_RejectsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	_, errs := ParsePathWithinRoot("/etc/passwd", root)
	if len(errs) == 0 {
		t.Fatal("expected confinement error")
	}
	if !strings.Contains(errs[0].Error(), "outside") {
		t.Errorf("error = %v, want outside workspace", errs[0])
	}
}

func TestParsePathWithinRoot_ParsesInsideRoot(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pod.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache, errs := ParsePathWithinRoot(manifest, root)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if cache.Len() == 0 {
		t.Fatal("expected parsed resources")
	}
}

func TestParsePathWithinRoot_ParsesDirectoryInsideRoot(t *testing.T) {
	root := t.TempDir()
	manifests := filepath.Join(root, "manifests")
	if err := os.MkdirAll(manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	podYAML := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
	if err := os.WriteFile(filepath.Join(manifests, "a.yaml"), []byte(podYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifests, "b.yml"), []byte(podYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifests, "notes.txt"), []byte("skip"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache, errs := ParsePathWithinRoot(root, root)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if cache.Len() != 2 {
		t.Fatalf("cache.Len() = %d, want 2 manifests parsed", cache.Len())
	}
}

func TestParsePathWithinRoot_RejectsSymlinkInDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "pod.yaml")
	if err := os.WriteFile(target, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, errs := ParsePathWithinRoot(root, root)
	if len(errs) == 0 {
		t.Fatal("expected symlink rejection error")
	}
	found := false
	for _, err := range errs {
		if strings.Contains(err.Error(), "symlink") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("errors = %v, want symlink rejection", errs)
	}
}

func TestParsePathWithinRoot_RejectsOversizedFileInDirectory(t *testing.T) {
	root := t.TempDir()
	big := filepath.Join(root, "huge.yaml")
	if err := os.WriteFile(big, make([]byte, maxManifestFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}

	_, errs := ParsePathWithinRoot(root, root)
	if len(errs) == 0 {
		t.Fatal("expected file size error")
	}
	if !strings.Contains(errs[0].Error(), "exceeds maximum") {
		t.Errorf("error = %v, want size limit message", errs[0])
	}
}

func TestParsePathWithinRoot_RejectsMissingPath(t *testing.T) {
	root := t.TempDir()
	_, errs := ParsePathWithinRoot(filepath.Join(root, "missing.yaml"), root)
	if len(errs) == 0 {
		t.Fatal("expected stat error for missing file")
	}
}

func TestParsePathWithinRoot_CollectsParseErrorsInDirectory(t *testing.T) {
	root := t.TempDir()
	valid := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\n"
	if err := os.WriteFile(filepath.Join(root, "good.yaml"), []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bad.yaml"), []byte("{{invalid"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache, errs := ParsePathWithinRoot(root, root)
	if len(errs) == 0 {
		t.Fatal("expected parse error for malformed yaml")
	}
	if cache.Len() == 0 {
		t.Fatal("expected valid manifest to still be parsed")
	}
}

func TestParsePathWithinRoot_ReportsUnreadableFileInDirectory(t *testing.T) {
	root := t.TempDir()
	locked := filepath.Join(root, "locked.yaml")
	if err := os.WriteFile(locked, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	_, errs := ParsePathWithinRoot(root, root)
	if len(errs) == 0 {
		t.Fatal("expected read error for unreadable manifest")
	}
	if !strings.Contains(errs[0].Error(), "reading") {
		t.Errorf("error = %v, want read failure", errs[0])
	}
}

func TestParsePathWithinRoot_RejectsPathOutsideRootDuringWalk(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	// Tighten root to nested subdir; sibling file at root level is outside bounded root.
	if err := os.WriteFile(filepath.Join(root, "outside.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: o\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "inside.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: i\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cache, errs := ParsePathWithinRoot(nested, nested)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors scanning confined dir: %v", errs)
	}
	if cache.Len() != 1 {
		t.Fatalf("cache.Len() = %d, want 1", cache.Len())
	}
}
