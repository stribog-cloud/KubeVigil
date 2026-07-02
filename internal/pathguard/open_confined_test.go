package pathguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenConfinedRegularFile_RejectsEmptyAndDotPath(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{".", ""} {
		_, err := openConfinedRegularFile(root, rel)
		if err == nil {
			t.Fatalf("openConfinedRegularFile(%q) expected error", rel)
		}
	}
}

func TestOpenConfinedRegularFile_RejectsDotDotTraversal(t *testing.T) {
	root := t.TempDir()
	_, err := openConfinedRegularFile(root, "../outside.yaml")
	if err == nil {
		t.Fatal("expected .. traversal rejection")
	}
}

func TestOpenConfinedRegularFile_RejectsMissingFile(t *testing.T) {
	root := t.TempDir()
	_, err := openConfinedRegularFile(root, "missing.yaml")
	if err == nil {
		t.Fatal("expected missing file error")
	}
}

func TestOpenConfinedRegularFile_RejectsNestedDirectoryTarget(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := openConfinedRegularFile(root, "sub")
	if err == nil {
		t.Fatal("expected error opening directory as file")
	}
}

func TestOpenConfinedRegularFile_ReadsNestedFile(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "nested")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("apiVersion: v1\n")
	if err := os.WriteFile(filepath.Join(sub, "pod.yaml"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := openConfinedRegularFile(root, filepath.Join("nested", "pod.yaml"))
	if err != nil {
		t.Fatalf("openConfinedRegularFile() error = %v", err)
	}
	defer f.Close()

	data := make([]byte, len(want))
	if _, err := f.Read(data); err != nil {
		t.Fatal(err)
	}
	if string(data) != string(want) {
		t.Fatalf("got %q, want %q", data, want)
	}
}

func TestOpenRegularWithinRoot_RejectsRelOutsideRootAfterResolve(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside-open3.yaml")
	if err := os.WriteFile(outside, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	// Absolute path outside root must fail in OpenRegularWithinRoot rel computation.
	_, err := OpenRegularWithinRoot(root, outside)
	if err == nil {
		t.Fatal("expected outside-root rejection")
	}
}

func TestOpenConfinedAt_RejectsNonDirectoryIntermediate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := openConfinedAt(root, []string{"file.yaml", "nested.yaml"})
	if err == nil {
		t.Fatal("expected error when intermediate path is not a directory")
	}
	if !strings.Contains(err.Error(), "opening") {
		t.Errorf("error = %v, want open failure", err)
	}
}
