package pathguard

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWithinRoot_AcceptsFileInsideRoot(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pod.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveWithinRoot(root, manifest)
	if err != nil {
		t.Fatalf("ResolveWithinRoot() error = %v", err)
	}
	if got != manifest {
		t.Errorf("got %q, want %q", got, manifest)
	}
}

func TestResolveWithinRoot_AcceptsRelativePathInsideRoot(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "k8s", "pod.yaml")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveWithinRoot(root, "k8s/pod.yaml")
	if err != nil {
		t.Fatalf("ResolveWithinRoot() error = %v", err)
	}
	if got != manifest {
		t.Errorf("got %q, want %q", got, manifest)
	}
}

func TestResolveWithinRoot_AcceptsDirectoryInsideRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "manifests"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveWithinRoot(root, "manifests")
	if err != nil {
		t.Fatalf("ResolveWithinRoot() error = %v", err)
	}
	want := filepath.Join(root, "manifests")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveWithinRoot_RejectsAbsoluteOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := "/etc/passwd"
	if _, err := os.Stat(outside); os.IsNotExist(err) {
		t.Skip("no /etc/passwd on this system")
	}

	_, err := ResolveWithinRoot(root, outside)
	if err == nil {
		t.Fatal("expected error for path outside workspace root")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Errorf("error = %v, want mention of outside workspace", err)
	}
}

func TestResolveWithinRoot_RejectsDotDotEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside-escape.yaml")
	if err := os.WriteFile(outside, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	_, err := ResolveWithinRoot(root, "../"+filepath.Base(outside))
	if err == nil {
		t.Fatal("expected error for .. traversal")
	}
}

func TestResolveWithinRoot_RejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.yaml")
	if err := os.WriteFile(outsideFile, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(root, "escape.yaml")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := ResolveWithinRoot(root, link)
	if err == nil {
		t.Fatal("expected error for symlink escape")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v, want symlink rejection", err)
	}
}

func TestResolveWithinRoot_RejectsSymlinkToParent(t *testing.T) {
	root := t.TempDir()
	parentLink := filepath.Join(root, "parent")
	if err := os.Symlink("..", parentLink); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := ResolveWithinRoot(root, filepath.Join("parent", "etc", "passwd"))
	if err == nil {
		t.Fatal("expected error for symlink pointing outside root")
	}
}

func TestResolveWithinRoot_RejectsNonexistentPath(t *testing.T) {
	root := t.TempDir()
	_, err := ResolveWithinRoot(root, "missing/pod.yaml")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestResolveWithinRoot_RejectsNonRegularNonDir(t *testing.T) {
	root := t.TempDir()
	if _, err := ResolveWithinRoot(root, "/dev/null"); os.IsNotExist(err) {
		t.Skip("no /dev/null on this system")
	} else if err == nil {
		t.Fatal("expected error for special file outside workspace")
	}
}

func TestAssertWithinRoot_AcceptsPathInsideRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "nested", "pod.yaml")
	if err := os.MkdirAll(filepath.Dir(inside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := AssertWithinRoot(root, inside); err != nil {
		t.Fatalf("AssertWithinRoot() error = %v", err)
	}
}

func TestAssertWithinRoot_RejectsPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside-pod.yaml")
	if err := os.WriteFile(outside, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	err := AssertWithinRoot(root, outside)
	if err == nil {
		t.Fatal("expected error for path outside root")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Errorf("error = %v, want outside workspace", err)
	}
}

func TestAssertWithinRoot_RejectsDotDotRelativePath(t *testing.T) {
	root := t.TempDir()
	err := AssertWithinRoot(root, "../"+filepath.Base(root))
	if err == nil {
		t.Fatal("expected error for .. relative path")
	}
}

func TestResolveWithinRoot_RejectsSymlinkParentDirectory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "manifests")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(realDir, "pod.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "via-link")
	if err := os.Symlink("manifests", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := ResolveWithinRoot(root, filepath.Join("via-link", "pod.yaml"))
	if err == nil {
		t.Fatal("expected error for path through symlink parent directory")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v, want symlink parent rejection", err)
	}
}

func TestOpenRegularWithinRoot_ReadsFileInsideRoot(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pod.yaml")
	content := []byte("apiVersion: v1\nkind: Pod\n")
	if err := os.WriteFile(manifest, content, 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := OpenRegularWithinRoot(root, "pod.yaml")
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

func TestOpenRegularWithinRoot_RejectsTOCTOUSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.yaml")
	if err := os.WriteFile(secret, []byte("stolen"), 0o644); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "pod.yaml")
	if err := os.WriteFile(target, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, target); err != nil {
		t.Fatal(err)
	}

	_, err := OpenRegularWithinRoot(root, "pod.yaml")
	if err == nil {
		t.Fatal("expected rejection when validated path replaced by symlink before open")
	}
	if !strings.Contains(err.Error(), "symlink") && !strings.Contains(err.Error(), "opening") {
		t.Errorf("error = %v, want symlink or open failure", err)
	}
}

func TestOpenRegularWithinRoot_RejectsMissingFile(t *testing.T) {
	root := t.TempDir()
	_, err := OpenRegularWithinRoot(root, "missing.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestOpenRegularWithinRoot_RejectsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside-open.yaml")
	if err := os.WriteFile(outside, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	_, err := OpenRegularWithinRoot(root, outside)
	if err == nil {
		t.Fatal("expected error for absolute path outside root")
	}
}

func TestDefaultWorkspaceRoot_UsesEnvWhenSet(t *testing.T) {
	root := t.TempDir()
	t.Setenv(WorkspaceRootEnv, root)
	got, err := DefaultWorkspaceRoot()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(root)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOpenRegularWithinRoot_RejectsDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "manifests"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := OpenRegularWithinRoot(root, "manifests")
	if err == nil {
		t.Fatal("expected error opening directory as regular file")
	}
}
