package pathguard

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestResolveWithinRoot_RejectsFifoInsideRoot(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo not supported: %v", err)
	}

	_, err := ResolveWithinRoot(root, fifo)
	if err == nil {
		t.Fatal("expected error for non-regular special file")
	}
	if !strings.Contains(err.Error(), "not a regular file or directory") {
		t.Errorf("error = %v, want non-regular rejection", err)
	}
}
