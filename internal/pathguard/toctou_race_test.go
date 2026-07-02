package pathguard

import (
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestOpenRegularWithinRoot_RejectsParentSymlinkToOutside(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.yaml")
	if err := os.WriteFile(secret, []byte("stolen"), 0o644); err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(root, "sub")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "pod.yaml"), []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(subDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, subDir); err != nil {
		t.Fatal(err)
	}

	_, err := OpenRegularWithinRoot(root, filepath.Join("sub", "pod.yaml"))
	if err == nil {
		t.Fatal("expected rejection when parent directory is a symlink to outside workspace")
	}
}

func TestOpenRegularWithinRoot_RejectsConcurrentParentSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.yaml")
	if err := os.WriteFile(secret, []byte("stolen"), 0o644); err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(root, "sub")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(subDir, "pod.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	relPath := filepath.Join("sub", "pod.yaml")
	done := make(chan struct{})
	defer close(done)

	var swaps atomic.Uint64
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				_ = os.RemoveAll(subDir)
				_ = os.Symlink(outside, subDir)
				swaps.Add(1)
				_ = os.Remove(subDir)
				_ = os.Mkdir(subDir, 0o755)
				_ = os.WriteFile(manifest, []byte("apiVersion: v1\n"), 0o644)
				swaps.Add(1)
			}
		}
	}()

	for i := 0; i < 2000; i++ {
		f, err := OpenRegularWithinRoot(root, relPath)
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(f)
		_ = f.Close()
		if readErr != nil {
			continue
		}
		if string(data) == "stolen" {
			t.Fatalf("read escaped workspace via parent symlink race (swap attempts=%d)", swaps.Load())
		}
	}
	if swaps.Load() == 0 {
		t.Fatal("concurrent swap goroutine did not run; race window not exercised")
	}
}
