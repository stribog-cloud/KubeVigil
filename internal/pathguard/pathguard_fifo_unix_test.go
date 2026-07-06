//go:build !windows

package pathguard

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOpenRegularWithinRoot_RejectsFifoInsideRoot(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo not supported: %v", err)
	}

	_, err := OpenRegularWithinRoot(root, "pipe")
	if err == nil {
		t.Fatal("expected error opening fifo as regular file")
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
