package pathguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultWorkspaceRoot_FromEnv(t *testing.T) {
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

func TestDefaultWorkspaceRoot_FallsBackToCwd(t *testing.T) {
	t.Setenv(WorkspaceRootEnv, "")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	got, err := DefaultWorkspaceRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != cwd {
		t.Errorf("got %q, want cwd %q", got, cwd)
	}
}
