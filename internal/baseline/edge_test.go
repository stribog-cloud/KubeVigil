package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestSave_ErrorOnBadPath(t *testing.T) {
	b := FromFindings([]checker.Finding{f("c", "Pod", "ns", "r", "")})
	// Writing into a nonexistent directory fails.
	err := b.Save(filepath.Join(t.TempDir(), "nope", "baseline.json"))
	if err == nil {
		t.Fatal("expected error writing to nonexistent directory")
	}
}

func TestLoad_Errors(t *testing.T) {
	dir := t.TempDir()

	// Missing file.
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected error for missing file")
	}

	// Invalid JSON.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("expected error for invalid JSON")
	}

	// Oversized file.
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, maxBaselineFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected size-limit error, got %v", err)
	}
}

func TestSave_DefaultsVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	b := &Baseline{Fingerprints: []string{"abc"}} // no version
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != SchemaVersion {
		t.Errorf("version = %q, want %q", loaded.Version, SchemaVersion)
	}
}
