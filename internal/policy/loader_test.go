package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestLoadBytes_Valid(t *testing.T) {
	ps, err := LoadBytes([]byte(`
version: v1
policies:
  - id: no-latest-tag
    name: No latest tag
    severity: high
    expression: 'true'
`))
	if err != nil {
		t.Fatalf("LoadBytes error = %v", err)
	}
	if len(ps.Policies) != 1 || ps.Policies[0].ID != "no-latest-tag" {
		t.Fatalf("unexpected parse: %+v", ps)
	}
}

func TestLoadBytes_Errors(t *testing.T) {
	cases := map[string]string{
		"bad yaml":        `policies: [::`,
		"unknown version": "version: v2\npolicies: []",
		"empty id":        "policies:\n  - id: ''\n    severity: low\n    expression: 'true'",
		"bad id chars":    "policies:\n  - id: 'Bad_ID'\n    severity: low\n    expression: 'true'",
		"leading dash id": "policies:\n  - id: '-x'\n    severity: low\n    expression: 'true'",
		"missing expr":    "policies:\n  - id: x\n    severity: low",
		"bad severity":    "policies:\n  - id: x\n    severity: nope\n    expression: 'true'",
		"duplicate id":    "policies:\n  - id: x\n    severity: low\n    expression: 'true'\n  - id: x\n    severity: low\n    expression: 'true'",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(doc)); err == nil {
				t.Errorf("expected error for %q", name)
			}
		})
	}
}

func TestLoadBytes_EmptySeverityDefaultsMedium(t *testing.T) {
	ps, err := LoadBytes([]byte("policies:\n  - id: x\n    expression: 'true'"))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	sev, err := ParseSeverity(ps.Policies[0].Severity)
	if err != nil || sev != checker.SeverityMedium {
		t.Errorf("empty severity: got %v err %v, want Medium", sev, err)
	}
}

func TestLoadFile_AndSizeLimit(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(good, []byte("policies:\n  - id: x\n    severity: low\n    expression: 'true'"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(good); err != nil {
		t.Fatalf("LoadFile good error = %v", err)
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, make([]byte, maxPolicyFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(big); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected size-limit error, got %v", err)
	}
}

func TestLoadDir_MergesAndRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	writeYAML := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeYAML("a.yaml", "policies:\n  - id: alpha\n    severity: low\n    expression: 'true'")
	writeYAML("b.yml", "policies:\n  - id: beta\n    severity: low\n    expression: 'true'")
	writeYAML("ignore.txt", "not a policy")

	ps, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir error = %v", err)
	}
	if len(ps.Policies) != 2 {
		t.Fatalf("got %d policies, want 2", len(ps.Policies))
	}

	writeYAML("c.yaml", "policies:\n  - id: alpha\n    severity: low\n    expression: 'true'")
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate error across files, got %v", err)
	}
}

func TestLoadDir_MissingDir(t *testing.T) {
	if _, err := LoadDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected error for missing dir")
	}
}
