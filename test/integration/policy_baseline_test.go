package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/baseline"
	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
	"github.com/stribog-cloud/kubevigil/internal/policy"
)

const celDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: unlabeled
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
`

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func policyRegistry(t *testing.T) *checker.Registry {
	t.Helper()
	reg := checker.NewRegistry()
	checkers, err := policy.Checkers(&policy.Set{Version: policy.SpecVersion, Policies: []policy.Spec{{
		ID:         "require-team-label",
		Name:       "team label required",
		Severity:   "medium",
		Category:   "workload",
		Message:    "missing team label",
		Expression: `!has(object.metadata.labels) || !("team" in object.metadata.labels)`,
		Match:      policy.Match{Kinds: []string{"Deployment"}},
	}}})
	if err != nil {
		t.Fatalf("compiling policy: %v", err)
	}
	for _, c := range checkers {
		if err := reg.Register(c); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

// TestCustomPolicy_FlowsThroughEngine proves a CEL policy runs in the real
// scan engine and produces a finding.
func TestCustomPolicy_FlowsThroughEngine(t *testing.T) {
	path := writeManifest(t, celDeployment)
	scanner := engine.NewScanner(policyRegistry(t), config.Default())

	result, err := scanner.ScanManifest(context.Background(), path)
	if err != nil {
		t.Fatalf("scan error = %v", err)
	}
	if countChecker(result.Findings, "require-team-label") != 1 {
		t.Fatalf("expected 1 custom-policy finding, got %d", countChecker(result.Findings, "require-team-label"))
	}
}

// TestCustomPolicy_RespectsExemptions proves exemptions apply to CEL findings
// identically to built-in checks — the pipeline treats them uniformly.
func TestCustomPolicy_RespectsExemptions(t *testing.T) {
	path := writeManifest(t, celDeployment)
	cfg := config.Default()
	cfg.Exemptions = []config.Exemption{{
		Namespace: "default",
		Reason:    "test",
	}}
	scanner := engine.NewScanner(policyRegistry(t), cfg)

	result, err := scanner.ScanManifest(context.Background(), path)
	if err != nil {
		t.Fatalf("scan error = %v", err)
	}
	if got := countChecker(result.Findings, "require-team-label"); got != 0 {
		t.Errorf("exemption should suppress custom-policy finding, got %d", got)
	}
}

// TestBaseline_AnnotatesEngineFindings proves baseline classification works on
// real engine output end-to-end.
func TestBaseline_AnnotatesEngineFindings(t *testing.T) {
	path := writeManifest(t, celDeployment)
	scanner := engine.NewScanner(policyRegistry(t), config.Default())
	result, err := scanner.ScanManifest(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}

	base := baseline.FromFindings(result.Findings)
	// A second identical scan should classify everything as existing.
	result2, err := scanner.ScanManifest(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	diff := baseline.Annotate(base, result2.Findings)
	if diff.New != 0 || diff.Resolved != 0 {
		t.Errorf("identical rescan drift = %+v, want no new/resolved", diff)
	}
	if diff.Existing == 0 {
		t.Error("expected existing findings after identical rescan")
	}
}

func countChecker(findings []checker.Finding, name string) int {
	n := 0
	for i := range findings {
		if findings[i].Checker == name {
			n++
		}
	}
	return n
}
