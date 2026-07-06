package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func writeFile(t *testing.T, dir, name, body string) error {
	t.Helper()
	return os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
}

func TestCheckers_BadSeverityFails(t *testing.T) {
	// A structurally-loaded set can still carry a bad severity if constructed
	// directly (bypassing Validate); Checkers must reject it.
	ps := &Set{Policies: []Spec{{ID: "x", Severity: "nope", Expression: "true"}}}
	if _, err := Checkers(ps); err == nil {
		t.Fatal("expected error for bad severity")
	}
}

func TestNewCelChecker_BadSeverity(t *testing.T) {
	if _, err := newCelChecker(&compiled{spec: Spec{ID: "x", Severity: "nope"}}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDescription_EmptyNameAndDescription(t *testing.T) {
	c, err := newCelChecker(&compiled{spec: Spec{ID: "only-id", Severity: "low", Expression: "true"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Description() != "" {
		t.Errorf("Description() = %q, want empty when no name/description", c.Description())
	}
}

func TestRun_SkipsEvaluationErrors(t *testing.T) {
	// Expression errors at runtime on a resource missing the field; Run must
	// skip it (no finding, no error) rather than fail the scan.
	ps := &Set{Policies: []Spec{{
		ID: "deep", Severity: "low",
		Expression: `object.spec.template.spec.serviceAccountName == "bad"`,
		Match:      Match{Kinds: []string{"Deployment"}},
	}}}
	checkers, err := Checkers(ps)
	if err != nil {
		t.Fatal(err)
	}
	// Deployment without spec.template → evaluation error, skipped.
	bad := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "x", "namespace": "default"},
		"spec":     map[string]any{},
	}}
	findings, err := checkers[0].Run(context.Background(), cacheWith(bad))
	if err != nil {
		t.Fatalf("Run should not error on per-resource eval failure: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("evaluation error must not produce a finding, got %d", len(findings))
	}
}

func TestResolveGVRs_UnknownKindEmpty(t *testing.T) {
	if got := resolveGVRs(Match{Kinds: []string{"NoSuchKind"}}); len(got) != 0 {
		t.Errorf("unknown kind should resolve to nothing, got %v", got)
	}
}

func TestNewCelChecker_ZeroGVRsWarnsButSucceeds(t *testing.T) {
	// A policy whose kinds resolve to nothing (typo) still constructs — it just
	// warns and will never fire. Constructing it must not error.
	c, err := newCelChecker(&compiled{spec: Spec{
		ID: "typo", Severity: "low", Expression: "true",
		Match: Match{Kinds: []string{"Deploymnt"}}, // typo
	}})
	if err != nil {
		t.Fatalf("zero-GVR policy should still construct: %v", err)
	}
	if len(c.RequiredResources()) != 0 {
		t.Errorf("expected no resolved GVRs, got %v", c.RequiredResources())
	}
}

func TestDescription_PrefersExplicitDescription(t *testing.T) {
	c, err := newCelChecker(&compiled{spec: Spec{ID: "d", Name: "Name", Description: "Explicit desc", Severity: "low", Expression: "true"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Description() != "Explicit desc" {
		t.Errorf("Description() = %q, want explicit description", c.Description())
	}
}

func TestAsBool(t *testing.T) {
	env, err := newEnv()
	if err != nil {
		t.Fatal(err)
	}
	// bool result
	ast, _ := env.Compile("true")
	prog, _ := env.Program(ast)
	val, _, _ := prog.Eval(map[string]any{"object": map[string]any{}})
	if b, err := asBool(val); err != nil || !b {
		t.Errorf("asBool(true) = %v, %v", b, err)
	}
	// non-bool result must error
	ast2, _ := env.Compile(`"a string"`)
	prog2, _ := env.Program(ast2)
	val2, _, _ := prog2.Eval(map[string]any{"object": map[string]any{}})
	if _, err := asBool(val2); err == nil {
		t.Error("asBool on string should error")
	}
}

func TestLoadDir_PropagatesFileError(t *testing.T) {
	dir := t.TempDir()
	// A syntactically broken policy file in the dir should fail LoadDir.
	if err := writeFile(t, dir, "bad.yaml", "policies:\n  - id: x\n    severity: nope\n    expression: 'true'"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Error("expected LoadDir to propagate a bad-file error")
	}
}
