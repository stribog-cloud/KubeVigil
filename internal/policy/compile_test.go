package policy

import (
	"strings"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestCompile_ValidAndInvalid(t *testing.T) {
	ps := &Set{Policies: []Spec{
		{ID: "ok", Severity: "low", Expression: `object.kind == "Pod"`},
	}}
	compiled, err := Compile(ps)
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("got %d compiled, want 1", len(compiled))
	}
}

func TestCompile_ReportsPolicyID(t *testing.T) {
	ps := &Set{Policies: []Spec{{ID: "broken", Severity: "low", Expression: `object.spec.replicas <`}}}
	_, err := Compile(ps)
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("error should name policy: %v", err)
	}
}

func TestEvaluate_RuntimeErrorNotViolation(t *testing.T) {
	// Accessing a missing field without has() is a runtime error, which must
	// surface as an error (never a silent violation).
	ps := &Set{Policies: []Spec{{ID: "risky", Severity: "low", Expression: `object.spec.missing.deep == 1`}}}
	compiled, err := Compile(ps)
	if err != nil {
		t.Fatalf("compile error = %v", err)
	}
	_, err = compiled[0].evaluate(map[string]any{"spec": map[string]any{}})
	if err == nil {
		t.Error("expected runtime evaluation error for missing field access")
	}
}

func TestResolveCategory(t *testing.T) {
	cases := map[string]checker.Category{
		"":         checker.CategoryCustom,
		"network":  checker.CategoryNetwork,
		"Workload": checker.CategoryWorkload,
		"nonsense": checker.CategoryCustom,
	}
	for in, want := range cases {
		if got := resolveCategory(in); got != want {
			t.Errorf("resolveCategory(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseSeverity_All(t *testing.T) {
	if _, err := ParseSeverity("critical"); err != nil {
		t.Errorf("critical should parse: %v", err)
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("bogus severity should error")
	}
}

func TestResolveGVRs_AllKindsWhenEmpty(t *testing.T) {
	all := resolveGVRs(Match{})
	if len(all) < 20 {
		t.Errorf("empty match should resolve to the broad known set, got %d", len(all))
	}
	// Group filter narrows.
	appsOnly := resolveGVRs(Match{APIGroups: []string{"apps"}})
	for _, gvr := range appsOnly {
		if gvr.Group != "apps" {
			t.Errorf("group filter leaked %v", gvr)
		}
	}
	if len(appsOnly) == 0 {
		t.Error("apps group should resolve some GVRs")
	}
}

func TestCelChecker_Metadata(t *testing.T) {
	c, err := newCelChecker(&compiled{spec: Spec{ID: "m", Name: "My Policy", Severity: "low", Category: "network", Expression: "true"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Description() != "My Policy" {
		t.Errorf("Description fallback = %q", c.Description())
	}
	if len(c.SupportedModes()) != 2 {
		t.Error("policies should support both scan modes")
	}
	if len(c.Categories()) != 1 || c.Categories()[0] != checker.CategoryNetwork {
		t.Errorf("category = %v", c.Categories())
	}
}
