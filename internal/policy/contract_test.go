package policy

import (
	"testing"

	"github.com/stribog-cloud/kubevigil/test/helpers"
)

// TestCelCheckers_SatisfyContract runs the standard checker contract suite
// against CEL-derived checkers to guarantee they are indistinguishable from
// built-in checkers to the scan pipeline (kebab-case name, non-empty
// description/categories/modes, empty-cache no-error, cancelled-context error).
func TestCelCheckers_SatisfyContract(t *testing.T) {
	set := &Set{Version: SpecVersion, Policies: []Spec{
		{ID: "custom-a", Name: "A", Severity: "high", Category: "workload", Expression: `object.kind == "Pod"`, Match: Match{Kinds: []string{"Pod"}}},
		{ID: "custom-b", Name: "B", Severity: "low", Expression: `has(object.metadata)`},
	}}
	checkers, err := Checkers(set)
	if err != nil {
		t.Fatalf("Checkers() error = %v", err)
	}
	helpers.RunCheckerContractTests(t, checkers)
}
