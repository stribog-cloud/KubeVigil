package checker

import (
	"testing"
)

// TestAllCheckersContract verifies that every registered checker meets the Checker
// interface contract. This test only runs if checkers are registered in this package's
// test binary. For the full contract test across all checker packages, see
// test/integration/contract_test.go.
func TestAllCheckersContract(t *testing.T) {
	checkers := DefaultRegistry().All()
	if len(checkers) == 0 {
		t.Skip("No checkers registered in this package — see test/integration/ for full contract test")
	}

	RunCheckerContractTests(t, checkers)
}
