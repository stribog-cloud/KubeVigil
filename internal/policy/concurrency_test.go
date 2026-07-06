package policy

import (
	"context"
	"sync"
	"testing"
)

func TestCelChecker_ConcurrentEvalNoRace(t *testing.T) {
	ps := &Set{Policies: []Spec{{
		ID: "conc", Severity: "low",
		Expression: `has(object.spec.replicas) && object.spec.replicas < 2`,
		Match:      Match{Kinds: []string{"Deployment"}},
	}}}
	checkers, err := Checkers(ps)
	if err != nil {
		t.Fatal(err)
	}
	cache := cacheWith(deployment("a", "default", 1), deployment("b", "default", 3))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := checkers[0].Run(context.Background(), cache); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
