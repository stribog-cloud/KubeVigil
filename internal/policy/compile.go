package policy

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// evalCostLimit bounds the cost of a single CEL evaluation. It prevents a
// pathological user expression (deep comprehensions over large objects) from
// consuming unbounded CPU during a scan. The limit is generous for typical
// resource-shape checks but finite.
const evalCostLimit = uint64(1_000_000)

// objectVar is the CEL variable name bound to each resource's object map.
const objectVar = "object"

// newEnv constructs the CEL environment shared by all compiled policies.
// It exposes a single variable, `object`, holding the resource as a dynamic
// map (the unstructured `.Object`). Expressions are pure (CEL has no side
// effects) and bounded by evalCostLimit at program-construction time.
func newEnv() (*cel.Env, error) {
	env, err := cel.NewEnv(
		cel.Variable(objectVar, cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("building CEL environment: %w", err)
	}
	return env, nil
}

// compiled is a policy whose CEL expression has been type-checked and turned
// into an executable program. It is safe for concurrent evaluation.
type compiled struct {
	spec Spec
	prog cel.Program
}

// Compile type-checks and compiles every policy in the set against a shared CEL
// environment. It returns an error identifying the first policy that fails to
// compile (used by `policy validate`). A successfully compiled policy's
// expression is guaranteed to produce a boolean.
func Compile(ps *Set) ([]compiled, error) {
	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	out := make([]compiled, 0, len(ps.Policies))
	for i := range ps.Policies {
		spec := ps.Policies[i]
		prog, err := compileExpr(env, spec.Expression)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", spec.ID, err)
		}
		out = append(out, compiled{spec: spec, prog: prog})
	}
	return out, nil
}

// compileExpr parses, type-checks (requiring a bool result), and compiles a
// single CEL expression.
func compileExpr(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("compiling expression: %w", iss.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("expression must evaluate to bool, got %s", ast.OutputType())
	}
	prog, err := env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(evalCostLimit),
	)
	if err != nil {
		return nil, fmt.Errorf("constructing program: %w", err)
	}
	return prog, nil
}

// evaluate runs the compiled program against a single resource object. A result
// of true means the policy is VIOLATED. Evaluation errors (e.g. a field access
// on a missing key without a guard) are returned to the caller so the checker
// can decide how to surface them; they are never treated as violations.
func (c *compiled) evaluate(object map[string]any) (bool, error) {
	val, _, err := c.prog.Eval(map[string]any{objectVar: object})
	if err != nil {
		return false, fmt.Errorf("evaluating policy %q: %w", c.spec.ID, err)
	}
	return asBool(val)
}

// asBool converts a CEL ref.Val to a Go bool, erroring on any non-bool result
// (compilation already guarantees bool, but guard against runtime dyn cases).
func asBool(val ref.Val) (bool, error) {
	b, ok := val.Value().(bool)
	if !ok {
		if val.Type() == types.BoolType {
			return val.Value() == true, nil
		}
		return false, fmt.Errorf("policy result is %s, not bool", val.Type())
	}
	return b, nil
}
