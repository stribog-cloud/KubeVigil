package policy

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

var deploymentGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

func deployment(name, ns string, replicas int64) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec":       map[string]any{"replicas": replicas},
	}}
}

func cacheWith(objs ...unstructured.Unstructured) *checker.ResourceCache {
	c := checker.NewResourceCache()
	for _, o := range objs {
		c.Add(deploymentGVR, o)
	}
	c.Freeze()
	return c
}

func TestCelChecker_FlagsViolatingResource(t *testing.T) {
	ps := &Set{Version: SpecVersion, Policies: []Spec{{
		ID:          "min-replicas",
		Name:        "Deployments need >=2 replicas",
		Severity:    "high",
		Category:    "workload",
		Message:     "deployment has fewer than 2 replicas",
		Remediation: "set spec.replicas >= 2",
		Expression:  `has(object.spec.replicas) && object.spec.replicas < 2`,
		Match:       Match{Kinds: []string{"Deployment"}},
	}}}

	checkers, err := Checkers(ps)
	if err != nil {
		t.Fatalf("Checkers() error = %v", err)
	}
	if len(checkers) != 1 {
		t.Fatalf("got %d checkers, want 1", len(checkers))
	}
	c := checkers[0]

	if c.Name() != "min-replicas" {
		t.Errorf("Name() = %q, want min-replicas", c.Name())
	}
	if got := c.RequiredResources(); len(got) != 1 || got[0] != deploymentGVR {
		t.Errorf("RequiredResources() = %v, want [%v]", got, deploymentGVR)
	}

	cache := cacheWith(
		deployment("solo", "default", 1), // violates
		deployment("ha", "default", 3),   // ok
	)
	findings, err := c.Run(context.Background(), cache)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Resource != "solo" || f.Kind != "Deployment" || f.Namespace != "default" {
		t.Errorf("finding identity wrong: %+v", f)
	}
	if f.Severity != checker.SeverityHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	if f.Checker != "min-replicas" {
		t.Errorf("checker = %q", f.Checker)
	}
}

func TestCelChecker_NamespaceFilter(t *testing.T) {
	ps := &Set{Policies: []Spec{{
		ID:         "always",
		Severity:   "low",
		Expression: `true`,
		Match:      Match{Kinds: []string{"Deployment"}, Namespaces: []string{"prod"}},
	}}}
	checkers, err := Checkers(ps)
	if err != nil {
		t.Fatal(err)
	}
	cache := cacheWith(deployment("a", "prod", 1), deployment("b", "dev", 1))
	findings, err := checkers[0].Run(context.Background(), cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Namespace != "prod" {
		t.Fatalf("namespace filter failed: %+v", findings)
	}
}

func TestCheckers_BadExpressionFails(t *testing.T) {
	ps := &Set{Policies: []Spec{{ID: "bad", Severity: "low", Expression: `object.spec.replicas +`}}}
	if _, err := Checkers(ps); err == nil {
		t.Fatal("expected compile error for malformed CEL")
	}
}

func TestCheckers_NonBoolExpressionFails(t *testing.T) {
	ps := &Set{Policies: []Spec{{ID: "notbool", Severity: "low", Expression: `object.metadata.name`}}}
	if _, err := Checkers(ps); err == nil {
		t.Fatal("expected error for non-bool expression")
	}
}
