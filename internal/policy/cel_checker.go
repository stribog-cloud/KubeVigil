package policy

import (
	"context"
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// celChecker adapts a compiled CEL policy to the checker.Checker interface so
// user-defined policies flow through the identical scan pipeline as built-in
// checkers: severity overrides, exemptions, framework mapping, and every output
// format apply with no special-casing.
type celChecker struct {
	compiled compiled
	severity checker.Severity
	category checker.Category
	gvrs     []schema.GroupVersionResource
	nsFilter map[string]struct{} // empty => all namespaces
}

// Checkers compiles a Set and returns one checker.Checker per policy,
// ready to register into a checker.Registry. Compilation errors (bad CEL,
// unknown severity) are returned so callers can fail cleanly.
func Checkers(ps *Set) ([]checker.Checker, error) {
	compiledPolicies, err := Compile(ps)
	if err != nil {
		return nil, err
	}
	out := make([]checker.Checker, 0, len(compiledPolicies))
	for i := range compiledPolicies {
		c, err := newCelChecker(&compiledPolicies[i])
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func newCelChecker(cp *compiled) (*celChecker, error) {
	sev, err := ParseSeverity(cp.spec.Severity)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", cp.spec.ID, err)
	}

	cc := &celChecker{
		compiled: *cp,
		severity: sev,
		category: resolveCategory(cp.spec.Category),
		nsFilter: toSet(cp.spec.Match.Namespaces),
	}
	cc.gvrs = resolveGVRs(cp.spec.Match)
	if len(cc.gvrs) == 0 {
		// A policy that resolves to no resource types (e.g. a typo in
		// match.kinds) will silently never fire — a false negative that is
		// easy to miss in a security tool. Warn rather than fail: the policy
		// may legitimately target kinds not present in this scan.
		slog.Warn("custom policy matches no known resource types; it will never fire",
			"policy", cp.spec.ID, "kinds", cp.spec.Match.Kinds, "apiGroups", cp.spec.Match.APIGroups)
	}
	return cc, nil
}

// resolveGVRs turns a policy's match block into the resource types it scans.
// With no kinds specified, the policy applies to every resource KubeVigil
// knows about; with kinds, it resolves each to its known GVR(s), optionally
// narrowed by API group.
func resolveGVRs(m Match) []schema.GroupVersionResource {
	if len(m.Kinds) == 0 {
		return filterByGroup(checker.AllKnownGVRs(), m.APIGroups)
	}
	seen := make(map[schema.GroupVersionResource]struct{})
	var out []schema.GroupVersionResource
	for _, kind := range m.Kinds {
		for _, gvr := range checker.GVRsForKind(kind) {
			if _, ok := seen[gvr]; ok {
				continue
			}
			seen[gvr] = struct{}{}
			out = append(out, gvr)
		}
	}
	return filterByGroup(out, m.APIGroups)
}

func filterByGroup(gvrs []schema.GroupVersionResource, groups []string) []schema.GroupVersionResource {
	if len(groups) == 0 {
		return gvrs
	}
	want := toSet(groups)
	out := gvrs[:0:0]
	for _, gvr := range gvrs {
		if _, ok := want[gvr.Group]; ok {
			out = append(out, gvr)
		}
	}
	return out
}

// Name returns the policy ID (used as the finding's checker name).
func (c *celChecker) Name() string { return c.compiled.spec.ID }

// Description returns the policy description, falling back to its name.
func (c *celChecker) Description() string {
	if c.compiled.spec.Description != "" {
		return c.compiled.spec.Description
	}
	return c.compiled.spec.Name
}

// Categories returns the policy's category.
func (c *celChecker) Categories() []checker.Category { return []checker.Category{c.category} }

// SupportedModes: custom policies run in both manifest and live scans.
func (c *celChecker) SupportedModes() []checker.ScanMode {
	return []checker.ScanMode{checker.ScanModeManifest, checker.ScanModeLive}
}

// RequiredResources returns the GVRs this policy needs fetched/parsed.
func (c *celChecker) RequiredResources() []schema.GroupVersionResource { return c.gvrs }

// Run evaluates the policy against every matching resource in the cache and
// emits a finding for each violation. Per-resource evaluation errors are logged
// and skipped (never treated as violations) so one malformed resource cannot
// fail an entire scan.
func (c *celChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var findings []checker.Finding
	for _, gvr := range c.gvrs {
		for _, res := range resources.List(gvr) {
			if !c.matchesNamespace(res) {
				continue
			}
			violated, err := c.compiled.evaluate(res.Object)
			if err != nil {
				slog.Debug("custom policy evaluation error",
					"policy", c.compiled.spec.ID,
					"resource", res.GetName(),
					"error", err)
				continue
			}
			if violated {
				findings = append(findings, c.finding(res))
			}
		}
	}
	return findings, nil
}

func (c *celChecker) matchesNamespace(res unstructured.Unstructured) bool {
	if len(c.nsFilter) == 0 {
		return true
	}
	_, ok := c.nsFilter[res.GetNamespace()]
	return ok
}

func (c *celChecker) finding(res unstructured.Unstructured) checker.Finding {
	msg := c.compiled.spec.Message
	if msg == "" {
		msg = c.compiled.spec.Name
	}
	return checker.Finding{
		Checker:     c.compiled.spec.ID,
		Severity:    c.severity,
		Resource:    res.GetName(),
		Namespace:   res.GetNamespace(),
		Kind:        res.GetKind(),
		Message:     msg,
		Remediation: c.compiled.spec.Remediation,
	}
}

func toSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}
