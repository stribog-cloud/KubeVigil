// Package policy implements KubeVigil's custom policy engine: user-defined
// security checks expressed as CEL (Common Expression Language) expressions
// that evaluate against Kubernetes resources and produce findings through the
// same pipeline as the built-in checkers.
//
// A policy is authored in YAML (in .kubevigil.yaml under `customPolicies:` or
// a standalone `--policy-file`), compiled once, and adapted into the
// checker.Checker interface so it flows through severity overrides, exemptions,
// framework mapping, and every output format with no special-casing.
package policy

// SpecVersion is the current policy document schema version.
const SpecVersion = "v1"

// Set is a versioned collection of user-defined policies, as loaded from
// a policy file or the config's customPolicies block.
type Set struct {
	// Version is the policy schema version (currently "v1").
	Version string `yaml:"version" json:"version"`
	// Policies is the ordered list of user-defined policies.
	Policies []Spec `yaml:"policies" json:"policies"`
}

// Spec is a single user-defined CEL policy. It maps 1:1 onto a checker.Checker
// at scan time: ID becomes the check name, Expression is evaluated against each
// matching resource, and a truthy result yields a finding.
type Spec struct {
	// ID is the kebab-case unique identifier; becomes the finding's checker name.
	ID string `yaml:"id" json:"id"`
	// Name is a short human-readable title.
	Name string `yaml:"name" json:"name"`
	// Description explains what the policy detects.
	Description string `yaml:"description" json:"description"`
	// Severity is one of critical|high|medium|low|info (case-insensitive).
	Severity string `yaml:"severity" json:"severity"`
	// Category is a grouping label; defaults to "custom" when empty.
	Category string `yaml:"category" json:"category"`
	// Message is the finding message shown to the user. If empty, Name is used.
	Message string `yaml:"message" json:"message"`
	// Remediation describes how to fix a violation.
	Remediation string `yaml:"remediation" json:"remediation"`
	// Expression is a CEL expression evaluated with `object` bound to the
	// resource. A result of true indicates a VIOLATION (a finding is emitted).
	Expression string `yaml:"expression" json:"expression"`
	// Match constrains which resources the policy is evaluated against.
	Match Match `yaml:"match" json:"match"`
}

// Match constrains the set of resources a policy applies to. An empty Match
// means "evaluate against every resource type KubeVigil scans by default".
type Match struct {
	// Kinds restricts to these resource kinds (e.g. Deployment, Pod). Empty = any.
	Kinds []string `yaml:"kinds" json:"kinds"`
	// APIGroups restricts to these API groups (e.g. "apps", "" for core). Empty = any.
	APIGroups []string `yaml:"apiGroups" json:"apiGroups"`
	// Namespaces restricts to resources in these namespaces. Empty = any.
	Namespaces []string `yaml:"namespaces" json:"namespaces"`
}
