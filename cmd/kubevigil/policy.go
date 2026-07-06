package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/stribog-cloud/kubevigil/internal/policy"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Work with custom CEL policies",
	Long:  "Validate and inspect user-defined CEL security policies.",
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate <file|dir>",
	Short: "Compile-check a custom policy file or directory",
	Long: "Load, structurally validate, and CEL-compile every policy in the given " +
		"file or directory. Exits 0 if all policies are valid, 3 otherwise.",
	Args: cobra.ExactArgs(1),
	RunE: runPolicyValidate,
}

var policyListCmd = &cobra.Command{
	Use:   "list <file|dir>",
	Short: "List the policies defined in a file or directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyList,
}

func init() {
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyListCmd)
	rootCmd.AddCommand(policyCmd)
}

// loadPolicySet loads a policy file or directory.
func loadPolicySet(path string) (*policy.Set, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return policy.LoadDir(path)
	}
	return policy.LoadFile(path)
}

func runPolicyValidate(_ *cobra.Command, args []string) error {
	ps, err := loadPolicySet(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Policy error: %v\n", err)
		return &exitError{code: 3, err: err}
	}
	// Structural validation happens in the loader; Compile enforces CEL
	// correctness (parseable, type-checks to bool).
	if _, err := policy.Compile(ps); err != nil {
		fmt.Fprintf(os.Stderr, "Policy error: %v\n", err)
		return &exitError{code: 3, err: err}
	}
	fmt.Fprintf(os.Stdout, "OK: %d policies valid in %s\n", len(ps.Policies), args[0])
	return nil
}

func runPolicyList(_ *cobra.Command, args []string) error {
	ps, err := loadPolicySet(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Policy error: %v\n", err)
		return &exitError{code: 3, err: err}
	}
	fmt.Fprintf(os.Stdout, "%-28s %-10s %-14s %s\n", "ID", "SEVERITY", "CATEGORY", "NAME")
	for i := range ps.Policies {
		p := &ps.Policies[i]
		sev, _ := policy.ParseSeverity(p.Severity)
		cat := p.Category
		if cat == "" {
			cat = "custom"
		}
		fmt.Fprintf(os.Stdout, "%-28s %-10s %-14s %s\n", p.ID, sev.String(), cat, p.Name)
	}
	fmt.Fprintf(os.Stdout, "\nTotal: %d policies\n", len(ps.Policies))
	return nil
}
