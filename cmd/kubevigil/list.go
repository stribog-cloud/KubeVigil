package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available resources",
}

var listChecksCmd = &cobra.Command{
	Use:   "checks",
	Short: "List all available security checks",
	RunE:  runListChecks,
}

func init() {
	listCmd.AddCommand(listChecksCmd)
	rootCmd.AddCommand(listCmd)
}

func runListChecks(_ *cobra.Command, _ []string) error {
	all := checker.DefaultRegistry().All()

	// Print header.
	fmt.Fprintf(os.Stdout, "%-30s %-14s %-18s %s\n", "ID", "CATEGORY", "MODES", "DESCRIPTION")
	fmt.Fprintf(os.Stdout, "%-30s %-14s %-18s %s\n",
		strings.Repeat("-", 30),
		strings.Repeat("-", 14),
		strings.Repeat("-", 18),
		strings.Repeat("-", 40),
	)

	for _, c := range all {
		categories := formatCategories(c.Categories())
		modes := formatModes(c.SupportedModes())
		fmt.Fprintf(os.Stdout, "%-30s %-14s %-18s %s\n", c.Name(), categories, modes, c.Description())
	}

	fmt.Fprintf(os.Stdout, "\nTotal: %d checks\n", len(all))
	return nil
}

// formatCategories joins category names with commas.
func formatCategories(cats []checker.Category) string {
	names := make([]string, len(cats))
	for i, c := range cats {
		names[i] = c.String()
	}
	return strings.Join(names, ", ")
}

// formatModes joins scan mode names with commas.
func formatModes(modes []checker.ScanMode) string {
	names := make([]string, len(modes))
	for i, m := range modes {
		names[i] = m.String()
	}
	return strings.Join(names, ", ")
}
