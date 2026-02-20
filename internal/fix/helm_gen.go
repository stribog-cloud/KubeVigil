package fix

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// HelmValuesOptions controls Helm values generation.
type HelmValuesOptions struct {
	// RiskLevel determines which fixes are included.
	RiskLevel RiskLevel
	// CommentOutBreaking when true (default) comments out potentially_breaking values.
	CommentOutBreaking bool
}

// DefaultHelmValuesOptions returns options with safe defaults.
func DefaultHelmValuesOptions() HelmValuesOptions {
	return HelmValuesOptions{
		RiskLevel:          RiskLevelSafe,
		CommentOutBreaking: true,
	}
}

// helmMapping defines how a check ID maps to a Helm values section.
type helmMapping struct {
	checkID string
	section string   // top-level group for ordering
	lines   []string // YAML lines (indented properly, relative to section)
	safety  checker.FixSafety
}

// sectionOrder defines the fixed output order for Helm value sections.
var sectionOrder = []string{
	"securityContext",
	"serviceAccount",
	"image",
	"resources",
}

// sectionIndex returns the sort index for a section name.
func sectionIndex(section string) int {
	for i, s := range sectionOrder {
		if s == section {
			return i
		}
	}
	return len(sectionOrder)
}

// defaultHelmMappings returns all built-in check ID to Helm value mappings.
func defaultHelmMappings() []helmMapping {
	return []helmMapping{
		{
			checkID: "privileged",
			section: "securityContext",
			lines:   []string{"  privileged: false"},
			safety:  checker.FixSafe,
		},
		{
			checkID: "privilege-escalation",
			section: "securityContext",
			lines:   []string{"  allowPrivilegeEscalation: false"},
			safety:  checker.FixSafe,
		},
		{
			checkID: "read-only-rootfs",
			section: "securityContext",
			lines:   []string{"  readOnlyRootFilesystem: true"},
			safety:  checker.FixLikelySafe,
		},
		{
			checkID: "run-as-root",
			section: "securityContext",
			lines:   []string{"  runAsNonRoot: true"},
			safety:  checker.FixLikelySafe,
		},
		{
			checkID: "capabilities-not-dropped",
			section: "securityContext",
			lines: []string{
				"  capabilities:",
				"    drop:",
				"      - ALL",
			},
			safety: checker.FixLikelySafe,
		},
		{
			checkID: "seccomp-profile",
			section: "securityContext",
			lines: []string{
				"  seccompProfile:",
				"    type: RuntimeDefault",
			},
			safety: checker.FixLikelySafe,
		},
		{
			checkID: "automount-token",
			section: "serviceAccount",
			lines:   []string{"  automountServiceAccountToken: false"},
			safety:  checker.FixSafe,
		},
		{
			checkID: "image-pull-policy",
			section: "image",
			lines:   []string{"  pullPolicy: Always"},
			safety:  checker.FixLikelySafe,
		},
		{
			checkID: "resource-limits-missing",
			section: "resources",
			lines: []string{
				"  limits:",
				"    cpu: 500m",
				"    memory: 256Mi",
			},
			safety: checker.FixPotentiallyBreaking,
		},
		{
			checkID: "resource-requests-missing",
			section: "resources",
			lines: []string{
				"  requests:",
				"    cpu: 100m",
				"    memory: 128Mi",
			},
			safety: checker.FixPotentiallyBreaking,
		},
	}
}

// GenerateHelmValues produces a security-values.yaml content from applied fixes in the plan.
func GenerateHelmValues(plan *Plan, opts HelmValuesOptions) ([]byte, error) {
	if plan == nil {
		return nil, fmt.Errorf("plan must not be nil")
	}

	// Collect applied check IDs (deduplicate).
	appliedChecks := make(map[string]bool)
	for i := range plan.Summary.Results {
		if plan.Summary.Results[i].Applied {
			appliedChecks[plan.Summary.Results[i].CheckID] = true
		}
	}

	// Filter mappings to only those with applied results.
	allMappings := defaultHelmMappings()
	var active []helmMapping
	for _, m := range allMappings {
		if appliedChecks[m.checkID] {
			active = append(active, m)
		}
	}

	// Group mappings by section.
	sectionMappings := make(map[string][]helmMapping)
	for _, m := range active {
		sectionMappings[m.section] = append(sectionMappings[m.section], m)
	}

	// Determine ordered sections.
	var sections []string
	seen := make(map[string]bool)
	for _, m := range active {
		if !seen[m.section] {
			seen[m.section] = true
			sections = append(sections, m.section)
		}
	}
	sort.Slice(sections, func(i, j int) bool {
		return sectionIndex(sections[i]) < sectionIndex(sections[j])
	})

	var b strings.Builder

	// Write header.
	writeHelmHeader(&b, opts.RiskLevel)

	// Write each section.
	for i, section := range sections {
		if i > 0 {
			b.WriteString("\n")
		}

		mappings := sectionMappings[section]

		// Check if all mappings in this section are potentially_breaking and should be commented.
		allBreaking := true
		for _, m := range mappings {
			if m.safety != checker.FixPotentiallyBreaking {
				allBreaking = false
				break
			}
		}

		commented := allBreaking && opts.CommentOutBreaking

		if commented {
			writeSectionCommented(&b, section, mappings)
		} else {
			writeSection(&b, section, mappings)
		}
	}

	return []byte(b.String()), nil
}

// writeHelmHeader writes the YAML comment header for Helm values output.
func writeHelmHeader(b *strings.Builder, riskLevel RiskLevel) {
	b.WriteString("# KubeVigil Security Values\n")
	b.WriteString("# Generated for Helm chart hardening\n")
	fmt.Fprintf(b, "# Risk level: %s\n", string(riskLevel))
	b.WriteString("#\n")
	b.WriteString("# Usage: helm upgrade <release> <chart> -f security-values.yaml\n")
	b.WriteString("\n")
}

// writeSectionComment writes a human-readable comment for a section.
func writeSectionComment(b *strings.Builder, section string) {
	switch section {
	case "securityContext":
		b.WriteString("# Security Context\n")
	case "serviceAccount":
		b.WriteString("# Service Account\n")
	case "image":
		b.WriteString("# Image\n")
	case "resources":
		b.WriteString("# Resources\n")
	default:
		fmt.Fprintf(b, "# %s\n", section)
	}
}

// writeSection writes an uncommented section with its mappings.
func writeSection(b *strings.Builder, section string, mappings []helmMapping) {
	writeSectionComment(b, section)
	fmt.Fprintf(b, "%s:\n", section)
	for _, m := range mappings {
		for _, line := range m.lines {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
}

// writeSectionCommented writes a commented-out section with a warning.
func writeSectionCommented(b *strings.Builder, section string, mappings []helmMapping) {
	fmt.Fprintf(b, "# %s (potentially breaking - verify before applying)\n", sectionDisplayName(section))
	fmt.Fprintf(b, "# %s:\n", section)
	for _, m := range mappings {
		for _, line := range m.lines {
			b.WriteString("# ")
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
}

// sectionDisplayName returns a human-readable name for a section.
func sectionDisplayName(section string) string {
	switch section {
	case "securityContext":
		return "Security Context"
	case "serviceAccount":
		return "Service Account"
	case "image":
		return "Image"
	case "resources":
		return "Resources"
	default:
		return section
	}
}

// WriteHelmValues generates and writes Helm values to the given path.
func WriteHelmValues(plan *Plan, opts HelmValuesOptions, path string) error {
	data, err := GenerateHelmValues(plan, opts)
	if err != nil {
		return fmt.Errorf("generating helm values: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // Helm values file; world-readable is intentional.
		return fmt.Errorf("writing helm values to %s: %w", path, err)
	}

	return nil
}
