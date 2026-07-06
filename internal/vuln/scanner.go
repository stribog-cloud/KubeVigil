package vuln

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// CheckerID is the synthetic checker name carried by vulnerability findings so
// they are distinguishable from posture findings in every report format. It is
// deliberately not a registered checker (it produces no posture rule), so the
// built-in check catalogue count is unaffected.
const CheckerID = "image-vulnerability"

// Scanner turns an SBOM package inventory into vulnerability findings by
// resolving each package against an OSVClient.
type Scanner struct {
	client OSVClient
}

// NewScanner constructs a vulnerability scanner over the given client.
func NewScanner(client OSVClient) *Scanner {
	return &Scanner{client: client}
}

// ScanOptions configures a vulnerability scan.
type ScanOptions struct {
	// Image is the container image reference the SBOM describes; it is recorded
	// on every finding so results can be attributed to the image. Optional.
	Image string
	// MinSeverity drops vulnerabilities below this severity from the results.
	// The zero value (SeverityInfo) keeps everything.
	MinSeverity checker.Severity
}

// Scan resolves the packages against the vulnerability database and returns one
// finding per (package, vulnerability) pair, ordered most-severe first. It
// returns an error only when the underlying client fails; an empty package list
// yields no findings and no error.
func (s *Scanner) Scan(ctx context.Context, packages []Package, opts ScanOptions) ([]checker.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	resolved, err := s.client.Resolve(ctx, packages)
	if err != nil {
		return nil, fmt.Errorf("resolving vulnerabilities: %w", err)
	}

	byPurl := map[string]Package{}
	for _, p := range packages {
		byPurl[p.Purl] = p
	}

	var findings []checker.Finding
	for purl, vulns := range resolved {
		pkg := byPurl[purl]
		for i := range vulns {
			v := &vulns[i]
			if v.Severity < opts.MinSeverity {
				continue
			}
			findings = append(findings, buildFinding(pkg, v, opts.Image))
		}
	}
	sortFindings(findings)
	return findings, nil
}

// buildFinding renders a single vulnerability as a fused posture-style finding.
func buildFinding(pkg Package, v *Vulnerability, image string) checker.Finding {
	displayID := primaryID(v)
	resource := image
	if resource == "" {
		resource = pkg.Name
	}

	var msg strings.Builder
	fmt.Fprintf(&msg, "%s in %s", displayID, pkg.Name)
	if pkg.Version != "" {
		fmt.Fprintf(&msg, "@%s", pkg.Version)
	}
	if v.Summary != "" {
		fmt.Fprintf(&msg, ": %s", strings.TrimRight(v.Summary, "."))
	}
	fmt.Fprintf(&msg, ".")
	if v.CVSS > 0 {
		fmt.Fprintf(&msg, " CVSS %.1f.", v.CVSS)
	}
	if v.FixedVersion != "" {
		fmt.Fprintf(&msg, " Fixed in %s.", v.FixedVersion)
	} else {
		msg.WriteString(" No fixed version is published.")
	}

	remediation := buildRemediation(pkg, v)

	return checker.Finding{
		Checker:      CheckerID,
		Severity:     v.Severity,
		Resource:     resource,
		Kind:         "ContainerImage",
		Container:    pkg.Name,
		Message:      msg.String(),
		Remediation:  remediation,
		FieldPath:    pkg.Purl,
		CurrentValue: pkg.Version,
		DesiredValue: v.FixedVersion,
		CVE: &checker.CVEInfo{
			ID:           v.ID,
			Aliases:      v.Aliases,
			Package:      pkg.Name,
			Version:      pkg.Version,
			FixedVersion: v.FixedVersion,
			CVSS:         v.CVSS,
			Vector:       v.Vector,
			Purl:         pkg.Purl,
			Image:        image,
		},
	}
}

func buildRemediation(pkg Package, v *Vulnerability) string {
	var b strings.Builder
	b.WriteString("## Why This Matters\n\n")
	fmt.Fprintf(&b, "The image ships %s", pkg.Name)
	if pkg.Version != "" {
		fmt.Fprintf(&b, " %s", pkg.Version)
	}
	fmt.Fprintf(&b, ", which is affected by %s.", primaryID(v))
	if v.Summary != "" {
		fmt.Fprintf(&b, " %s.", strings.TrimRight(v.Summary, "."))
	}
	b.WriteString("\n\n## How to Fix\n\n")
	if v.FixedVersion != "" {
		fmt.Fprintf(&b, "Rebuild the image with %s upgraded to %s or later, then re-push and roll out the new digest.\n",
			pkg.Name, v.FixedVersion)
	} else {
		fmt.Fprintf(&b, "No fixed version is published yet. Track %s, apply a vendor mitigation, or remove the package if it is not required.\n",
			primaryID(v))
	}
	b.WriteString("\n## Learn More\n\n")
	fmt.Fprintf(&b, "OSV advisory: https://osv.dev/vulnerability/%s\n", v.ID)
	return b.String()
}

// primaryID prefers a CVE identifier for display: OSV records are often keyed by
// a GHSA/DSA id while the CVE alias is what users recognise.
func primaryID(v *Vulnerability) string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// sortFindings orders findings most-severe first, then by resource and message
// for stable, reproducible output.
func sortFindings(findings []checker.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].Resource != findings[j].Resource {
			return findings[i].Resource < findings[j].Resource
		}
		return findings[i].Message < findings[j].Message
	})
}
