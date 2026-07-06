package vuln

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Package is a single software component extracted from an SBOM, identified by
// its package URL (purl). Name and Version are carried for human-readable
// reporting; Purl is the key used to query OSV.dev.
type Package struct {
	// Purl is the package URL (e.g. "pkg:golang/github.com/foo/bar@1.2.3").
	Purl string
	// Name is the component name from the SBOM.
	Name string
	// Version is the component version from the SBOM.
	Version string
}

// spdxDocument is the minimal subset of the SPDX 2.x JSON schema we need.
type spdxDocument struct {
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

// cyclonedxDocument is the minimal subset of the CycloneDX JSON schema we need.
type cyclonedxDocument struct {
	BOMFormat  string `json:"bomFormat"`
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"components"`
}

// ParseSBOM extracts the package inventory from an SPDX or CycloneDX JSON
// document. The format is auto-detected from the payload. Only components that
// carry a package URL (purl) are returned, since the purl is what OSV.dev
// matches on; components without one cannot be checked for vulnerabilities and
// are skipped. The result is deduplicated by purl and returned in a stable
// order so scans are reproducible.
func ParseSBOM(data []byte) ([]Package, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("parsing SBOM: empty document")
	}

	// Detect the format from marker fields rather than trusting a file
	// extension. SPDX has "spdxVersion"; CycloneDX has "bomFormat":"CycloneDX".
	var probe struct {
		SPDXVersion string `json:"spdxVersion"`
		BOMFormat   string `json:"bomFormat"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	switch {
	case probe.SPDXVersion != "":
		return parseSPDX(data)
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		return parseCycloneDX(data)
	default:
		return nil, fmt.Errorf("parsing SBOM: unrecognized format (need SPDX 'spdxVersion' or CycloneDX 'bomFormat')")
	}
}

func parseSPDX(data []byte) ([]Package, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing SPDX SBOM: %w", err)
	}
	seen := map[string]Package{}
	for i := range doc.Packages {
		p := &doc.Packages[i]
		for _, ref := range p.ExternalRefs {
			if !strings.EqualFold(ref.ReferenceType, "purl") {
				continue
			}
			purl := strings.TrimSpace(ref.ReferenceLocator)
			if purl == "" {
				continue
			}
			seen[purl] = Package{Purl: purl, Name: p.Name, Version: p.VersionInfo}
		}
	}
	return sortedPackages(seen), nil
}

func parseCycloneDX(data []byte) ([]Package, error) {
	var doc cyclonedxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing CycloneDX SBOM: %w", err)
	}
	seen := map[string]Package{}
	for _, comp := range doc.Components {
		purl := strings.TrimSpace(comp.Purl)
		if purl == "" {
			continue
		}
		seen[purl] = Package{Purl: purl, Name: comp.Name, Version: comp.Version}
	}
	return sortedPackages(seen), nil
}

// sortedPackages returns the deduplicated packages ordered by purl for
// reproducible scans.
func sortedPackages(seen map[string]Package) []Package {
	out := make([]Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Purl < out[j].Purl })
	return out
}
