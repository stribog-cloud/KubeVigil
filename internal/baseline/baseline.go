// Package baseline implements finding baselining and drift detection for
// KubeVigil. A baseline is a versioned snapshot of the finding identities from
// a scan; a later scan can be compared against it to classify each finding as
// new or existing and to report resolved findings. This powers CI gates that
// fail only on NEW findings ("--fail-on-new") and "what changed since last
// scan" reporting, without a database — the baseline is a portable JSON file.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// SchemaVersion is the baseline file format version.
const SchemaVersion = "v1"

// Status values assigned to findings after a baseline comparison.
const (
	StatusNew      = "new"
	StatusExisting = "existing"
)

// maxBaselineFileSize bounds a baseline file read (guards against a malformed
// or hostile file exhausting memory).
const maxBaselineFileSize = 16 << 20 // 16 MiB

// Baseline is a portable snapshot of finding identities from a scan.
type Baseline struct {
	// Version is the baseline schema version.
	Version string `json:"version"`
	// CreatedAt is an RFC3339 timestamp; set by the caller (stamped after the
	// scan, since the engine has no wall clock during a deterministic run).
	CreatedAt string `json:"created_at,omitempty"`
	// ToolVersion records the KubeVigil version that produced the baseline.
	ToolVersion string `json:"tool_version,omitempty"`
	// Fingerprints is the sorted, de-duplicated set of finding identities.
	Fingerprints []string `json:"fingerprints"`
}

// Fingerprint returns a stable identity for a finding, independent of its
// message, severity, or the ordering of a scan. Two findings share a
// fingerprint iff they are the same check on the same resource+container — the
// logical "same problem" across scans. FieldPath is deliberately excluded
// because array indices in a path can shift between otherwise-identical scans.
func Fingerprint(f *checker.Finding) string {
	// Pipe-join identity fields; the fields themselves never contain a newline,
	// and a null separator disambiguates empty components from each other.
	id := strings.Join([]string{
		f.Checker,
		f.Kind,
		f.Namespace,
		f.Resource,
		f.Container,
	}, "\x00")
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// FromFindings builds a baseline from a set of findings.
func FromFindings(findings []checker.Finding) *Baseline {
	set := make(map[string]struct{}, len(findings))
	for i := range findings {
		set[Fingerprint(&findings[i])] = struct{}{}
	}
	fps := make([]string, 0, len(set))
	for fp := range set {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	return &Baseline{Version: SchemaVersion, Fingerprints: fps}
}

// Save writes the baseline as indented JSON to path.
func (b *Baseline) Save(path string) error {
	if b.Version == "" {
		b.Version = SchemaVersion
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing baseline %q: %w", path, err)
	}
	return nil
}

// Load reads and validates a baseline file.
func Load(path string) (*Baseline, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline %q: %w", path, err)
	}
	if info.Size() > maxBaselineFileSize {
		return nil, fmt.Errorf("baseline file %q exceeds %d bytes", path, maxBaselineFileSize)
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path, size-capped above
	if err != nil {
		return nil, fmt.Errorf("reading baseline %q: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline %q: %w", path, err)
	}
	if b.Version != "" && b.Version != SchemaVersion {
		return nil, fmt.Errorf("unsupported baseline version %q (want %q)", b.Version, SchemaVersion)
	}
	return &b, nil
}

// set returns the baseline fingerprints as a lookup set.
func (b *Baseline) set() map[string]struct{} {
	m := make(map[string]struct{}, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		m[fp] = struct{}{}
	}
	return m
}

// DiffResult summarizes a comparison of current findings against a baseline.
type DiffResult struct {
	// New is the count of findings not present in the baseline.
	New int
	// Existing is the count of findings present in the baseline.
	Existing int
	// Resolved is the count of baseline fingerprints absent from the current scan.
	Resolved int
	// ResolvedFingerprints lists the baseline entries no longer present.
	ResolvedFingerprints []string
}

// Annotate sets each finding's Status to "new" or "existing" relative to the
// baseline and returns a summary including resolved (fixed) findings. The
// findings slice is mutated in place.
func Annotate(b *Baseline, findings []checker.Finding) DiffResult {
	baseSet := b.set()
	currentSet := make(map[string]struct{}, len(findings))
	var res DiffResult
	for i := range findings {
		fp := Fingerprint(&findings[i])
		currentSet[fp] = struct{}{}
		if _, ok := baseSet[fp]; ok {
			findings[i].Status = StatusExisting
			res.Existing++
		} else {
			findings[i].Status = StatusNew
			res.New++
		}
	}
	for _, fp := range b.Fingerprints {
		if _, ok := currentSet[fp]; !ok {
			res.Resolved++
			res.ResolvedFingerprints = append(res.ResolvedFingerprints, fp)
		}
	}
	sort.Strings(res.ResolvedFingerprints)
	return res
}
