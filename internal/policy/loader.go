package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxPolicyFileSize bounds a single policy file to guard against resource
// exhaustion from a malicious or malformed file (mirrors the engine's caps).
const maxPolicyFileSize = 1 << 20 // 1 MiB

// validIDChars reports whether s is a valid kebab-case policy ID.
func validID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			// valid kebab-case character
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

// LoadBytes parses a Set from YAML bytes and validates it.
func LoadBytes(data []byte) (*Set, error) {
	var ps Set
	if err := yaml.Unmarshal(data, &ps); err != nil {
		return nil, fmt.Errorf("parsing policy document: %w", err)
	}
	if err := ps.Validate(); err != nil {
		return nil, err
	}
	return &ps, nil
}

// LoadFile reads and validates a policy document from a single file.
func LoadFile(path string) (*Set, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file %q: %w", path, err)
	}
	if info.Size() > maxPolicyFileSize {
		return nil, fmt.Errorf("policy file %q exceeds %d bytes", path, maxPolicyFileSize)
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path, size-capped above
	if err != nil {
		return nil, fmt.Errorf("reading policy file %q: %w", path, err)
	}
	ps, err := LoadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("in %q: %w", path, err)
	}
	return ps, nil
}

// LoadDir loads and merges every *.yaml/*.yml policy file in dir (non-recursive),
// in lexical order, rejecting duplicate policy IDs across files.
func LoadDir(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading policy dir %q: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)

	merged := &Set{Version: SpecVersion}
	seen := make(map[string]string)
	for _, f := range files {
		ps, err := LoadFile(f)
		if err != nil {
			return nil, err
		}
		for j := range ps.Policies {
			p := &ps.Policies[j]
			if prev, dup := seen[p.ID]; dup {
				return nil, fmt.Errorf("duplicate policy id %q in %q (already defined in %q)", p.ID, f, prev)
			}
			seen[p.ID] = f
			merged.Policies = append(merged.Policies, *p)
		}
	}
	return merged, nil
}

// Validate checks structural correctness: known version, unique valid IDs,
// required fields, and parseable severities. It does NOT compile CEL — that is
// done by Compile so callers can separate structural from semantic errors.
func (ps *Set) Validate() error {
	if ps.Version != "" && ps.Version != SpecVersion {
		return fmt.Errorf("unsupported policy version %q (want %q)", ps.Version, SpecVersion)
	}
	seen := make(map[string]struct{}, len(ps.Policies))
	for i := range ps.Policies {
		p := &ps.Policies[i]
		if !validID(p.ID) {
			return fmt.Errorf("policy #%d: invalid id %q (must be non-empty kebab-case: a-z, 0-9, -)", i, p.ID)
		}
		if _, dup := seen[p.ID]; dup {
			return fmt.Errorf("duplicate policy id %q", p.ID)
		}
		seen[p.ID] = struct{}{}
		if strings.TrimSpace(p.Expression) == "" {
			return fmt.Errorf("policy %q: expression is required", p.ID)
		}
		if _, err := ParseSeverity(p.Severity); err != nil {
			return fmt.Errorf("policy %q: %w", p.ID, err)
		}
	}
	return nil
}
