// Package helpers provides test utilities for KubeVigil checker tests.
package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// AssertNoFindings asserts that the findings slice is empty.
func AssertNoFindings(t *testing.T, findings []checker.Finding) {
	t.Helper()
	assert.Empty(t, findings, "expected no findings but got %d", len(findings))
}

// AssertFindingCount asserts that the findings slice has exactly the expected count.
func AssertFindingCount(t *testing.T, findings []checker.Finding, count int) {
	t.Helper()
	assert.Len(t, findings, count, "expected %d findings but got %d", count, len(findings))
}

// AssertFindingForResource asserts that at least one finding references the given resource name.
func AssertFindingForResource(t *testing.T, findings []checker.Finding, name string) {
	t.Helper()
	for i := range findings {
		if findings[i].Resource == name {
			return
		}
	}
	t.Errorf("no finding found for resource %q", name)
}

// AssertFindingForContainer asserts that at least one finding references the given container name.
func AssertFindingForContainer(t *testing.T, findings []checker.Finding, name string) {
	t.Helper()
	for i := range findings {
		if findings[i].Container == name {
			return
		}
	}
	t.Errorf("no finding found for container %q", name)
}

// AssertAllFindingsHaveRequiredFields asserts that every finding has all required fields populated.
func AssertAllFindingsHaveRequiredFields(t *testing.T, findings []checker.Finding) {
	t.Helper()
	for i := range findings {
		f := &findings[i]
		assert.NotEmpty(t, f.Checker, "finding[%d].Checker is empty", i)
		assert.NotEmpty(t, f.Message, "finding[%d].Message is empty", i)
		assert.NotEmpty(t, f.Remediation, "finding[%d].Remediation is empty", i)
		assert.NotEmpty(t, f.Resource, "finding[%d].Resource is empty", i)
		assert.NotEmpty(t, f.Kind, "finding[%d].Kind is empty", i)
	}
}

// FindingMatch specifies criteria for matching a finding. Zero-value fields are ignored.
type FindingMatch struct {
	Checker   string
	Severity  *checker.Severity
	Resource  string
	Namespace string
	Kind      string
	Container string
}

// AssertFinding asserts that at least one finding matches all non-zero fields in the match criteria.
func AssertFinding(t *testing.T, findings []checker.Finding, match *FindingMatch) {
	t.Helper()
	for i := range findings {
		f := &findings[i]
		if match.Checker != "" && f.Checker != match.Checker {
			continue
		}
		if match.Severity != nil && f.Severity != *match.Severity {
			continue
		}
		if match.Resource != "" && f.Resource != match.Resource {
			continue
		}
		if match.Namespace != "" && f.Namespace != match.Namespace {
			continue
		}
		if match.Kind != "" && f.Kind != match.Kind {
			continue
		}
		if match.Container != "" && f.Container != match.Container {
			continue
		}
		return // match found
	}
	t.Errorf("no finding matched %+v in %d findings", match, len(findings))
}
