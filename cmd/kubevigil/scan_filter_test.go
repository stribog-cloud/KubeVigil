package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestFilterByNamespace_ExcludesClusterScoped(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "run-as-root", Namespace: "production", Resource: "web-deploy", Severity: checker.SeverityHigh},
		{Checker: "psa-labels-missing", Namespace: "", Resource: "production", Severity: checker.SeverityMedium},
		{Checker: "image-tag-latest", Namespace: "production", Resource: "api-deploy", Severity: checker.SeverityMedium},
	}

	filtered := filterByNamespace(findings, "production")

	assert.Len(t, filtered, 2, "cluster-scoped finding (Namespace == \"\") must be excluded")
	for _, f := range filtered {
		assert.Equal(t, "production", f.Namespace, "all findings must belong to the requested namespace")
	}
}

func TestFilterByNamespace_OnlyMatchesExactNamespace(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "run-as-root", Namespace: "production", Severity: checker.SeverityHigh},
		{Checker: "run-as-root", Namespace: "staging", Severity: checker.SeverityHigh},
		{Checker: "psa-labels-missing", Namespace: "", Severity: checker.SeverityMedium},
		{Checker: "run-as-root", Namespace: "production-canary", Severity: checker.SeverityHigh},
	}

	filtered := filterByNamespace(findings, "production")

	assert.Len(t, filtered, 1)
	assert.Equal(t, "production", filtered[0].Namespace)
}

func TestFilterByNamespace_EmptyNamespaceReturnsEmpty(t *testing.T) {
	// Filtering for "" would match cluster-scoped findings, but
	// the caller never passes "" (guarded by if flagNamespace != "").
	// Test documents this edge: passing "" returns cluster-scoped only.
	findings := []checker.Finding{
		{Checker: "run-as-root", Namespace: "production", Severity: checker.SeverityHigh},
		{Checker: "psa-labels-missing", Namespace: "", Severity: checker.SeverityMedium},
	}

	filtered := filterByNamespace(findings, "")

	assert.Len(t, filtered, 1)
	assert.Equal(t, "", filtered[0].Namespace)
}

func TestFilterByNamespace_EmptyFindings(t *testing.T) {
	filtered := filterByNamespace(nil, "production")
	assert.Empty(t, filtered)
}
