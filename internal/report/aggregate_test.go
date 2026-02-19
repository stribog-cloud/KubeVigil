package report

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestAggregateFindings_Empty(t *testing.T) {
	result := aggregateFindings(nil)
	assert.Empty(t, result)
}

func TestAggregateFindings_SingleFinding(t *testing.T) {
	findings := []checker.Finding{
		{
			Checker:   "privileged",
			Severity:  checker.SeverityCritical,
			Resource:  "nginx",
			Namespace: "default",
			Kind:      "Deployment",
			Container: "nginx",
			Message:   "Container runs in privileged mode",
		},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 1)
	assert.Equal(t, "privileged", result[0].Checker)
	assert.Equal(t, checker.SeverityCritical, result[0].Severity)
	assert.Equal(t, "Container runs in privileged mode", result[0].Message)
	require.Len(t, result[0].Resources, 1)
	assert.Equal(t, "default/Deployment/nginx", result[0].Resources[0].Name)
	assert.Equal(t, "nginx", result[0].Resources[0].Container)
}

func TestAggregateFindings_GroupsSameCheckerMessage(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Container: "nginx", Message: "Container runs in privileged mode"},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "redis", Namespace: "default", Kind: "Deployment", Container: "redis", Message: "Container runs in privileged mode"},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "worker", Namespace: "default", Kind: "StatefulSet", Container: "worker", Message: "Container runs in privileged mode"},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 1, "same checker+message should produce one group")
	assert.Equal(t, "privileged", result[0].Checker)
	require.Len(t, result[0].Resources, 3)
	assert.Equal(t, "default/Deployment/nginx", result[0].Resources[0].Name)
	assert.Equal(t, "default/Deployment/redis", result[0].Resources[1].Name)
	assert.Equal(t, "default/StatefulSet/worker", result[0].Resources[2].Name)
}

func TestAggregateFindings_DifferentCheckers(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "Container runs in privileged mode"},
		{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "nginx", Namespace: "default", Kind: "Deployment", Message: "Container runs as root"},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 2, "different checkers should not be grouped")
}

func TestAggregateFindings_SameCheckerDifferentMessages(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "image-tag-latest", Severity: checker.SeverityMedium, Resource: "a", Namespace: "default", Kind: "Deployment", Message: "Image uses latest tag: nginx:latest"},
		{Checker: "image-tag-latest", Severity: checker.SeverityMedium, Resource: "b", Namespace: "default", Kind: "Deployment", Message: "Image uses latest tag: redis:latest"},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 1, "same checker+severity should be grouped even with different messages")
	assert.Len(t, result[0].Resources, 2)
	// Individual resource messages are preserved for drilldown.
	assert.Equal(t, "Image uses latest tag: nginx:latest", result[0].Resources[0].Message)
	assert.Equal(t, "Image uses latest tag: redis:latest", result[0].Resources[1].Message)
}

func TestAggregateFindings_SameCheckerDifferentSeverities(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "resource-limits", Severity: checker.SeverityHigh, Resource: "a", Namespace: "default", Kind: "Deployment", Message: "No memory limit"},
		{Checker: "resource-limits", Severity: checker.SeverityMedium, Resource: "b", Namespace: "default", Kind: "Deployment", Message: "No CPU limit"},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 2, "same checker but different severities should not be grouped")
}

func TestAggregateFindings_50SameChecker(t *testing.T) {
	findings := make([]checker.Finding, 50)
	for i := range findings {
		findings[i] = checker.Finding{
			Checker:   "automount-token",
			Severity:  checker.SeverityHigh,
			Resource:  fmt.Sprintf("app-%d", i),
			Namespace: "default",
			Kind:      "Deployment",
			Message:   fmt.Sprintf("Deployment %q auto-mounts a ServiceAccount token.", fmt.Sprintf("app-%d", i)),
		}
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 1, "50 findings with same checker+severity should produce 1 group")
	assert.Len(t, result[0].Resources, 50)
}

func TestAggregateFindings_PreservesOrder(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Namespace: "default", Kind: "Deployment", Message: "privileged"},
		{Checker: "run-as-root", Severity: checker.SeverityHigh, Resource: "b", Namespace: "default", Kind: "Deployment", Message: "root"},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "c", Namespace: "default", Kind: "Deployment", Message: "privileged"},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 2)
	assert.Equal(t, "privileged", result[0].Checker)
	assert.Len(t, result[0].Resources, 2) // a and c grouped
	assert.Equal(t, "run-as-root", result[1].Checker)
	assert.Len(t, result[1].Resources, 1)
}

func TestAggregateFindings_PreservesRemediation(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Namespace: "default", Kind: "Deployment", Message: "priv", Remediation: "Set privileged: false"},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "b", Namespace: "default", Kind: "Deployment", Message: "priv", Remediation: "Set privileged: false"},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 1)
	assert.Equal(t, "Set privileged: false", result[0].Remediation)
}

func TestAggregateFindings_PreservesFrameworks(t *testing.T) {
	fws := []checker.FrameworkRef{{Framework: "cis", ControlID: "5.2.1"}}
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Namespace: "default", Kind: "Deployment", Message: "priv", Frameworks: fws},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "b", Namespace: "default", Kind: "Deployment", Message: "priv"},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 1)
	require.Len(t, result[0].Frameworks, 1)
	assert.Equal(t, "5.2.1", result[0].Frameworks[0].ControlID)
}

func TestAggregateFindings_PreservesFieldPath(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "a", Namespace: "default", Kind: "Deployment", Message: "priv", FieldPath: ".spec.containers[0].securityContext.privileged"},
		{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "b", Namespace: "default", Kind: "Deployment", Message: "priv", FieldPath: ".spec.containers[0].securityContext.privileged"},
	}
	result := aggregateFindings(findings)
	require.Len(t, result, 1)
	assert.Equal(t, ".spec.containers[0].securityContext.privileged", result[0].Resources[0].FieldPath)
	assert.Equal(t, ".spec.containers[0].securityContext.privileged", result[0].Resources[1].FieldPath)
}
