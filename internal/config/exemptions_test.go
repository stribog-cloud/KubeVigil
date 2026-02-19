package config

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestExemptionKey(t *testing.T) {
	assert.Equal(t, "default/Deployment/nginx", ExemptionKey("default", "Deployment", "nginx"))
	assert.Equal(t, "/Pod/test", ExemptionKey("", "Pod", "test"))
}

func TestIsExempt_NamespaceMatch(t *testing.T) {
	exemptions := []Exemption{
		{Namespace: "kube-system"},
	}
	finding := checker.Finding{
		Checker:   "privileged",
		Namespace: "kube-system",
		Resource:  "kube-proxy",
		Kind:      "DaemonSet",
	}
	assert.True(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_NamespaceMismatch(t *testing.T) {
	exemptions := []Exemption{
		{Namespace: "kube-system"},
	}
	finding := checker.Finding{
		Checker:   "privileged",
		Namespace: "default",
		Resource:  "nginx",
		Kind:      "Deployment",
	}
	assert.False(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_ResourceMatch(t *testing.T) {
	exemptions := []Exemption{
		{Resource: "nginx"},
	}
	finding := checker.Finding{
		Checker:  "privileged",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.True(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_KindMatch(t *testing.T) {
	exemptions := []Exemption{
		{Kind: "DaemonSet"},
	}
	finding := checker.Finding{
		Checker:  "privileged",
		Resource: "kube-proxy",
		Kind:     "DaemonSet",
	}
	assert.True(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_CheckMatch(t *testing.T) {
	exemptions := []Exemption{
		{Checks: []string{"privileged", "host-pid"}},
	}
	finding := checker.Finding{
		Checker:  "privileged",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.True(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_CheckMismatch(t *testing.T) {
	exemptions := []Exemption{
		{Checks: []string{"host-pid", "host-ipc"}},
	}
	finding := checker.Finding{
		Checker:  "privileged",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.False(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_AnnotationSkipAll(t *testing.T) {
	annotations := map[string]string{
		"kubevigil.io/skip": "*",
	}
	finding := checker.Finding{
		Checker:  "privileged",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.True(t, IsExempt(nil, &finding, annotations))
}

func TestIsExempt_AnnotationSkipSpecific(t *testing.T) {
	annotations := map[string]string{
		"kubevigil.io/skip": "privileged,run-as-root",
	}

	findingMatch := checker.Finding{
		Checker:  "privileged",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.True(t, IsExempt(nil, &findingMatch, annotations))

	findingMatch2 := checker.Finding{
		Checker:  "run-as-root",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.True(t, IsExempt(nil, &findingMatch2, annotations))
}

func TestIsExempt_AnnotationMiss(t *testing.T) {
	annotations := map[string]string{
		"kubevigil.io/skip": "host-pid,host-ipc",
	}
	finding := checker.Finding{
		Checker:  "privileged",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.False(t, IsExempt(nil, &finding, annotations))
}

func TestIsExempt_Expired(t *testing.T) {
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	exemptions := []Exemption{
		{
			Namespace: "default",
			Expires:   yesterday,
		},
	}
	finding := checker.Finding{
		Checker:   "privileged",
		Namespace: "default",
		Resource:  "nginx",
		Kind:      "Deployment",
	}
	assert.False(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_NotExpired(t *testing.T) {
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")
	exemptions := []Exemption{
		{
			Namespace: "default",
			Expires:   tomorrow,
		},
	}
	finding := checker.Finding{
		Checker:   "privileged",
		Namespace: "default",
		Resource:  "nginx",
		Kind:      "Deployment",
	}
	assert.True(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_NoExemptions(t *testing.T) {
	finding := checker.Finding{
		Checker:  "privileged",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.False(t, IsExempt(nil, &finding, nil))
}

func TestIsExempt_MultiFieldMatch(t *testing.T) {
	exemptions := []Exemption{
		{
			Namespace: "kube-system",
			Kind:      "DaemonSet",
			Checks:    []string{"privileged"},
		},
	}
	finding := checker.Finding{
		Checker:   "privileged",
		Namespace: "kube-system",
		Resource:  "kube-proxy",
		Kind:      "DaemonSet",
	}
	assert.True(t, IsExempt(exemptions, &finding, nil))

	// Same but wrong kind.
	findingWrongKind := checker.Finding{
		Checker:   "privileged",
		Namespace: "kube-system",
		Resource:  "kube-proxy",
		Kind:      "Deployment",
	}
	assert.False(t, IsExempt(exemptions, &findingWrongKind, nil))
}

func TestFilterFindings(t *testing.T) {
	exemptions := []Exemption{
		{Namespace: "kube-system"},
	}
	annotations := map[string]map[string]string{
		ExemptionKey("default", "Deployment", "skip-me"): {
			"kubevigil.io/skip": "*",
		},
	}

	findings := []checker.Finding{
		{Checker: "privileged", Namespace: "kube-system", Resource: "kube-proxy", Kind: "DaemonSet"},
		{Checker: "privileged", Namespace: "default", Resource: "nginx", Kind: "Deployment"},
		{Checker: "run-as-root", Namespace: "default", Resource: "skip-me", Kind: "Deployment"},
	}

	filtered := FilterFindings(findings, exemptions, annotations)
	require.Len(t, filtered, 1)
	assert.Equal(t, "nginx", filtered[0].Resource)
}

func TestFilterFindings_NoExemptions(t *testing.T) {
	findings := []checker.Finding{
		{Checker: "privileged", Resource: "nginx", Kind: "Deployment"},
		{Checker: "run-as-root", Resource: "app", Kind: "Pod"},
	}

	filtered := FilterFindings(findings, nil, nil)
	assert.Len(t, filtered, 2)
}

func TestFilterFindings_Empty(t *testing.T) {
	filtered := FilterFindings(nil, nil, nil)
	assert.Nil(t, filtered)
}

func TestIsExempt_AnnotationTakesPrecedence(t *testing.T) {
	// Even if config exemptions don't match, annotation should exempt.
	exemptions := []Exemption{
		{Namespace: "other-namespace"},
	}
	annotations := map[string]string{
		"kubevigil.io/skip": "privileged",
	}
	finding := checker.Finding{
		Checker:   "privileged",
		Namespace: "default",
		Resource:  "nginx",
		Kind:      "Deployment",
	}
	assert.True(t, IsExempt(exemptions, &finding, annotations))
}

func TestIsExempt_ExpiresInvalidDate(t *testing.T) {
	// Invalid expiry date format should not prevent the exemption from applying.
	exemptions := []Exemption{
		{
			Namespace: "default",
			Expires:   "not-a-date",
		},
	}
	finding := checker.Finding{
		Checker:   "privileged",
		Namespace: "default",
		Resource:  "nginx",
		Kind:      "Deployment",
	}
	// With an unparseable date, the exemption still applies (fail open for expiry).
	assert.True(t, IsExempt(exemptions, &finding, nil))
}

func TestIsExempt_AnnotationWithSpaces(t *testing.T) {
	// Annotation values with spaces around commas.
	annotations := map[string]string{
		"kubevigil.io/skip": "privileged, run-as-root",
	}
	finding := checker.Finding{
		Checker:  "run-as-root",
		Resource: "nginx",
		Kind:     "Deployment",
	}
	assert.True(t, IsExempt(nil, &finding, annotations))
}

func TestExemptionKey_Format(t *testing.T) {
	tests := []struct {
		namespace string
		kind      string
		name      string
		want      string
	}{
		{"default", "Deployment", "nginx", "default/Deployment/nginx"},
		{"kube-system", "DaemonSet", "kube-proxy", "kube-system/DaemonSet/kube-proxy"},
		{"", "Pod", "test", "/Pod/test"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s/%s", tt.namespace, tt.kind, tt.name), func(t *testing.T) {
			assert.Equal(t, tt.want, ExemptionKey(tt.namespace, tt.kind, tt.name))
		})
	}
}
