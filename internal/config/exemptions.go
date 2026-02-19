package config

import (
	"strings"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// Exemption defines a rule for skipping specific findings during scans.
type Exemption struct {
	// Namespace limits the exemption to resources in this namespace.
	Namespace string `yaml:"namespace"`
	// Resource limits the exemption to this resource name.
	Resource string `yaml:"resource"`
	// Kind limits the exemption to this resource kind.
	Kind string `yaml:"kind"`
	// Checks limits the exemption to these check IDs. Empty means all checks.
	Checks []string `yaml:"checks"`
	// Reason documents why this exemption exists.
	Reason string `yaml:"reason"`
	// ApprovedBy documents who approved this exemption.
	ApprovedBy string `yaml:"approved_by"`
	// Expires is the date (YYYY-MM-DD) when this exemption stops applying.
	Expires string `yaml:"expires"`
	// Annotation is reserved for annotation-based exemption matching.
	Annotation string `yaml:"annotation"`
}

const (
	// skipAnnotationKey is the annotation used to skip checks on a resource.
	skipAnnotationKey = "kubevigil.io/skip"
	// expiryDateFormat is the expected date format for exemption expiry.
	expiryDateFormat = "2006-01-02"
)

// ExemptionKey builds a lookup key for a resource from its namespace, kind, and name.
func ExemptionKey(namespace, kind, name string) string {
	return namespace + "/" + kind + "/" + name
}

// IsExempt checks whether a finding should be skipped based on exemptions and annotations.
// It first checks annotation-based exemptions (kubevigil.io/skip), then config-based exemptions.
func IsExempt(exemptions []Exemption, finding *checker.Finding, annotations map[string]string) bool {
	// Check annotation-based exemptions first.
	if skipValue, ok := annotations[skipAnnotationKey]; ok {
		if skipValue == "*" {
			return true
		}
		for _, id := range strings.Split(skipValue, ",") {
			if strings.TrimSpace(id) == finding.Checker {
				return true
			}
		}
	}

	// Check config-based exemptions.
	for i := range exemptions {
		if matchesExemption(&exemptions[i], finding) {
			return true
		}
	}
	return false
}

// matchesExemption returns true if the finding matches all non-empty fields of the exemption.
func matchesExemption(ex *Exemption, finding *checker.Finding) bool {
	if ex.Namespace != "" && ex.Namespace != finding.Namespace {
		return false
	}
	if ex.Resource != "" && ex.Resource != finding.Resource {
		return false
	}
	if ex.Kind != "" && ex.Kind != finding.Kind {
		return false
	}
	if len(ex.Checks) > 0 {
		found := false
		for _, c := range ex.Checks {
			if c == finding.Checker {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if ex.Expires != "" {
		expiry, err := time.Parse(expiryDateFormat, ex.Expires)
		if err == nil && time.Now().After(expiry) {
			return false
		}
	}
	return true
}

// FilterFindings returns only findings that are not exempt.
// annotationsByResource maps ExemptionKey(namespace, kind, name) to the resource's annotations.
func FilterFindings(findings []checker.Finding, exemptions []Exemption, annotationsByResource map[string]map[string]string) []checker.Finding {
	var filtered []checker.Finding
	for i := range findings {
		key := ExemptionKey(findings[i].Namespace, findings[i].Kind, findings[i].Resource)
		annotations := annotationsByResource[key]
		if !IsExempt(exemptions, &findings[i], annotations) {
			filtered = append(filtered, findings[i])
		}
	}
	return filtered
}
