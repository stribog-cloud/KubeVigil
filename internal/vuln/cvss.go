// Package vuln adds a container-image vulnerability layer to KubeVigil. It
// reads a software bill of materials (SPDX or CycloneDX JSON), queries the
// OSV.dev vulnerability database for known vulnerabilities affecting the
// inventoried packages, and fuses the results into the scan report as
// "image-vulnerability" findings alongside the posture checks.
package vuln

import (
	"math"
	"strings"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// cvssMetric holds the coefficient tables for CVSS v3.x base-score computation.
var (
	attackVector      = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	attackComplexity  = map[string]float64{"L": 0.77, "H": 0.44}
	userInteraction   = map[string]float64{"N": 0.85, "R": 0.62}
	impactCoefficient = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
)

// privilegesRequired returns the PR coefficient, which depends on whether the
// scope changed (a raised-privilege attack that also breaks scope is scored
// higher).
func privilegesRequired(value string, scopeChanged bool) float64 {
	switch value {
	case "N":
		return 0.85
	case "L":
		if scopeChanged {
			return 0.68
		}
		return 0.62
	case "H":
		if scopeChanged {
			return 0.5
		}
		return 0.27
	default:
		return 0.85
	}
}

// ScoreCVSS parses a CVSS v3.0/v3.1 vector string and returns the base score
// (0.0–10.0). ok is false when the vector is not a supported CVSS v3.x vector
// or is missing required base metrics — the caller should then fall back to a
// text severity. CVSS v2 and v4 vectors are deliberately not scored here (v2 is
// obsolete and v4's scoring is not a closed-form base formula); they return
// ok=false so the text-severity fallback applies.
func ScoreCVSS(vector string) (score float64, ok bool) {
	v := strings.TrimSpace(vector)
	if !strings.HasPrefix(v, "CVSS:3.0/") && !strings.HasPrefix(v, "CVSS:3.1/") {
		return 0, false
	}

	metrics := map[string]string{}
	for _, part := range strings.Split(v, "/")[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	// All base metrics are mandatory in a valid base vector.
	for _, key := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if _, present := metrics[key]; !present {
			return 0, false
		}
	}

	av, avOK := attackVector[metrics["AV"]]
	ac, acOK := attackComplexity[metrics["AC"]]
	ui, uiOK := userInteraction[metrics["UI"]]
	c, cOK := impactCoefficient[metrics["C"]]
	iImp, iOK := impactCoefficient[metrics["I"]]
	a, aOK := impactCoefficient[metrics["A"]]
	if !avOK || !acOK || !uiOK || !cOK || !iOK || !aOK {
		return 0, false
	}
	scopeChanged := metrics["S"] == "C"
	pr := privilegesRequired(metrics["PR"], scopeChanged)

	iss := 1 - ((1 - c) * (1 - iImp) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	base := impact + exploitability
	if scopeChanged {
		base = 1.08 * base
	}
	if base > 10 {
		base = 10
	}
	return roundUp1(base), true
}

// roundUp1 rounds a value up to one decimal place, matching the CVSS v3.1
// specification's Roundup function (ceil to the nearest tenth). A small epsilon
// guards against binary-float representations of exact tenths rounding up
// spuriously.
func roundUp1(x float64) float64 {
	scaled := x * 100000
	rounded := math.Round(scaled)
	if int(rounded)%10000 == 0 {
		return rounded / 100000
	}
	return (math.Floor(rounded/10000) + 1) / 10
}

// SeverityFromScore maps a CVSS base score to a KubeVigil severity using the
// CVSS v3.1 qualitative severity-rating bands.
func SeverityFromScore(score float64) checker.Severity {
	switch {
	case score >= 9.0:
		return checker.SeverityCritical
	case score >= 7.0:
		return checker.SeverityHigh
	case score >= 4.0:
		return checker.SeverityMedium
	case score > 0.0:
		return checker.SeverityLow
	default:
		return checker.SeverityInfo
	}
}

// SeverityFromText maps a database's qualitative severity label (as OSV records
// carry in database_specific.severity, e.g. "CRITICAL", "HIGH", "MODERATE") to
// a KubeVigil severity. It is the fallback when no scorable CVSS vector exists.
// An unrecognised or empty label yields SeverityMedium — a vulnerability with no
// severity metadata is still a vulnerability, and defaulting to Info would let
// it slip past a High threshold silently.
func SeverityFromText(label string) checker.Severity {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return checker.SeverityCritical
	case "HIGH":
		return checker.SeverityHigh
	case "MODERATE", "MEDIUM":
		return checker.SeverityMedium
	case "LOW":
		return checker.SeverityLow
	case "NONE", "NEGLIGIBLE", "INFO", "INFORMATIONAL":
		return checker.SeverityInfo
	default:
		return checker.SeverityMedium
	}
}
