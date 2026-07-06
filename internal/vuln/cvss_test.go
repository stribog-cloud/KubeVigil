package vuln

import (
	"math"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestScoreCVSS(t *testing.T) {
	tests := []struct {
		name      string
		vector    string
		wantScore float64
		wantOK    bool
	}{
		{
			name:      "critical all-high network",
			vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantScore: 9.8,
			wantOK:    true,
		},
		{
			name:      "high mixed impact (CVE-2021-3121)",
			vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
			wantScore: 8.6,
			wantOK:    true,
		},
		{
			name:      "medium scope-changed reflected XSS",
			vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			wantScore: 6.1,
			wantOK:    true,
		},
		{
			name:      "low local high-complexity",
			vector:    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
			wantScore: 1.8,
			wantOK:    true,
		},
		{
			name:      "none — no impact",
			vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			wantScore: 0.0,
			wantOK:    true,
		},
		{
			name:      "cvss 3.0 also supported",
			vector:    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantScore: 9.8,
			wantOK:    true,
		},
		{
			name:   "cvss v2 not scored",
			vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			wantOK: false,
		},
		{
			name:   "cvss v4 not scored here",
			vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			wantOK: false,
		},
		{
			name:   "missing base metric",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
			wantOK: false,
		},
		{
			name:   "empty",
			vector: "",
			wantOK: false,
		},
		{
			name:   "garbage metric value",
			vector: "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score, ok := ScoreCVSS(tc.vector)
			if ok != tc.wantOK {
				t.Fatalf("ScoreCVSS(%q) ok=%v, want %v", tc.vector, ok, tc.wantOK)
			}
			if tc.wantOK && math.Abs(score-tc.wantScore) > 0.05 {
				t.Fatalf("ScoreCVSS(%q) score=%.2f, want %.1f", tc.vector, score, tc.wantScore)
			}
		})
	}
}

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  checker.Severity
	}{
		{9.8, checker.SeverityCritical},
		{9.0, checker.SeverityCritical},
		{8.9, checker.SeverityHigh},
		{7.0, checker.SeverityHigh},
		{6.9, checker.SeverityMedium},
		{4.0, checker.SeverityMedium},
		{3.9, checker.SeverityLow},
		{0.1, checker.SeverityLow},
		{0.0, checker.SeverityInfo},
	}
	for _, tc := range tests {
		if got := SeverityFromScore(tc.score); got != tc.want {
			t.Errorf("SeverityFromScore(%.1f)=%v, want %v", tc.score, got, tc.want)
		}
	}
}

func TestSeverityFromText(t *testing.T) {
	tests := []struct {
		label string
		want  checker.Severity
	}{
		{"CRITICAL", checker.SeverityCritical},
		{"critical", checker.SeverityCritical},
		{"HIGH", checker.SeverityHigh},
		{"MODERATE", checker.SeverityMedium},
		{"MEDIUM", checker.SeverityMedium},
		{"LOW", checker.SeverityLow},
		{"NONE", checker.SeverityInfo},
		{"negligible", checker.SeverityInfo},
		{"  High  ", checker.SeverityHigh},
		{"", checker.SeverityMedium}, // unknown → medium, not silently Info
		{"weird-label", checker.SeverityMedium},
	}
	for _, tc := range tests {
		if got := SeverityFromText(tc.label); got != tc.want {
			t.Errorf("SeverityFromText(%q)=%v, want %v", tc.label, got, tc.want)
		}
	}
}
