package vuln

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// fakeClient is a deterministic OSVClient for scanner tests.
type fakeClient struct {
	result map[string][]Vulnerability
	err    error
}

func (f *fakeClient) Resolve(_ context.Context, _ []Package) (map[string][]Vulnerability, error) {
	return f.result, f.err
}

func TestScanner_Scan(t *testing.T) {
	pkgs := []Package{
		{Purl: "pkg:pypi/django@3.2.0", Name: "django", Version: "3.2.0"},
		{Purl: "pkg:npm/lodash@4.17.15", Name: "lodash", Version: "4.17.15"},
	}
	fc := &fakeClient{result: map[string][]Vulnerability{
		"pkg:pypi/django@3.2.0": {
			{ID: "GHSA-aaaa", Aliases: []string{"CVE-2021-1"}, Summary: "sqli", Severity: checker.SeverityCritical, CVSS: 9.8, FixedVersion: "3.2.5"},
		},
		"pkg:npm/lodash@4.17.15": {
			{ID: "CVE-2020-2", Summary: "proto pollution", Severity: checker.SeverityMedium, CVSS: 5.3},
		},
	}}
	findings, err := NewScanner(fc).Scan(context.Background(), pkgs, ScanOptions{Image: "myapp:1.0"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	// Sorted most-severe first: django (Critical) before lodash (Medium).
	crit := findings[0]
	if crit.Severity != checker.SeverityCritical || crit.Checker != CheckerID {
		t.Errorf("finding[0]=%+v", crit)
	}
	if crit.Resource != "myapp:1.0" || crit.Kind != "ContainerImage" || crit.Container != "django" {
		t.Errorf("finding[0] attribution wrong: %+v", crit)
	}
	// Display id prefers the CVE alias over the GHSA primary id.
	if !strings.Contains(crit.Message, "CVE-2021-1") {
		t.Errorf("message should show CVE alias: %q", crit.Message)
	}
	if !strings.Contains(crit.Message, "Fixed in 3.2.5") || !strings.Contains(crit.Message, "CVSS 9.8") {
		t.Errorf("message missing fixed/cvss: %q", crit.Message)
	}
	if crit.CVE == nil || crit.CVE.ID != "GHSA-aaaa" || crit.CVE.Purl != "pkg:pypi/django@3.2.0" {
		t.Errorf("CVE metadata wrong: %+v", crit.CVE)
	}
	if crit.CurrentValue != "3.2.0" || crit.DesiredValue != "3.2.5" {
		t.Errorf("current/desired wrong: %v/%v", crit.CurrentValue, crit.DesiredValue)
	}
	// lodash finding has no fixed version → message says so.
	if !strings.Contains(findings[1].Message, "No fixed version") {
		t.Errorf("lodash message: %q", findings[1].Message)
	}
}

func TestScanner_MinSeverityFilter(t *testing.T) {
	fc := &fakeClient{result: map[string][]Vulnerability{
		"p": {
			{ID: "A", Severity: checker.SeverityLow},
			{ID: "B", Severity: checker.SeverityHigh},
		},
	}}
	findings, err := NewScanner(fc).Scan(context.Background(),
		[]Package{{Purl: "p", Name: "x"}}, ScanOptions{MinSeverity: checker.SeverityHigh})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].CVE.ID != "B" {
		t.Fatalf("min-severity filter failed: %+v", findings)
	}
}

func TestScanner_EmptyAndError(t *testing.T) {
	t.Run("empty packages", func(t *testing.T) {
		f, err := NewScanner(&fakeClient{}).Scan(context.Background(), nil, ScanOptions{})
		if err != nil || f != nil {
			t.Errorf("empty scan: findings=%v err=%v", f, err)
		}
	})
	t.Run("client error", func(t *testing.T) {
		fc := &fakeClient{err: errors.New("network down")}
		_, err := NewScanner(fc).Scan(context.Background(),
			[]Package{{Purl: "p"}}, ScanOptions{})
		if err == nil || !strings.Contains(err.Error(), "resolving vulnerabilities") {
			t.Errorf("want wrapped client error, got %v", err)
		}
	})
}

func TestScanner_NoImageUsesPackageName(t *testing.T) {
	fc := &fakeClient{result: map[string][]Vulnerability{
		"p": {{ID: "CVE-1", Severity: checker.SeverityHigh}},
	}}
	findings, _ := NewScanner(fc).Scan(context.Background(),
		[]Package{{Purl: "p", Name: "libfoo"}}, ScanOptions{})
	if findings[0].Resource != "libfoo" {
		t.Errorf("resource=%q, want package name fallback", findings[0].Resource)
	}
}

func TestPrimaryID(t *testing.T) {
	if got := primaryID(&Vulnerability{ID: "CVE-2021-1"}); got != "CVE-2021-1" {
		t.Errorf("got %q", got)
	}
	if got := primaryID(&Vulnerability{ID: "GHSA-x", Aliases: []string{"GO-1", "CVE-2021-9"}}); got != "CVE-2021-9" {
		t.Errorf("got %q, want CVE alias", got)
	}
	if got := primaryID(&Vulnerability{ID: "GHSA-x", Aliases: []string{"GO-1"}}); got != "GHSA-x" {
		t.Errorf("got %q, want primary id when no CVE alias", got)
	}
}
