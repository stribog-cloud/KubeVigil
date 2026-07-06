package vuln

import (
	"context"
	"math"
	"net/http"
	"testing"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestScoreCVSS_ScopeChangedPrivileges(t *testing.T) {
	// Scope-changed vectors exercise the raised PR coefficients and the
	// scope-changed impact/base formula.
	cases := []struct{ vector string }{
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"},
		{"CVSS:3.1/AV:N/AC:L/PR:Z/UI:N/S:C/C:H/I:H/A:H"}, // unknown PR → default coefficient
	}
	for _, tc := range cases {
		score, ok := ScoreCVSS(tc.vector)
		if !ok || score <= 0 || score > 10 {
			t.Errorf("ScoreCVSS(%q)=%.1f ok=%v", tc.vector, score, ok)
		}
	}
}

func TestRoundUp1(t *testing.T) {
	cases := []struct {
		in   float64
		want float64
	}{
		{5.0, 5.0},   // exact tenth — returns as-is
		{8.585, 8.6}, // rounds up
		{0.0, 0.0},
		{10.0, 10.0},
	}
	for _, tc := range cases {
		if got := roundUp1(tc.in); math.Abs(got-tc.want) > 0.001 {
			t.Errorf("roundUp1(%.3f)=%.3f, want %.1f", tc.in, got, tc.want)
		}
	}
}

func TestParseSBOM_SPDXEmptyPurlSkipped(t *testing.T) {
	// A purl external ref present but with an empty locator must be skipped, not
	// emitted as an empty-purl package.
	doc := `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"x","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"  "}]}
	]}`
	pkgs, err := ParseSBOM([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("got %d packages, want 0 (empty purl skipped)", len(pkgs))
	}
}

func TestHTTPOSVClient_BuildRequestError(t *testing.T) {
	// A base URL containing a control character makes http.NewRequestWithContext
	// fail, exercising the request-build error path in postJSON/getJSON.
	c := &HTTPOSVClient{baseURL: "http://\x7f invalid", http: &http.Client{}}
	if _, err := c.Resolve(context.Background(), []Package{{Purl: "p"}}); err == nil {
		t.Error("expected request-build error")
	}
}

func TestSortFindings_TieBreaks(t *testing.T) {
	// Equal severity → order by resource, then message.
	fc := &fakeClient{result: map[string][]Vulnerability{
		"p1": {{ID: "CVE-b", Severity: checker.SeverityHigh, Summary: "bbb"}},
		"p2": {{ID: "CVE-a", Severity: checker.SeverityHigh, Summary: "aaa"}},
	}}
	pkgs := []Package{{Purl: "p1", Name: "zeta"}, {Purl: "p2", Name: "alpha"}}
	findings, err := NewScanner(fc).Scan(context.Background(), pkgs, ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings", len(findings))
	}
	// Both High; resource "alpha" sorts before "zeta".
	if findings[0].Resource != "alpha" || findings[1].Resource != "zeta" {
		t.Errorf("tie-break by resource failed: %q, %q", findings[0].Resource, findings[1].Resource)
	}
}
