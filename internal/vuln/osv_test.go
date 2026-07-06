package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// newTestClient points an HTTPOSVClient at a test server.
func newTestClient(srv *httptest.Server) *HTTPOSVClient {
	return &HTTPOSVClient{baseURL: srv.URL, http: srv.Client()}
}

func TestHTTPOSVClient_Resolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/querybatch":
			// django has one vuln, lodash has none.
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-xxxx"}]},{}]}`))
		case "/v1/vulns/GHSA-xxxx":
			_, _ = w.Write([]byte(`{
			  "id":"GHSA-xxxx",
			  "summary":"SQL injection in django",
			  "aliases":["CVE-2021-1234"],
			  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			  "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"3.2.5"}]}]}]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv)
	pkgs := []Package{
		{Purl: "pkg:pypi/django@3.2.0", Name: "django", Version: "3.2.0"},
		{Purl: "pkg:npm/lodash@4.17.15", Name: "lodash", Version: "4.17.15"},
	}
	got, err := c.Resolve(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d affected packages, want 1", len(got))
	}
	vs := got["pkg:pypi/django@3.2.0"]
	if len(vs) != 1 {
		t.Fatalf("django vulns=%d, want 1", len(vs))
	}
	v := vs[0]
	if v.ID != "GHSA-xxxx" || v.Severity != checker.SeverityCritical {
		t.Errorf("vuln=%+v, want id GHSA-xxxx severity Critical", v)
	}
	if v.CVSS < 9.7 || v.FixedVersion != "3.2.5" {
		t.Errorf("cvss=%.1f fixed=%q, want ~9.8 and 3.2.5", v.CVSS, v.FixedVersion)
	}
	if _, exists := got["pkg:npm/lodash@4.17.15"]; exists {
		t.Errorf("lodash should have no vulns")
	}
}

func TestHTTPOSVClient_SeverityTextFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"OSV-1"}]}]}`))
			return
		}
		// No scorable CVSS vector; only a text severity.
		_, _ = w.Write([]byte(`{"id":"OSV-1","summary":"x","database_specific":{"severity":"HIGH"}}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	got, err := c.Resolve(context.Background(), []Package{{Purl: "pkg:golang/x@1", Name: "x"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	v := got["pkg:golang/x@1"][0]
	if v.Severity != checker.SeverityHigh {
		t.Errorf("severity=%v, want High (text fallback)", v.Severity)
	}
	if v.CVSS != 0 {
		t.Errorf("cvss=%.1f, want 0 (no vector)", v.CVSS)
	}
}

func TestHTTPOSVClient_ErrorPaths(t *testing.T) {
	t.Run("querybatch non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		}))
		defer srv.Close()
		_, err := newTestClient(srv).Resolve(context.Background(), []Package{{Purl: "p"}})
		if err == nil || !strings.Contains(err.Error(), "429") {
			t.Errorf("expected 429 error, got %v", err)
		}
	})

	t.Run("querybatch bad json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{not json`))
		}))
		defer srv.Close()
		_, err := newTestClient(srv).Resolve(context.Background(), []Package{{Purl: "p"}})
		if err == nil {
			t.Error("expected decode error")
		}
	})

	t.Run("vulns fetch non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/querybatch" {
				_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"X"}]}]}`))
				return
			}
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()
		_, err := newTestClient(srv).Resolve(context.Background(), []Package{{Purl: "p"}})
		if err == nil {
			t.Error("expected fetch error")
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		c := &HTTPOSVClient{baseURL: "http://127.0.0.1:1", http: &http.Client{Timeout: time.Second}}
		_, err := c.Resolve(context.Background(), []Package{{Purl: "p"}})
		if err == nil {
			t.Error("expected connection error")
		}
	})
}

func TestNewHTTPOSVClient_Defaults(t *testing.T) {
	c := NewHTTPOSVClient(0)
	if c.http.Timeout != 30*time.Second {
		t.Errorf("default timeout=%v, want 30s", c.http.Timeout)
	}
	if c.baseURL != defaultOSVBaseURL {
		t.Errorf("baseURL=%q", c.baseURL)
	}
	if NewHTTPOSVClient(5*time.Second).http.Timeout != 5*time.Second {
		t.Error("explicit timeout not honored")
	}
}

func TestHTTPOSVClient_PerPackageFixedVersion(t *testing.T) {
	// One advisory affecting two packages with DIFFERENT fixed versions. Each
	// package must get ITS OWN fixed version, not whichever appears first.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			// Both packages map to the same advisory.
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"OSV-multi"}]},{"vulns":[{"id":"OSV-multi"}]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{
		  "id":"OSV-multi","summary":"shared advisory",
		  "database_specific":{"severity":"HIGH"},
		  "affected":[
		    {"package":{"name":"pkg-a"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.1.0"}]}]},
		    {"package":{"name":"pkg-b"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.2.0"}]}]}
		  ]
		}`))
	}))
	defer srv.Close()

	got, err := newTestClient(srv).Resolve(context.Background(), []Package{
		{Purl: "pkg:generic/pkg-a@1.0", Name: "pkg-a"},
		{Purl: "pkg:generic/pkg-b@2.0", Name: "pkg-b"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got["pkg:generic/pkg-a@1.0"][0].FixedVersion != "1.1.0" {
		t.Errorf("pkg-a fixed=%q, want 1.1.0", got["pkg:generic/pkg-a@1.0"][0].FixedVersion)
	}
	if got["pkg:generic/pkg-b@2.0"][0].FixedVersion != "2.2.0" {
		t.Errorf("pkg-b fixed=%q, want 2.2.0", got["pkg:generic/pkg-b@2.0"][0].FixedVersion)
	}
}

func TestFixedVersionFor_NoAffected(t *testing.T) {
	// A record with no affected entries yields no fixed version.
	if got := fixedVersionFor(&osvRecord{}, "anything"); got != "" {
		t.Errorf("empty record fixed=%q, want empty", got)
	}
}

func TestRecordToVuln_NoSeverity(t *testing.T) {
	// A record with neither a vector nor a text severity defaults to Medium so a
	// vulnerability never silently drops below a High threshold.
	v := recordToVuln(&osvRecord{ID: "OSV-9", Summary: "s"})
	if v.Severity != checker.SeverityMedium {
		t.Errorf("severity=%v, want Medium default", v.Severity)
	}
}
