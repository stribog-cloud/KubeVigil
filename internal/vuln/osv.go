package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// defaultOSVBaseURL is the OSV.dev REST API root.
const defaultOSVBaseURL = "https://api.osv.dev"

// osvBatchLimit is the maximum number of queries OSV.dev accepts in a single
// querybatch request.
const osvBatchLimit = 1000

// maxOSVResponseBytes caps a single OSV.dev response body so a compromised or
// MITM'd endpoint cannot exhaust memory. Far above any legitimate response.
const maxOSVResponseBytes = 64 << 20

// Vulnerability is a resolved vulnerability record: an OSV advisory with its
// severity already mapped to a KubeVigil severity.
type Vulnerability struct {
	// ID is the OSV primary identifier.
	ID string
	// Aliases are equivalent identifiers (CVE, GHSA, …).
	Aliases []string
	// Summary is the one-line advisory summary.
	Summary string
	// Severity is the KubeVigil severity derived from the CVSS vector (or the
	// database's text severity when no scorable vector is present).
	Severity checker.Severity
	// CVSS is the CVSS base score (0 when unavailable).
	CVSS float64
	// Vector is the CVSS vector string the score came from.
	Vector string
	// FixedVersion is the earliest fixed version, best-effort from the advisory's
	// affected ranges (empty when none is published).
	FixedVersion string
}

// OSVClient resolves the vulnerabilities affecting a set of SBOM packages. It is
// an interface so unit tests can inject a deterministic fake and only an
// integration test touches the network.
type OSVClient interface {
	// Resolve returns, keyed by package purl, the vulnerabilities affecting each
	// package. Packages with no known vulnerabilities are omitted from the map.
	Resolve(ctx context.Context, packages []Package) (map[string][]Vulnerability, error)
}

// HTTPOSVClient is the production OSVClient backed by the OSV.dev REST API.
type HTTPOSVClient struct {
	baseURL string
	http    *http.Client
}

// NewHTTPOSVClient constructs an OSV.dev client with the given per-request
// timeout. A zero timeout applies a sane default.
func NewHTTPOSVClient(timeout time.Duration) *HTTPOSVClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPOSVClient{
		baseURL: defaultOSVBaseURL,
		http:    &http.Client{Timeout: timeout},
	}
}

// osvBatchRequest / osvBatchResponse mirror POST /v1/querybatch.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Purl string `json:"purl"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// osvRecord mirrors the subset of GET /v1/vulns/{id} we consume.
type osvRecord struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Resolve implements OSVClient against the live OSV.dev API. It batches the
// purl queries (respecting the 1000-query limit), then fetches each unique
// advisory once (advisories are cached across packages within the call) and
// maps the resolved vulnerabilities back to every purl they affect.
func (c *HTTPOSVClient) Resolve(ctx context.Context, packages []Package) (map[string][]Vulnerability, error) {
	purlToIDs, err := c.queryBatches(ctx, packages)
	if err != nil {
		return nil, err
	}

	// Fetch each unique advisory record once. The advisory-level fields
	// (severity, summary, aliases) are shared, but the fixed version is
	// package-specific — a single advisory can affect several packages with
	// different fixes — so it is resolved per package below, not cached.
	cache := map[string]*osvRecord{}
	for _, ids := range purlToIDs {
		for _, id := range ids {
			if _, done := cache[id]; done {
				continue
			}
			rec, ferr := c.fetchRecord(ctx, id)
			if ferr != nil {
				return nil, ferr
			}
			cache[id] = rec
		}
	}

	purlToName := map[string]string{}
	for _, p := range packages {
		purlToName[p.Purl] = p.Name
	}

	out := map[string][]Vulnerability{}
	for purl, ids := range purlToIDs {
		for _, id := range ids {
			rec := cache[id]
			if rec == nil {
				continue
			}
			v := recordToVuln(rec)
			v.FixedVersion = fixedVersionFor(rec, purlToName[purl])
			out[purl] = append(out[purl], *v)
		}
		sort.Slice(out[purl], func(i, j int) bool { return out[purl][i].ID < out[purl][j].ID })
	}
	return out, nil
}

// queryBatches runs the querybatch endpoint over the packages in chunks and
// returns, per purl, the advisory IDs affecting it.
func (c *HTTPOSVClient) queryBatches(ctx context.Context, packages []Package) (map[string][]string, error) {
	purlToIDs := map[string][]string{}
	for start := 0; start < len(packages); start += osvBatchLimit {
		end := start + osvBatchLimit
		if end > len(packages) {
			end = len(packages)
		}
		chunk := packages[start:end]

		req := osvBatchRequest{Queries: make([]osvQuery, len(chunk))}
		for i, p := range chunk {
			req.Queries[i] = osvQuery{Package: osvPackage{Purl: p.Purl}}
		}
		var resp osvBatchResponse
		if err := c.postJSON(ctx, "/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		for i := range chunk {
			if i >= len(resp.Results) {
				break
			}
			for _, v := range resp.Results[i].Vulns {
				purlToIDs[chunk[i].Purl] = append(purlToIDs[chunk[i].Purl], v.ID)
			}
		}
	}
	return purlToIDs, nil
}

// fetchRecord retrieves a single advisory record.
func (c *HTTPOSVClient) fetchRecord(ctx context.Context, id string) (*osvRecord, error) {
	var rec osvRecord
	if err := c.getJSON(ctx, "/v1/vulns/"+id, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// recordToVuln maps the advisory-level fields of an OSV record to a
// Vulnerability, preferring a scorable CVSS vector and falling back to the
// database's text severity. FixedVersion is package-specific and set separately
// by the caller via fixedVersionFor.
func recordToVuln(rec *osvRecord) *Vulnerability {
	v := &Vulnerability{
		ID:       rec.ID,
		Aliases:  rec.Aliases,
		Summary:  rec.Summary,
		Severity: checker.SeverityMedium,
	}
	scored := false
	for _, s := range rec.Severity {
		score, ok := ScoreCVSS(s.Score)
		if !ok {
			continue
		}
		v.CVSS = score
		v.Vector = s.Score
		v.Severity = SeverityFromScore(score)
		scored = true
		break
	}
	if !scored {
		v.Severity = SeverityFromText(rec.DatabaseSpecific.Severity)
	}
	return v
}

// fixedVersionFor returns the fixed version for a specific package. Because a
// single advisory can affect several packages with different fixes, it prefers
// the "fixed" event on the affected entry whose package name matches pkgName,
// and only falls back to the first fixed event of any affected entry when no
// name match exists (or the package name is unknown).
func fixedVersionFor(rec *osvRecord, pkgName string) string {
	// First pass: the affected entry whose package name matches.
	if pkgName != "" {
		for i := range rec.Affected {
			if strings.EqualFold(rec.Affected[i].Package.Name, pkgName) {
				if fixed := firstFixed(rec, i); fixed != "" {
					return fixed
				}
			}
		}
	}
	// Fallback: first fixed event across any affected entry (best-effort).
	for i := range rec.Affected {
		if fixed := firstFixed(rec, i); fixed != "" {
			return fixed
		}
	}
	return ""
}

// firstFixed returns the first non-empty "fixed" event of the i-th affected
// entry.
func firstFixed(rec *osvRecord, i int) string {
	for _, rng := range rec.Affected[i].Ranges {
		for _, ev := range rng.Events {
			if ev.Fixed != "" {
				return ev.Fixed
			}
		}
	}
	return ""
}

func (c *HTTPOSVClient) postJSON(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding OSV request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("building OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *HTTPOSVClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("building OSV request: %w", err)
	}
	return c.do(req, out)
}

func (c *HTTPOSVClient) do(req *http.Request, out any) error {
	req.Header.Set("User-Agent", "kubevigil")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("querying OSV.dev: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("OSV.dev returned %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	// Cap the response body: OSV.dev is a trusted TLS endpoint, but a
	// compromised or MITM'd server must not be able to exhaust memory with an
	// unbounded response. 64 MiB is far above any legitimate advisory or batch.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOSVResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("decoding OSV response: %w", err)
	}
	return nil
}
