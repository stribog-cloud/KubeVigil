package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// fakeScanner returns a fixed set of findings (or an error) for any object.
type fakeScanner struct {
	findings []checker.Finding
	err      error
}

func (f *fakeScanner) ScanObject(_ context.Context, _ unstructured.Unstructured) (*checker.ScanResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &checker.ScanResult{Findings: f.findings}, nil
}

func reviewFor(t *testing.T, obj map[string]any) *admissionv1.AdmissionReview {
	t.Helper()
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:    types.UID("test-uid"),
			Object: runtime.RawExtension{Raw: raw},
		},
	}
}

func post(t *testing.T, h *Handler, review *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	t.Helper()
	// Re-marshal through the real admission type to exercise decode.
	body, err := json.Marshal(map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request": map[string]any{
			"uid":    string(review.Request.UID),
			"object": json.RawMessage(review.Request.Object.Raw),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding response: %v (body: %s)", err, rr.Body.String())
	}
	return out.Response
}

var samplePod = map[string]any{
	"apiVersion": "v1", "kind": "Pod",
	"metadata": map[string]any{"name": "web", "namespace": "default"},
}

func TestReview_DeniesAtOrAboveThreshold(t *testing.T) {
	h := &Handler{
		Scanner: &fakeScanner{findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "web", Namespace: "default", Message: "privileged container"},
		}},
		FailOn: checker.SeverityHigh,
	}
	resp := post(t, h, reviewFor(t, samplePod))
	if resp.Allowed {
		t.Fatal("critical finding must deny admission")
	}
	if resp.Result == nil || resp.Result.Code != http.StatusForbidden {
		t.Errorf("expected forbidden status, got %+v", resp.Result)
	}
	if resp.UID != "test-uid" {
		t.Errorf("UID not echoed: %q", resp.UID)
	}
}

func TestReview_WarnsBelowThreshold(t *testing.T) {
	h := &Handler{
		Scanner: &fakeScanner{findings: []checker.Finding{
			{Checker: "resource-limits", Severity: checker.SeverityLow, Resource: "web", Namespace: "default", Message: "no limits"},
		}},
		FailOn: checker.SeverityHigh,
	}
	resp := post(t, h, reviewFor(t, samplePod))
	if !resp.Allowed {
		t.Fatal("low finding must allow with a warning")
	}
	if len(resp.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %v", resp.Warnings)
	}
}

func TestReview_AllowsCleanObject(t *testing.T) {
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	resp := post(t, h, reviewFor(t, samplePod))
	if !resp.Allowed || len(resp.Warnings) != 0 {
		t.Fatalf("clean object should be allowed with no warnings: %+v", resp)
	}
}

func TestReview_DenialCarriesSubThresholdWarnings(t *testing.T) {
	h := &Handler{
		Scanner: &fakeScanner{findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "web", Message: "priv"},
			{Checker: "no-limits", Severity: checker.SeverityLow, Resource: "web", Message: "limits"},
		}},
		FailOn: checker.SeverityHigh,
	}
	resp := post(t, h, reviewFor(t, samplePod))
	if resp.Allowed {
		t.Fatal("should deny")
	}
	if len(resp.Warnings) != 1 {
		t.Errorf("sub-threshold finding should still warn on a denial: %v", resp.Warnings)
	}
}

func TestReview_FailsOpenOnScanError(t *testing.T) {
	h := &Handler{Scanner: &fakeScanner{err: errors.New("boom")}, FailOn: checker.SeverityHigh}
	resp := post(t, h, reviewFor(t, samplePod))
	if !resp.Allowed {
		t.Fatal("a scan error must fail OPEN (allow) so the webhook can't take down the cluster")
	}
	if len(resp.Warnings) == 0 {
		t.Error("scan error should surface a warning")
	}
}

func TestServeHTTP_Rejects(t *testing.T) {
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}

	// Wrong method.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/validate", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should be 405, got %d", rr.Code)
	}

	// Wrong content type.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("non-json should be 415, got %d", rr.Code)
	}

	// Malformed JSON.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed body should be 400, got %d", rr.Code)
	}

	// No request field.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader([]byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`)))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing request should be 400, got %d", rr.Code)
	}
}

func TestReview_UndecodableObjectAllows(t *testing.T) {
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	resp := h.review(context.Background(), &admissionv1.AdmissionRequest{
		UID:    "x",
		Object: runtime.RawExtension{Raw: []byte("not-json")},
	})
	if !resp.Allowed {
		t.Fatal("undecodable object should be allowed without scanning")
	}
}

func TestReview_MultipleDenialsJoined(t *testing.T) {
	h := &Handler{
		Scanner: &fakeScanner{findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "web", Namespace: "default", Message: "priv"},
			{Checker: "host-network", Severity: checker.SeverityHigh, Resource: "web", Namespace: "default", Message: "hostnet"},
		}},
		FailOn: checker.SeverityHigh,
	}
	resp := post(t, h, reviewFor(t, samplePod))
	if resp.Allowed {
		t.Fatal("should deny")
	}
	// Both denials must appear in the joined message.
	if got := resp.Result.Message; !bytes.Contains([]byte(got), []byte("privileged")) || !bytes.Contains([]byte(got), []byte("host-network")) {
		t.Errorf("both denials should be listed, got: %s", got)
	}
}

func TestServeHTTP_RejectsOversizedBody(t *testing.T) {
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	big := make([]byte, maxBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Error("oversized body must be rejected")
	}
}

func TestReview_ScanTimeoutBranch(t *testing.T) {
	// Exercises the ScanTimeout>0 context-with-timeout branch.
	h := &Handler{
		Scanner:     &fakeScanner{findings: []checker.Finding{{Checker: "x", Severity: checker.SeverityLow, Resource: "web", Message: "m"}}},
		FailOn:      checker.SeverityHigh,
		ScanTimeout: time.Second,
	}
	resp := post(t, h, reviewFor(t, samplePod))
	if !resp.Allowed || len(resp.Warnings) != 1 {
		t.Fatalf("expected allow+1 warning with timeout set: %+v", resp)
	}
}

// slowScanner blocks until its context is cancelled, simulating a runaway scan.
type slowScanner struct{}

func (slowScanner) ScanObject(ctx context.Context, _ unstructured.Unstructured) (*checker.ScanResult, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestReview_DeniesAmplificationObject(t *testing.T) {
	// A Pod padded with far more than maxContainers must be DENIED at the source,
	// before any scan runs — closing the fail-open-on-demand bypass.
	containers := make([]any, maxContainers+50)
	for i := range containers {
		containers[i] = map[string]any{"name": "c", "image": "nginx"}
	}
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	resp := post(t, h, reviewFor(t, map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "bomb", "namespace": "default"},
		"spec":     map[string]any{"containers": containers},
	}))
	if resp.Allowed {
		t.Fatal("amplification-shaped object must be denied, not scanned")
	}
	if resp.Result == nil || resp.Result.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %+v", resp.Result)
	}
}

func TestReview_TimeoutFailsOpen(t *testing.T) {
	// A scan that never returns must not block the handler: it fails open after
	// ScanTimeout so the API server is not held up.
	h := &Handler{Scanner: slowScanner{}, FailOn: checker.SeverityHigh, ScanTimeout: 50 * time.Millisecond}
	resp := post(t, h, reviewFor(t, samplePod))
	if !resp.Allowed {
		t.Fatal("a scan timeout must fail open (allow), not block")
	}
	if len(resp.Warnings) == 0 {
		t.Error("timeout should surface a warning")
	}
}

func TestReview_CapsReportedFindings(t *testing.T) {
	// Many denials must be truncated with a summary line, bounding response size.
	findings := make([]checker.Finding, maxReportedFindings+20)
	for i := range findings {
		findings[i] = checker.Finding{Checker: "c", Severity: checker.SeverityHigh, Resource: "web", Message: "m"}
	}
	h := &Handler{Scanner: &fakeScanner{findings: findings}, FailOn: checker.SeverityHigh}
	resp := post(t, h, reviewFor(t, samplePod))
	if resp.Allowed {
		t.Fatal("should deny")
	}
	// The message lists at most maxReportedFindings + 1 truncation line.
	lines := bytes.Count([]byte(resp.Result.Message), []byte("\n"))
	if lines > maxReportedFindings+2 {
		t.Errorf("denial message not truncated: %d lines", lines)
	}
	if !bytes.Contains([]byte(resp.Result.Message), []byte("truncated")) {
		t.Error("expected a truncation marker")
	}
}

func TestContainerCount_WorkloadAndCronJob(t *testing.T) {
	// Deployment template.
	dep := map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers":     []any{map[string]any{}, map[string]any{}},
		"initContainers": []any{map[string]any{}},
	}}}}
	if got := containerCount(dep); got != 3 {
		t.Errorf("deployment containerCount = %d, want 3", got)
	}
	// CronJob nests deeper.
	cj := map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{
		"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{}}}},
	}}}}
	if got := containerCount(cj); got != 1 {
		t.Errorf("cronjob containerCount = %d, want 1", got)
	}
	// No spec.
	if got := containerCount(map[string]any{"kind": "ConfigMap"}); got != 0 {
		t.Errorf("no-spec containerCount = %d, want 0", got)
	}
}

func TestServeHTTP_AcceptsContentTypeWithParams(t *testing.T) {
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
		"request": map[string]any{"uid": "u", "object": samplePod},
	})
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("content-type with charset should be accepted, got %d", rr.Code)
	}
}
