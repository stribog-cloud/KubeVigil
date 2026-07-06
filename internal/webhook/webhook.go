// Package webhook implements a Kubernetes ValidatingAdmissionWebhook that runs
// KubeVigil's checkers (and any custom CEL policies) against admission requests
// in real time. It turns the auditor into a gate: an object whose findings meet
// or exceed a configured severity threshold is denied at admission; findings
// below the threshold are surfaced as admission warnings and the object is
// allowed. This is the v1.2.0 "runtime" surface.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

// maxBodyBytes bounds an admission request body to guard the webhook against
// resource exhaustion from a hostile or malformed AdmissionReview.
const maxBodyBytes = 3 << 20 // 3 MiB

// admissionGVK is the only AdmissionReview version this webhook speaks.
var admissionGVK = schema.GroupVersionKind{Group: "admission.k8s.io", Version: "v1", Kind: "AdmissionReview"}

// ObjectScanner scans a single object and returns its findings. *engine.Scanner
// satisfies this via ScanObject; the interface keeps the webhook decoupled from
// the engine package for testing.
type ObjectScanner interface {
	ScanObject(ctx context.Context, obj unstructured.Unstructured) (*checker.ScanResult, error)
}

// Handler validates admission requests against a scanner.
type Handler struct {
	// Scanner runs the checks against each admitted object.
	Scanner ObjectScanner
	// FailOn is the minimum severity that DENIES admission. Findings below it
	// become warnings. If SeverityInfo, any finding denies.
	FailOn checker.Severity
	// ScanTimeout bounds a single object scan.
	ScanTimeout time.Duration
}

// ServeHTTP implements the AdmissionReview request/response contract.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		http.Error(w, "expected Content-Type application/json", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "decoding AdmissionReview", http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "AdmissionReview has no request", http.StatusBadRequest)
		return
	}

	resp := h.review(r.Context(), review.Request)

	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: admissionGVK.GroupVersion().String(), Kind: admissionGVK.Kind},
		Response: resp,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		slog.Error("encoding AdmissionReview response", "error", err)
	}
}

// review scans the request object and builds an AdmissionResponse. It is
// fail-open on internal errors (allows with a warning) so a scanner bug or an
// unparseable object never blocks the whole cluster's admissions — a webhook
// that fails closed on its own bugs is a cluster-wide outage.
func (h *Handler) review(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{UID: req.UID}

	var obj unstructured.Unstructured
	if err := json.Unmarshal(req.Object.Raw, &obj.Object); err != nil || len(obj.Object) == 0 {
		resp.Allowed = true
		resp.Warnings = []string{"kubevigil: could not decode object; allowed without scanning"}
		return resp
	}

	scanCtx := ctx
	if h.ScanTimeout > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, h.ScanTimeout)
		defer cancel()
	}

	result, err := h.Scanner.ScanObject(scanCtx, obj)
	if err != nil {
		slog.Warn("admission scan error; allowing", "error", err, "kind", obj.GetKind(), "name", obj.GetName())
		resp.Allowed = true
		resp.Warnings = []string{fmt.Sprintf("kubevigil: scan error (%v); allowed without a verdict", err)}
		return resp
	}

	var denials, warnings []string
	for i := range result.Findings {
		f := &result.Findings[i]
		msg := findingLine(f)
		if f.Severity >= h.FailOn {
			denials = append(denials, msg)
		} else {
			warnings = append(warnings, msg)
		}
	}

	if len(denials) > 0 {
		resp.Allowed = false
		resp.Result = &metav1.Status{
			Message: fmt.Sprintf("kubevigil denied admission: %d finding(s) at or above %s severity:\n%s",
				len(denials), h.FailOn, joinLines(denials)),
			Reason: metav1.StatusReasonForbidden,
			Code:   http.StatusForbidden,
		}
		// Sub-threshold findings still ride along as warnings on a denial.
		resp.Warnings = prefix(warnings)
		return resp
	}

	resp.Allowed = true
	resp.Warnings = prefix(warnings)
	return resp
}

func findingLine(f *checker.Finding) string {
	loc := f.Resource
	if f.Namespace != "" {
		loc = f.Namespace + "/" + f.Resource
	}
	return fmt.Sprintf("[%s] %s (%s): %s", f.Severity, f.Checker, loc, f.Message)
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += "  - " + l
	}
	return out
}

// prefix tags each warning so operators can tell KubeVigil warnings apart in
// kubectl output. Returns nil for an empty slice (admission warnings are
// omitted when absent).
func prefix(warnings []string) []string {
	if len(warnings) == 0 {
		return nil
	}
	out := make([]string, len(warnings))
	for i, w := range warnings {
		out[i] = "kubevigil: " + w
	}
	return out
}
