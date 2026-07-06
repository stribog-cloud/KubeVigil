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
	"mime"
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

// maxContainers caps the number of containers (across containers,
// initContainers, ephemeralContainers, at both pod and template level) the
// webhook will scan. A byte cap alone is insufficient: a ~1.6 MiB Pod padded
// with tens of thousands of trivial containers stays under maxBodyBytes yet
// amplifies into hundreds of thousands of findings — enough CPU/memory to OOM
// or time out the webhook, which under failurePolicy: Ignore then silently
// admits the object. No legitimate workload approaches this, so such an object
// is DENIED outright (this is the object itself being hostile, not an internal
// error, so failing closed here is correct and safe).
const maxContainers = 100

// maxReportedFindings caps how many finding lines are listed in a denial
// message or warning array, bounding response size regardless of scan volume.
const maxReportedFindings = 50

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
	// Accept application/json with or without parameters (e.g. "; charset=utf-8")
	// so a stricter equality check can't cause a self-inflicted 415 on every
	// request — which under failurePolicy: Fail would be a cluster outage.
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
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

	// Reject amplification-shaped objects before scanning them. This is the one
	// place the webhook fails CLOSED: the object itself is the attack, and no
	// real workload has this many containers.
	if n := containerCount(obj.Object); n > maxContainers {
		slog.Warn("admission denied: object exceeds container limit", "kind", obj.GetKind(), "name", obj.GetName(), "containers", n)
		resp.Allowed = false
		resp.Result = &metav1.Status{
			Message: fmt.Sprintf("kubevigil denied admission: object declares %d containers, exceeding the webhook limit of %d (suspected amplification)", n, maxContainers),
			Reason:  metav1.StatusReasonForbidden,
			Code:    http.StatusForbidden,
		}
		return resp
	}

	scanCtx := ctx
	if h.ScanTimeout > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, h.ScanTimeout)
		defer cancel()
	}

	// Run the scan in a goroutine so a runaway checker (Go cannot preempt a
	// CPU-bound goroutine) still bounds the HANDLER's response time: on timeout
	// we fail open and return, letting the API server proceed rather than
	// blocking admission for the whole cluster.
	type outcome struct {
		result *checker.ScanResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, e := h.Scanner.ScanObject(scanCtx, obj)
		done <- outcome{r, e}
	}()

	var result *checker.ScanResult
	select {
	case <-scanCtx.Done():
		slog.Warn("admission scan exceeded timeout; allowing", "kind", obj.GetKind(), "name", obj.GetName())
		resp.Allowed = true
		resp.Warnings = []string{"kubevigil: scan timed out; allowed without a verdict"}
		return resp
	case out := <-done:
		if out.err != nil {
			slog.Warn("admission scan error; allowing", "error", out.err, "kind", obj.GetKind(), "name", obj.GetName())
			resp.Allowed = true
			resp.Warnings = []string{fmt.Sprintf("kubevigil: scan error (%v); allowed without a verdict", out.err)}
			return resp
		}
		result = out.result
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
				len(denials), h.FailOn, joinLines(capReported(denials))),
			Reason: metav1.StatusReasonForbidden,
			Code:   http.StatusForbidden,
		}
		// Sub-threshold findings still ride along as warnings on a denial.
		resp.Warnings = prefix(capReported(warnings))
		return resp
	}

	resp.Allowed = true
	resp.Warnings = prefix(capReported(warnings))
	return resp
}

// capReported truncates a finding-line slice to maxReportedFindings, appending
// a summary line when truncated, so a scan with many findings can never build
// an unbounded response.
func capReported(lines []string) []string {
	if len(lines) <= maxReportedFindings {
		return lines
	}
	out := make([]string, 0, maxReportedFindings+1)
	out = append(out, lines[:maxReportedFindings]...)
	out = append(out, fmt.Sprintf("... and %d more finding(s) (truncated)", len(lines)-maxReportedFindings))
	return out
}

// containerCount totals the containers a pod-bearing object declares, at both
// the pod level (spec.containers/initContainers/ephemeralContainers) and the
// workload-template level (spec.template.spec.*). It is a bounded structural
// walk used only to reject amplification-shaped objects.
func containerCount(obj map[string]any) int {
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil {
		return 0
	}
	n := podSpecContainers(spec)
	if tmpl, ok := spec["template"].(map[string]any); ok {
		if tspec, ok := tmpl["spec"].(map[string]any); ok {
			n += podSpecContainers(tspec)
		}
	}
	// CronJob nests one level deeper: spec.jobTemplate.spec.template.spec.
	if jt, ok := spec["jobTemplate"].(map[string]any); ok {
		if jspec, ok := jt["spec"].(map[string]any); ok {
			if tmpl, ok := jspec["template"].(map[string]any); ok {
				if tspec, ok := tmpl["spec"].(map[string]any); ok {
					n += podSpecContainers(tspec)
				}
			}
		}
	}
	return n
}

func podSpecContainers(podSpec map[string]any) int {
	n := 0
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		if arr, ok := podSpec[key].([]any); ok {
			n += len(arr)
		}
	}
	return n
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
