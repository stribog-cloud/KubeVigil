package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/config"
	"github.com/stribog-cloud/kubevigil/internal/engine"
	"github.com/stribog-cloud/kubevigil/internal/webhook"
)

// TestWebhook_RealEngineDeniesPrivilegedPod wires the real scan engine to the
// admission handler and confirms a privileged pod is denied over an HTTP
// round-trip — the full stack, not a fake scanner.
func TestWebhook_RealEngineDeniesPrivilegedPod(t *testing.T) {
	scanner := engine.NewScanner(checker.DefaultRegistry(), config.Default())
	h := &webhook.Handler{Scanner: scanner, FailOn: checker.SeverityHigh}

	body := admissionReviewJSON(t, map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "evil", "namespace": "default"},
		"spec": map[string]any{"containers": []any{map[string]any{
			"name": "c", "image": "nginx",
			"securityContext": map[string]any{"privileged": true},
		}}},
	})

	resp := doAdmission(t, h, body)
	assert.False(t, resp.Allowed, "privileged pod must be denied")
	require.NotNil(t, resp.Status)
	assert.Equal(t, int32(http.StatusForbidden), resp.Status.Code)
	assert.Contains(t, resp.Status.Message, "privileged")
}

func TestWebhook_RealEngineAllowsBenignObject(t *testing.T) {
	scanner := engine.NewScanner(checker.DefaultRegistry(), config.Default())
	h := &webhook.Handler{Scanner: scanner, FailOn: checker.SeverityCritical}

	body := admissionReviewJSON(t, map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "cm", "namespace": "default"},
		"data":     map[string]any{"key": "value"},
	})

	resp := doAdmission(t, h, body)
	assert.True(t, resp.Allowed, "a benign ConfigMap should be admitted at critical threshold")
}

// admissionResponse is a minimal decode target for the response.
type admissionResponse struct {
	Response struct {
		Allowed  bool     `json:"allowed"`
		Warnings []string `json:"warnings"`
		Status   *struct {
			Message string `json:"message"`
			Code    int32  `json:"code"`
		} `json:"status"`
	} `json:"response"`
}

func admissionReviewJSON(t *testing.T, obj map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request":    map[string]any{"uid": "it-1", "object": obj},
	})
	require.NoError(t, err)
	return b
}

func doAdmission(t *testing.T, h http.Handler, body []byte) struct {
	Allowed  bool
	Warnings []string
	Status   *struct {
		Message string
		Code    int32
	}
} {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

	var ar admissionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &ar))
	out := struct {
		Allowed  bool
		Warnings []string
		Status   *struct {
			Message string
			Code    int32
		}
	}{Allowed: ar.Response.Allowed, Warnings: ar.Response.Warnings}
	if ar.Response.Status != nil {
		out.Status = &struct {
			Message string
			Code    int32
		}{Message: ar.Response.Status.Message, Code: ar.Response.Status.Code}
	}
	return out
}
