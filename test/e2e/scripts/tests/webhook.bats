#!/usr/bin/env bats
# KubeVigil E2E — Admission Webhook Command Tests (11 tests)
#
# Validates `kubevigil webhook` end-to-end: config/flag validation (missing
# TLS material, invalid --fail-on, --help) and the live HTTPS admission
# server (/healthz, /validate) using a self-signed certificate on an
# ephemeral localhost port. No live Kubernetes cluster or API server is
# required — these tests exercise the webhook's HTTP server directly.
#
# All kubevigil invocations use the real binary built from source.
# No mocking — these are true E2E tests.

load test_helper

# Path to the kubevigil binary (built by go build).
KUBEVIGIL=""

# PID and port of a webhook server started by start_webhook_server, if any.
WEBHOOK_PID=""
WEBHOOK_PORT=""

# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

setup() {
    # Call the shared setup for temp dirs and PATH.
    BATS_TEST_TMPDIR="$(mktemp -d)"
    export BATS_TEST_TMPDIR

    MOCK_DIR="$(mktemp -d)"
    export MOCK_DIR
    export PATH="${MOCK_DIR}:${ORIGINAL_PATH}"

    # Find or build the kubevigil binary.
    if [[ -x "${PROJECT_ROOT}/bin/kubevigil" ]]; then
        KUBEVIGIL="${PROJECT_ROOT}/bin/kubevigil"
    elif command -v kubevigil &>/dev/null; then
        KUBEVIGIL="kubevigil"
    else
        skip "kubevigil binary not found — run 'make build' first"
    fi

    WEBHOOK_PID=""
    WEBHOOK_PORT=""
}

teardown() {
    stop_webhook_server

    export PATH="${ORIGINAL_PATH}"
    if [[ -n "${BATS_TEST_TMPDIR:-}" && -d "${BATS_TEST_TMPDIR}" ]]; then
        rm -rf "${BATS_TEST_TMPDIR}"
    fi
    if [[ -n "${MOCK_DIR:-}" && -d "${MOCK_DIR}" ]]; then
        rm -rf "${MOCK_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# Server lifecycle helpers
# ---------------------------------------------------------------------------

# gen_cert writes a self-signed localhost cert/key pair into BATS_TEST_TMPDIR.
gen_cert() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${BATS_TEST_TMPDIR}/tls.key" -out "${BATS_TEST_TMPDIR}/tls.crt" \
        -days 1 -nodes -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1
}

# start_webhook_server generates a cert, picks a high ephemeral localhost
# port, and starts `kubevigil webhook` in the background, polling /healthz
# until it responds (or failing the test after ~5s). Extra args are appended
# to the invocation (e.g. --fail-on).
start_webhook_server() {
    gen_cert
    WEBHOOK_PORT=$((18600 + (RANDOM % 300)))

    "${KUBEVIGIL}" webhook \
        --tls-cert "${BATS_TEST_TMPDIR}/tls.crt" \
        --tls-key "${BATS_TEST_TMPDIR}/tls.key" \
        --addr "127.0.0.1:${WEBHOOK_PORT}" \
        "$@" \
        >"${BATS_TEST_TMPDIR}/webhook.log" 2>&1 &
    WEBHOOK_PID=$!

    local i=0
    until curl -sk -o /dev/null -m 1 "https://127.0.0.1:${WEBHOOK_PORT}/healthz" 2>/dev/null; do
        i=$((i + 1))
        if [[ "${i}" -ge 50 ]]; then
            echo "webhook server did not become ready on port ${WEBHOOK_PORT}" >&2
            cat "${BATS_TEST_TMPDIR}/webhook.log" >&2
            return 1
        fi
        sleep 0.1
    done
}

# stop_webhook_server kills the background server started by
# start_webhook_server, if it is still running. Safe to call unconditionally
# (e.g. from teardown) even when no server was started.
stop_webhook_server() {
    if [[ -n "${WEBHOOK_PID:-}" ]] && kill -0 "${WEBHOOK_PID}" 2>/dev/null; then
        kill "${WEBHOOK_PID}" 2>/dev/null
        wait "${WEBHOOK_PID}" 2>/dev/null
    fi
    WEBHOOK_PID=""
}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

# curl_status POSTs (or GETs) to the running webhook server and prints only
# the numeric HTTP status code.
#
# Usage:
#   curl_status GET /healthz
#   curl_status POST /validate application/json '{"...":"..."}'
curl_status() {
    local method="${1:?method required}"
    local path="${2:?path required}"
    local content_type="${3:-}"
    local body="${4:-}"

    if [[ -n "${content_type}" ]]; then
        curl -sk -m 5 -o /dev/null -w "%{http_code}" -X "${method}" \
            -H "Content-Type: ${content_type}" -d "${body}" \
            "https://127.0.0.1:${WEBHOOK_PORT}${path}"
    else
        curl -sk -m 5 -o /dev/null -w "%{http_code}" -X "${method}" \
            "https://127.0.0.1:${WEBHOOK_PORT}${path}"
    fi
}

# admission_field POSTs an AdmissionReview wrapping the given object JSON to
# /validate and prints one field from the decoded response: "allowed" (the
# literal "true"/"false"), "code" (the numeric status code, if denied), or
# "message" (the denial message, if denied).
admission_field() {
    local object_json="${1:?object json required}"
    local field="${2:?field required (allowed|code|message)}"
    local review
    review=$(printf '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"test-uid","object":%s}}' "${object_json}")

    curl -sk -m 5 -X POST -H "Content-Type: application/json" \
        -d "${review}" "https://127.0.0.1:${WEBHOOK_PORT}/validate" \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
resp = data.get('response', {})
field = '${field}'
if field == 'allowed':
    print(str(bool(resp.get('allowed', False))).lower())
elif field == 'code':
    print(resp.get('status', {}).get('code', ''))
elif field == 'message':
    print(resp.get('status', {}).get('message', ''))
"
}

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

# privileged_pod_json is a bare Pod with a privileged container — trips the
# built-in "privileged" checker at Critical severity, which is at or above
# the default "high" --fail-on threshold.
privileged_pod_json() {
    cat <<'EOF'
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web","namespace":"default"},"spec":{"containers":[{"name":"app","image":"nginx","securityContext":{"privileged":true}}]}}
EOF
}

# benign_configmap_json is a ConfigMap with an innocuous data value — no
# workload checkers apply to a ConfigMap's GVR, and its data does not match
# any secret-like key name or high-entropy value, so it produces zero
# findings and is unconditionally allowed.
benign_configmap_json() {
    cat <<'EOF'
{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cfg","namespace":"default"},"data":{"greeting":"hello"}}
EOF
}

# ---------------------------------------------------------------------------
# 1. Missing --tls-cert and --tls-key exits 3
# ---------------------------------------------------------------------------
@test "webhook: missing --tls-cert and --tls-key exits 3" {
    run "${KUBEVIGIL}" webhook
    assert_exit_code 3
    assert_output_contains "requires --tls-cert and --tls-key"
}

# ---------------------------------------------------------------------------
# 2. --tls-cert without --tls-key exits 3
# ---------------------------------------------------------------------------
@test "webhook: --tls-cert without --tls-key exits 3" {
    run "${KUBEVIGIL}" webhook --tls-cert "${BATS_TEST_TMPDIR}/tls.crt"
    assert_exit_code 3
    assert_output_contains "requires --tls-cert and --tls-key"
}

# ---------------------------------------------------------------------------
# 3. Invalid --fail-on exits 3
# ---------------------------------------------------------------------------
@test "webhook: invalid --fail-on exits 3" {
    run "${KUBEVIGIL}" webhook --fail-on bogus
    # This error is returned as a silent exitError (cobra's SilenceErrors
    # suppresses the message; only the exit code is asserted here), same as
    # the equivalent scan --fail-on-new test in policy-baseline.bats.
    assert_exit_code 3
}

# ---------------------------------------------------------------------------
# 4. --help prints usage and describes the admission webhook
# ---------------------------------------------------------------------------
@test "webhook: --help prints usage" {
    run "${KUBEVIGIL}" webhook --help
    assert_exit_code 0
    assert_output_contains "Usage:"
    assert_output_contains "ValidatingAdmissionWebhook"
    assert_output_contains "--tls-cert"
    assert_output_contains "--fail-on"
}

# ---------------------------------------------------------------------------
# 5. /healthz returns 200
# ---------------------------------------------------------------------------
@test "webhook: /healthz returns 200" {
    start_webhook_server

    run curl_status GET /healthz
    assert_output_contains "200"
}

# ---------------------------------------------------------------------------
# 6. A privileged pod is denied admission (403)
# ---------------------------------------------------------------------------
@test "webhook: privileged pod is denied admission" {
    start_webhook_server

    local pod
    pod="$(privileged_pod_json)"

    run admission_field "${pod}" allowed
    assert_output_contains "false"

    run admission_field "${pod}" code
    assert_output_contains "403"

    run admission_field "${pod}" message
    assert_output_contains "privileged"
}

# ---------------------------------------------------------------------------
# 7. A benign object is allowed
# ---------------------------------------------------------------------------
@test "webhook: benign object is allowed" {
    start_webhook_server

    run admission_field "$(benign_configmap_json)" allowed
    assert_output_contains "true"
}

# ---------------------------------------------------------------------------
# 8. Malformed AdmissionReview body returns 400
# ---------------------------------------------------------------------------
@test "webhook: malformed AdmissionReview returns 400" {
    start_webhook_server

    run curl_status POST /validate application/json '{not json'
    assert_output_contains "400"
}

# ---------------------------------------------------------------------------
# 9. AdmissionReview with no request field returns 400
# ---------------------------------------------------------------------------
@test "webhook: AdmissionReview with no request field returns 400" {
    start_webhook_server

    run curl_status POST /validate application/json '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}'
    assert_output_contains "400"
}

# ---------------------------------------------------------------------------
# 10. Non-JSON content type returns 415
# ---------------------------------------------------------------------------
@test "webhook: non-JSON content type returns 415" {
    start_webhook_server

    run curl_status POST /validate text/plain '{}'
    assert_output_contains "415"
}

# ---------------------------------------------------------------------------
# 11. Non-POST request to /validate returns 405
# ---------------------------------------------------------------------------
@test "webhook: non-POST request to /validate returns 405" {
    start_webhook_server

    run curl_status GET /validate
    assert_output_contains "405"
}
