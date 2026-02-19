#!/usr/bin/env bash
# KubeVigil E2E — Run Fix Tests (Live Cluster Mode)
#
# Creates a Kind cluster, deploys insecure workloads, scans them,
# generates kubectl patches, applies patches to the cluster,
# re-scans to verify finding reduction, and cleans up.
#
# Usage:
#   ./run-fix-live.sh [--skip-build] [--keep-cluster]
#
# Requirements:
#   - Go 1.22+, kind, kubectl, python3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/helpers.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLUSTER_NAME="kubevigil-fix-e2e"
CLUSTER_CONTEXT="kind-${CLUSTER_NAME}"
KUBEVIGIL=""
SCENARIOS="${E2E_ROOT}/scenarios"
RESULTS_DIR=""
PASS_COUNT=0
FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run KubeVigil fix E2E tests against a live Kind cluster.

Options:
  --skip-build    Skip building the binary
  --keep-cluster  Do not delete the Kind cluster on exit
  --help          Show this help message

This script:
  1. Creates a Kind cluster
  2. Deploys insecure workloads from fix-safe scenarios
  3. Scans and generates kubectl patches
  4. Applies patches to the live cluster
  5. Re-scans to verify finding reduction
  6. Cleans up
EOF
}

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

build_kubevigil() {
    log_info "Building kubevigil..."
    (cd "${PROJECT_ROOT}" && go build -o bin/kubevigil ./cmd/kubevigil/)
    KUBEVIGIL="${PROJECT_ROOT}/bin/kubevigil"
    log_success "Built: ${KUBEVIGIL}"
}

find_kubevigil() {
    if [[ -x "${PROJECT_ROOT}/bin/kubevigil" ]]; then
        KUBEVIGIL="${PROJECT_ROOT}/bin/kubevigil"
    elif command -v kubevigil &>/dev/null; then
        KUBEVIGIL="kubevigil"
    else
        log_error "kubevigil binary not found."
        exit 2
    fi
}

create_cluster() {
    if cluster_exists "${CLUSTER_NAME}"; then
        log_info "Cluster ${CLUSTER_NAME} already exists."
    else
        log_info "Creating Kind cluster: ${CLUSTER_NAME}"
        kind create cluster --name "${CLUSTER_NAME}" --wait 60s
        log_success "Cluster created."
    fi
    wait_for_nodes_ready "${CLUSTER_CONTEXT}" 120
}

deploy_scenarios() {
    log_info "Deploying insecure workloads..."

    # Create a test namespace.
    create_namespace "${CLUSTER_CONTEXT}" "kv-fix-e2e"

    # Deploy fix-safe manifests to the test namespace.
    for f in "${SCENARIOS}"/fix-safe/*.yaml; do
        local basename
        basename=$(basename "${f}")
        if [[ "${basename}" == "namespace.yaml" ]]; then
            continue  # Skip namespace file, use our test namespace
        fi
        # Patch namespace to our test namespace and apply.
        sed 's/namespace: kv-e2e-fix-safe/namespace: kv-fix-e2e/' "${f}" | \
            kubectl --context "${CLUSTER_CONTEXT}" apply -f - 2>/dev/null || true
    done

    # Wait for deployments to be created.
    sleep 5
    log_success "Workloads deployed."
}

pass_test() {
    log_success "PASS: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail_test() {
    log_error "FAIL: $1 — ${2:-}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

# ---------------------------------------------------------------------------
# Test: Live Scan → Generate Patches → Apply → Re-scan
# ---------------------------------------------------------------------------

test_live_fix_workflow() {
    local name="Live fix workflow — scan → patch → re-scan"
    RESULTS_DIR="$(mktemp -d)"

    # Pre-scan.
    log_info "Running pre-fix scan..."
    local pre_scan="${RESULTS_DIR}/pre-scan.json"
    "${KUBEVIGIL}" scan --context "${CLUSTER_CONTEXT}" -n kv-fix-e2e -o json > "${pre_scan}" 2>/dev/null || true

    local pre_count
    pre_count=$(python3 -c "
import json
with open('${pre_scan}') as f:
    data = json.load(f)
findings = data.get('scan_result', data).get('findings', [])
print(len(findings))
" 2>/dev/null || echo "0")
    log_info "Pre-fix findings: ${pre_count}"

    if [[ "${pre_count}" -eq 0 ]]; then
        fail_test "${name}" "No findings in pre-scan (expected insecure workloads)"
        return
    fi

    # Generate kubectl patches from manifest-mode scan.
    log_info "Generating kubectl patches..."
    local workdir
    workdir="$(mktemp -d)/fix-safe"
    cp -r "${SCENARIOS}/fix-safe" "${workdir}"

    local patches="${RESULTS_DIR}/patches.sh"
    "${KUBEVIGIL}" fix "${workdir}" -o kubectl > "${patches}" 2>/dev/null || true

    # Apply patches to the live cluster (replace namespace).
    if [[ -s "${patches}" ]]; then
        log_info "Applying patches to live cluster..."
        sed 's/kv-e2e-fix-safe/kv-fix-e2e/g' "${patches}" | \
            grep '^kubectl' | \
            while IFS= read -r cmd; do
                eval "${cmd} --context ${CLUSTER_CONTEXT}" 2>/dev/null || true
            done
    fi

    # Wait for changes to propagate.
    sleep 5

    # Post-scan.
    log_info "Running post-fix scan..."
    local post_scan="${RESULTS_DIR}/post-scan.json"
    "${KUBEVIGIL}" scan --context "${CLUSTER_CONTEXT}" -n kv-fix-e2e -o json > "${post_scan}" 2>/dev/null || true

    local post_count
    post_count=$(python3 -c "
import json
with open('${post_scan}') as f:
    data = json.load(f)
findings = data.get('scan_result', data).get('findings', [])
print(len(findings))
" 2>/dev/null || echo "0")
    log_info "Post-fix findings: ${post_count}"

    if [[ "${post_count}" -lt "${pre_count}" ]]; then
        pass_test "${name}"
    else
        fail_test "${name}" "Findings not reduced: before=${pre_count} after=${post_count}"
    fi

    rm -rf "${workdir}"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    local keep_cluster="${1:-false}"

    if [[ "${keep_cluster}" = false ]]; then
        log_info "Deleting Kind cluster: ${CLUSTER_NAME}"
        kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
        log_success "Cluster deleted."
    else
        log_info "Keeping cluster: ${CLUSTER_NAME}"
    fi

    if [[ -n "${RESULTS_DIR}" && -d "${RESULTS_DIR}" ]]; then
        rm -rf "${RESULTS_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local skip_build=false
    local keep_cluster=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-build) skip_build=true; shift ;;
            --keep-cluster) keep_cluster=true; shift ;;
            --help) usage; exit 0 ;;
            *) log_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    log_info "KubeVigil Fix E2E Tests (Live Cluster Mode)"
    log_info "============================================"

    check_prerequisites

    if [[ "${skip_build}" = false ]]; then
        build_kubevigil
    else
        find_kubevigil
    fi

    # Trap cleanup.
    trap "cleanup ${keep_cluster}" EXIT

    create_cluster
    deploy_scenarios
    test_live_fix_workflow

    # Summary.
    echo ""
    log_info "============================================"
    log_info "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
    log_info "============================================"

    if [[ "${FAIL_COUNT}" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
