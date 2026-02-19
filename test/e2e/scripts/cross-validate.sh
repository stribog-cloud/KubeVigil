#!/usr/bin/env bash
# KubeVigil E2E — Cross-Validate with Other Tools
#
# Runs competing security scanning tools against the same cluster for comparison.
#
# Usage:
#   ./cross-validate.sh [--context CONTEXT] [--results-dir DIR] [--tool TOOL] [--help]
#
# Options:
#   --context CONTEXT     Kubeconfig context (default: kind-kubevigil-e2e-single)
#   --results-dir DIR     Directory for saving results (default: <e2e>/results/<context>/<timestamp>/cross-validation)
#   --tool TOOL           Restrict to a specific tool (trivy, kubescape, polaris, kube-bench)
#   --help                Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/helpers.sh"

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run third-party security scanners for cross-validation against KubeVigil.

Supported tools (optional — skipped if not found on PATH):
  - trivy       (aquasecurity/trivy)
  - kubescape   (kubescape/kubescape)
  - polaris     (fairwindsops/polaris)
  - kube-bench  (aquasecurity/kube-bench)

Options:
  --context CONTEXT     Kubeconfig context (default: kind-kubevigil-e2e-single)
  --results-dir DIR     Directory for saving results
  --tool TOOL           Restrict to a specific tool
  --help                Show this help message

Examples:
  $(basename "$0")
  $(basename "$0") --context kind-kubevigil-e2e-multi
  $(basename "$0") --tool kubescape
EOF
}

# ---------------------------------------------------------------------------
# Tool install hints (bash 3.2 compatible — no associative arrays)
# ---------------------------------------------------------------------------

install_hint_for() {
    case "${1}" in
        trivy)      echo "brew install trivy" ;;
        kubescape)  echo "brew install kubescape" ;;
        polaris)    echo "brew install fairwindsops/tap/polaris" ;;
        kube-bench) echo "See https://github.com/aquasecurity/kube-bench#install" ;;
        *)          echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# Tool Runners
# ---------------------------------------------------------------------------

run_trivy() {
    local context="${1}"
    local output_dir="${2}"

    log_info "Running trivy k8s scan..."
    trivy k8s --context "${context}" --report summary \
        --output "${output_dir}/trivy-results.txt" 2>&1 || true
    log_success "trivy results saved to ${output_dir}/trivy-results.txt"
}

run_kubescape() {
    local context="${1}"
    local output_dir="${2}"

    log_info "Running kubescape scan..."
    kubescape scan --kube-context "${context}" \
        --format json --output "${output_dir}/kubescape-results.json" 2>&1 || true
    log_success "kubescape results saved to ${output_dir}/kubescape-results.json"
}

run_polaris() {
    local context="${1}"
    local output_dir="${2}"

    log_info "Running polaris audit..."
    polaris audit --kube-context "${context}" \
        --format json --output-file "${output_dir}/polaris-results.json" 2>&1 || true
    log_success "polaris results saved to ${output_dir}/polaris-results.json"
}

run_kube_bench() {
    local context="${1}"
    local output_dir="${2}"

    log_info "Running kube-bench..."
    kube-bench run --json > "${output_dir}/kube-bench-results.json" 2>&1 || true
    log_success "kube-bench results saved to ${output_dir}/kube-bench-results.json"
}

# run_tool dispatches to the correct runner function.
run_tool() {
    local tool="${1}"
    local context="${2}"
    local output_dir="${3}"

    case "${tool}" in
        trivy)      run_trivy "${context}" "${output_dir}" ;;
        kubescape)  run_kubescape "${context}" "${output_dir}" ;;
        polaris)    run_polaris "${context}" "${output_dir}" ;;
        kube-bench) run_kube_bench "${context}" "${output_dir}" ;;
    esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local context="kind-kubevigil-e2e-single"
    local results_dir=""
    local restrict_tool=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --context)
                context="${2:?--context requires a value}"
                shift 2
                ;;
            --results-dir)
                results_dir="${2:?--results-dir requires a value}"
                shift 2
                ;;
            --tool)
                restrict_tool="${2:?--tool requires a value}"
                shift 2
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Set default results dir if not specified.
    if [[ -z "${results_dir}" ]]; then
        local timestamp
        timestamp=$(date +"%Y%m%d-%H%M%S")
        results_dir="${E2E_ROOT}/results/${context}/${timestamp}/cross-validation"
    fi
    mkdir -p "${results_dir}"

    log_info "Cross-validation results will be saved to: ${results_dir}"

    local tools_run=0
    local tools_skipped=0
    local all_tools="trivy kubescape polaris kube-bench"

    # If --tool was specified, restrict to that tool.
    if [[ -n "${restrict_tool}" ]]; then
        all_tools="${restrict_tool}"
    fi

    for tool in ${all_tools}; do
        if command -v "${tool}" &>/dev/null; then
            run_tool "${tool}" "${context}" "${results_dir}"
            tools_run=$((tools_run + 1))
        else
            log_warn "${tool} not found on PATH — skipping. Install with: $(install_hint_for "${tool}")"
            tools_skipped=$((tools_skipped + 1))
        fi
    done

    # Print comparison summary.
    log_info "=== Cross-Validation comparison Summary ==="
    log_info "Tools run:    ${tools_run}"
    log_info "Tools skipped: ${tools_skipped}"
    log_info "Results saved to: ${results_dir}"

    if [[ "${tools_run}" -eq 0 ]]; then
        log_warn "No third-party tools were available. Install them for cross-validation."
    fi

    log_success "Cross-validation complete."
}

main "$@"
