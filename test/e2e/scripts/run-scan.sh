#!/usr/bin/env bash
# KubeVigil E2E — Run Security Scan
#
# Runs KubeVigil against a Kind cluster and saves results in multiple formats.
#
# Usage:
#   ./run-scan.sh [--context CONTEXT] [--output-format FORMAT] [--format FORMAT]
#                 [--results-dir DIR] [--profile PROFILE] [--help]
#
# Options:
#   --context CONTEXT       Kubeconfig context (default: kind-kubevigil-e2e-single)
#   --output-format FORMAT  Primary output format (default: json)
#   --format FORMAT         Alias for --output-format
#   --results-dir DIR       Results directory override
#   --profile PROFILE       Scan profile (default: standard)
#   --help                  Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/helpers.sh"

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run KubeVigil against a Kind cluster and save results.

Options:
  --context CONTEXT       Kubeconfig context (default: kind-kubevigil-e2e-single)
  --output-format FORMAT  Primary output format: text, json, html, etc. (default: json)
  --format FORMAT         Alias for --output-format
  --results-dir DIR       Results directory override
  --profile PROFILE       Scan profile (default: standard)
  --help                  Show this help message

Results are saved to: test/e2e/results/<context>/<timestamp>/

Examples:
  $(basename "$0")
  $(basename "$0") --context kind-kubevigil-e2e-multi --output-format html
EOF
}

# ---------------------------------------------------------------------------
# Core Logic
# ---------------------------------------------------------------------------

find_kubevigil() {
    # Honor KUBEVIGIL_BIN if explicitly set.
    if [[ -n "${KUBEVIGIL_BIN:-}" ]]; then
        if [[ -x "${KUBEVIGIL_BIN}" ]]; then
            echo "${KUBEVIGIL_BIN}"
            return 0
        fi
        log_error "KUBEVIGIL_BIN set to '${KUBEVIGIL_BIN}' but file not found or not executable."
        return 1
    fi

    # Check PATH first.
    if command -v kubevigil &>/dev/null; then
        echo "kubevigil"
        return 0
    fi

    # Look for the binary in common locations.
    local locations="${PROJECT_ROOT}/bin/kubevigil ${PROJECT_ROOT}/kubevigil"

    for loc in ${locations}; do
        if [[ -x "${loc}" ]]; then
            echo "${loc}"
            return 0
        fi
    done

    # Fall back to go run.
    if command -v go &>/dev/null; then
        echo "go run ${PROJECT_ROOT}/cmd/kubevigil/"
        return 0
    fi

    log_error "Cannot find kubevigil binary. Run 'make build' first or ensure Go is installed."
    return 1
}

run_kubevigil_scan() {
    local context="${1}"
    local format="${2}"
    local profile="${3}"
    local output_file="${4}"

    local kubevigil
    kubevigil=$(find_kubevigil)

    local cmd
    if [[ "${kubevigil}" == go\ run* ]]; then
        cmd="go run ${PROJECT_ROOT}/cmd/kubevigil/ scan"
    else
        cmd="${kubevigil} scan"
    fi

    cmd="${cmd} --context ${context} -o ${format}"

    if [[ -n "${profile}" ]]; then
        cmd="${cmd} --severity info"
    fi

    log_info "Running: ${cmd} > ${output_file}"
    eval "${cmd}" > "${output_file}" 2>&1 || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local context="kind-kubevigil-e2e-single"
    local output_format="json"
    local profile=""
    local results_dir=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --context)
                context="${2:?--context requires a value}"
                shift 2
                ;;
            --output-format)
                output_format="${2:?--output-format requires a value}"
                shift 2
                ;;
            --format)
                output_format="${2:?--format requires a value}"
                shift 2
                ;;
            --results-dir)
                results_dir="${2:?--results-dir requires a value}"
                shift 2
                ;;
            --profile)
                profile="${2:?--profile requires a value}"
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

    # Check kubevigil is available before checking other prerequisites.
    local kubevigil_path
    kubevigil_path="$(find_kubevigil)" || exit 1

    check_prerequisites

    # Create results directory.
    local timestamp
    timestamp=$(date +"%Y%m%d-%H%M%S")
    if [[ -z "${results_dir}" ]]; then
        results_dir="${E2E_ROOT}/results/${context}/${timestamp}"
    fi
    mkdir -p "${results_dir}"

    log_info "scan results will be saved to: ${results_dir}"

    # Run scans in multiple formats.
    local fmt ext
    for fmt in json text html; do
        case "${fmt}" in
            json) ext="json" ;;
            text) ext="txt" ;;
            html) ext="html" ;;
        esac
        local outfile="${results_dir}/scan-results.${ext}"
        run_kubevigil_scan "${context}" "${fmt}" "${profile}" "${outfile}"
        log_success "Saved ${fmt} results to ${outfile}"
    done

    # Print summary from JSON results.
    local json_file="${results_dir}/scan-results.json"
    if [[ -f "${json_file}" ]] && command -v python3 &>/dev/null; then
        log_info "=== Scan Summary ==="
        python3 -c "
import json, sys
try:
    with open('${json_file}') as f:
        data = json.load(f)
    findings = data.get('findings', [])
    total = len(findings)
    print(f'Total findings: {total}')
    by_sev = {}
    for f in findings:
        sev = f.get('severity', 'unknown')
        by_sev[sev] = by_sev.get(sev, 0) + 1
    print('By severity:')
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        if sev in by_sev:
            print(f'  {sev}: {by_sev[sev]}')
except Exception as e:
    print(f'Could not parse results: {e}', file=sys.stderr)
" 2>&1 || log_warn "Could not generate summary"
    fi

    # Check for critical findings.
    local has_critical=false
    if [[ -f "${json_file}" ]] && command -v python3 &>/dev/null; then
        has_critical=$(python3 -c "
import json
try:
    with open('${json_file}') as f:
        data = json.load(f)
    findings = data.get('findings', [])
    critical = [f for f in findings if f.get('severity') == 'Critical']
    print('true' if critical else 'false')
except:
    print('false')
" 2>/dev/null || echo "false")
    fi

    log_success "scan complete. Results in: ${results_dir}"

    if [[ "${has_critical}" == "true" ]]; then
        log_warn "Critical finding detected — exiting with code 1."
        exit 1
    fi

    exit 0
}

main "$@"
