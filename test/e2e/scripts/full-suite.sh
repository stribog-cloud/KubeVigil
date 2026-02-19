#!/usr/bin/env bash
# KubeVigil E2E — Full Test Suite
#
# Orchestrates the complete E2E flow:
#   1. Create Kind cluster
#   2. Deploy scenario manifests
#   3. Run KubeVigil scan
#   4. (Optional) Cross-validate with other tools
#   5. Teardown cluster
#
# Usage:
#   ./full-suite.sh [OPTIONS]
#
# Options:
#   --topology TOPOLOGY       Cluster topology (default: single)
#   --k8s-version VERSION     Kubernetes version (default: latest)
#   --keep-cluster            Skip teardown (useful for debugging)
#   --skip-cross-validate     Skip cross-validation step
#   --results-dir DIR         Results directory override
#   --yes                     Skip confirmation prompts
#   --help                    Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/helpers.sh"

# ---------------------------------------------------------------------------
# Helpers (bash 3.2 compatible — no associative arrays)
# ---------------------------------------------------------------------------

# context_for returns the kubectl context name for a topology.
context_for() {
    case "${1}" in
        single) echo "kind-kubevigil-e2e-single" ;;
        multi)  echo "kind-kubevigil-e2e-multi" ;;
        ha)     echo "kind-kubevigil-e2e-ha" ;;
        *)      echo "kind-kubevigil-e2e-single" ;;
    esac
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run the complete KubeVigil E2E test suite.

Steps: setup cluster -> deploy scenarios -> scan -> (cross-validate) -> teardown

Options:
  --topology TOPOLOGY       Cluster topology: single, multi, ha (default: single)
  --k8s-version VERSION     Kubernetes version for Kind (default: latest)
  --keep-cluster            Skip teardown at the end
  --skip-cross-validate     Skip third-party cross-validation
  --results-dir DIR         Results directory override
  --yes                     Skip confirmation prompts
  --help                    Show this help message

Examples:
  $(basename "$0")                                      # Full suite with single-node cluster
  $(basename "$0") --topology multi --keep-cluster      # Multi-node, keep cluster for debugging
  $(basename "$0") --skip-cross-validate                # Skip third-party tools
EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local topology="single"
    local k8s_version=""
    local keep_cluster=false
    local skip_cross_validate=false
    local results_dir=""
    local auto_yes=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --topology)
                topology="${2:?--topology requires a value}"
                shift 2
                ;;
            --k8s-version)
                k8s_version="${2:?--k8s-version requires a value}"
                shift 2
                ;;
            --keep-cluster)
                keep_cluster=true
                shift
                ;;
            --skip-cross-validate)
                skip_cross_validate=true
                shift
                ;;
            --results-dir)
                results_dir="${2:?--results-dir requires a value}"
                shift 2
                ;;
            --yes)
                auto_yes="--yes"
                shift
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

    check_prerequisites

    local context
    context="$(context_for "${topology}")"

    # Set up results and log directory.
    if [[ -z "${results_dir}" ]]; then
        local timestamp
        timestamp=$(date +"%Y%m%d-%H%M%S")
        results_dir="${E2E_ROOT}/results"
    fi
    mkdir -p "${results_dir}"
    local log_file="${results_dir}/full-suite-$(date +"%Y%m%d-%H%M%S").log"

    log_info "Full E2E suite starting. Log file: ${log_file}"
    log_info "Topology: ${topology}, Keep cluster: ${keep_cluster}, Skip cross validation: ${skip_cross_validate}"

    local scan_exit_code=0

    # Tee all output to the log file.
    exec > >(tee -a "${log_file}") 2>&1

    # find_script locates a sub-script. Checks PATH first (for testing/mocking),
    # then falls back to the co-located script in SCRIPT_DIR.
    find_script() {
        local name="${1}.sh"
        if command -v "${name}" &>/dev/null; then
            command -v "${name}"
        else
            echo "${SCRIPT_DIR}/${name}"
        fi
    }

    # Step 1: setup cluster.
    log_info "=== Step 1/5: setup Cluster ==="
    local setup_args=(--topology "${topology}")
    if [[ -n "${k8s_version}" ]]; then
        setup_args+=(--k8s-version "${k8s_version}")
    fi
    "$(find_script setup-clusters)" "${setup_args[@]}"

    # Step 2: deploy scenarios.
    log_info "=== Step 2/5: deploy Scenarios ==="
    "$(find_script deploy-scenarios)" --scenario all --context "${context}" --clean

    # Step 3: Run scan.
    log_info "=== Step 3/5: Run KubeVigil scan ==="
    "$(find_script run-scan)" --context "${context}" --results-dir "${results_dir}" || scan_exit_code=$?

    # Step 4: cross-validate (optional).
    if [[ "${skip_cross_validate}" == "false" ]]; then
        log_info "=== Step 4/5: cross-validate ==="
        "$(find_script cross-validate)" --context "${context}" --results-dir "${results_dir}" || true
    else
        log_info "=== Step 4/5: Cross-Validate (SKIPPED) ==="
    fi

    # Step 5: teardown (unless --keep-cluster).
    if [[ "${keep_cluster}" == "false" ]]; then
        log_info "=== Step 5/5: teardown Cluster ==="
        "$(find_script teardown-clusters)" --topology "${topology}" --yes
    else
        log_info "=== Step 5/5: Teardown (SKIPPED — --keep-cluster) ==="
        log_info "Cluster remains available. Context: ${context}"
        log_info "To delete later: kind delete cluster --name kubevigil-e2e-${topology}"
    fi

    # Final summary.
    log_info "========================================"
    log_info "E2E Suite Complete"
    log_info "  Topology:       ${topology}"
    log_info "  Context:        ${context}"
    log_info "  Scan exit code: ${scan_exit_code}"
    log_info "  Log file:       ${log_file}"
    log_info "  Results dir:    ${results_dir}"
    log_info "========================================"

    if [[ "${scan_exit_code}" -ne 0 ]]; then
        log_warn "Scan reported findings (exit code ${scan_exit_code})."
    else
        log_success "Scan completed with no critical findings."
    fi

    exit "${scan_exit_code}"
}

main "$@"
