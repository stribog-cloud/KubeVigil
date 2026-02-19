#!/usr/bin/env bash
# KubeVigil E2E — Deploy Scenario Manifests
#
# Deploys vulnerable workload manifests to a Kind cluster for security scanning.
#
# Usage:
#   ./deploy-scenarios.sh [--scenario CATEGORY|all] [--context CONTEXT] [--clean] [--help]
#
# Options:
#   --scenario CATEGORY   Deploy a specific scenario category or 'all' (default: all)
#   --context CONTEXT     Kubeconfig context (default: kind-kubevigil-e2e-single)
#   --clean               Delete existing kv-e2e-* namespaces before deploying
#   --help                Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/helpers.sh"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCENARIOS_DIR="${E2E_ROOT}/scenarios"
ALL_SCENARIOS=(
    workload-security
    image-security
    rbac
    network
    secrets
    psa
    cluster-hardening
    scheduling
    storage
    clean
    mixed
)

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Deploy E2E scenario manifests to a Kind cluster.

Options:
  --scenario CATEGORY   Scenario category to deploy (default: all)
                        Categories: ${ALL_SCENARIOS[*]}
  --context CONTEXT     Kubeconfig context (default: kind-kubevigil-e2e-single)
  --clean               Delete existing kv-e2e-* namespaces before deploying
  --help                Show this help message

Examples:
  $(basename "$0")                                          # Deploy all scenarios
  $(basename "$0") --scenario workload-security             # Deploy only workload scenarios
  $(basename "$0") --context kind-kubevigil-e2e-multi --clean
EOF
}

# ---------------------------------------------------------------------------
# Core Logic
# ---------------------------------------------------------------------------

deploy_scenario() {
    local category="${1:?category required}"
    local context="${2:?context required}"
    local scenario_dir="${SCENARIOS_DIR}/${category}"

    if [[ ! -d "${scenario_dir}" ]]; then
        log_warn "Scenario directory not found: ${scenario_dir} — skipping."
        return 0
    fi

    local yaml_count
    yaml_count=$(find "${scenario_dir}" -name '*.yaml' -o -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')

    if [[ "${yaml_count}" -eq 0 ]]; then
        log_warn "No YAML files in ${scenario_dir} — skipping."
        return 0
    fi

    log_info "Deploying scenario '${category}' (${yaml_count} files)..."

    # Apply namespace.yaml first if it exists.
    if [[ -f "${scenario_dir}/namespace.yaml" ]]; then
        kubectl --context "${context}" apply -f "${scenario_dir}/namespace.yaml" 2>/dev/null || true
    fi

    # Apply all manifests in the directory.
    # Use || true because some manifests intentionally contain invalid
    # resources (e.g., ephemeral containers on create, PSPs on K8s 1.25+)
    # that fail to apply. We still want to continue deploying remaining
    # scenarios.
    kubectl --context "${context}" apply -f "${scenario_dir}/" --recursive 2>&1 | while read -r line; do
        log_info "  ${line}"
    done || true

    log_success "Scenario '${category}': ${yaml_count} manifest files applied."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local scenario="all"
    local context="kind-kubevigil-e2e-single"
    local clean=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scenario)
                scenario="${2:?--scenario requires a value}"
                shift 2
                ;;
            --context)
                context="${2:?--context requires a value}"
                shift 2
                ;;
            --clean)
                clean=true
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

    # Validate scenario.
    if [[ "${scenario}" != "all" ]]; then
        local valid=false
        for s in "${ALL_SCENARIOS[@]}"; do
            if [[ "${scenario}" == "${s}" ]]; then
                valid=true
                break
            fi
        done
        if [[ "${valid}" == "false" ]]; then
            log_error "Invalid scenario: '${scenario}'. Must be one of: ${ALL_SCENARIOS[*]}, all"
            exit 1
        fi
    fi

    check_prerequisites

    # Clean existing namespaces if requested.
    if [[ "${clean}" == "true" ]]; then
        log_info "Cleaning existing E2E namespaces..."
        delete_e2e_namespaces "${context}"
    fi

    # Deploy scenarios.
    local deployed=0
    if [[ "${scenario}" == "all" ]]; then
        for s in "${ALL_SCENARIOS[@]}"; do
            deploy_scenario "${s}" "${context}"
            deployed=$((deployed + 1))
        done
    else
        deploy_scenario "${scenario}" "${context}"
        deployed=1
    fi

    log_success "Deployment complete: ${deployed} scenario(s) deployed to context '${context}'."

    # Print summary of resources in E2E namespaces.
    log_info "Resource summary:"
    kubectl --context "${context}" get all --all-namespaces 2>/dev/null \
        | grep 'kv-e2e-\|default' \
        | head -50 || true
}

main "$@"
