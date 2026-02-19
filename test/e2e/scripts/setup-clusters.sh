#!/usr/bin/env bash
# KubeVigil E2E — Setup Kind Clusters
#
# Creates Kind clusters for E2E testing using pre-defined configurations.
#
# Usage:
#   ./setup-clusters.sh [--topology single|multi|ha|all] [--k8s-version VERSION] [--dry-run] [--help]
#
# Options:
#   --topology TOPOLOGY   Cluster topology: single, multi, ha, all (default: single)
#   --k8s-version VER     Kubernetes version for Kind node image (default: latest)
#   --dry-run             Print commands without executing them
#   --help                Show this help message

set -euo pipefail

# Source shared helpers.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/helpers.sh"

# ---------------------------------------------------------------------------
# Constants (bash 3.2 compatible — no associative arrays)
# ---------------------------------------------------------------------------

TOPOLOGIES="single multi ha"

# cluster_name_for returns the Kind cluster name for a topology.
cluster_name_for() {
    case "${1}" in
        single) echo "kubevigil-e2e-single" ;;
        multi)  echo "kubevigil-e2e-multi" ;;
        ha)     echo "kubevigil-e2e-ha" ;;
        *)      echo "" ;;
    esac
}

# cluster_config_for returns the Kind config file path for a topology.
cluster_config_for() {
    case "${1}" in
        single) echo "${E2E_ROOT}/clusters/kind-single-node.yaml" ;;
        multi)  echo "${E2E_ROOT}/clusters/kind-multi-node.yaml" ;;
        ha)     echo "${E2E_ROOT}/clusters/kind-ha-control-plane.yaml" ;;
        *)      echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Create Kind clusters for KubeVigil E2E testing.

Options:
  --topology TOPOLOGY   Cluster topology: single, multi, ha, all (default: single)
  --k8s-version VER     Kubernetes version for Kind node image (default: latest available)
  --dry-run             Print commands without executing them
  --help                Show this help message

Examples:
  $(basename "$0")                          # Create single-node cluster
  $(basename "$0") --topology multi         # Create multi-node cluster
  $(basename "$0") --topology all           # Create all three clusters
  $(basename "$0") --topology single --k8s-version 1.30
EOF
}

# ---------------------------------------------------------------------------
# Core Logic
# ---------------------------------------------------------------------------

# create_cluster creates a single Kind cluster for the given topology.
create_cluster() {
    local topo="${1:?topology required}"
    local k8s_version="${2:-}"
    local dry_run="${3:-false}"

    local name
    name="$(cluster_name_for "${topo}")"
    local config
    config="$(cluster_config_for "${topo}")"

    if [[ ! -f "${config}" ]]; then
        log_error "Config file not found: ${config}"
        return 1
    fi

    if [[ "${dry_run}" == "false" ]] && cluster_exists "${name}"; then
        log_info "Cluster '${name}' already exists — skipping creation."
        return 0
    fi

    local cmd="kind create cluster --name ${name} --config ${config}"

    if [[ -n "${k8s_version}" ]]; then
        cmd="${cmd} --image kindest/node:v${k8s_version}"
    fi

    if [[ "${dry_run}" == "true" ]]; then
        log_info "[dry-run] Would create cluster '${name}' (topology: ${topo})"
        log_info "[dry-run] Config: ${config}"
        log_info "[dry-run] Command: ${cmd}"
        return 0
    fi

    log_info "Creating Kind cluster '${name}' (topology: ${topo})..."
    log_info "Command: ${cmd}"

    eval "${cmd}"

    local context="kind-${name}"
    wait_for_nodes_ready "${context}" 180

    log_success "Cluster '${name}' is ready (context: ${context})."
    kubectl --context "${context}" get nodes
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local topology="single"
    local k8s_version=""
    local dry_run=false

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
            --dry-run)
                dry_run=true
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

    # Validate topology.
    if [[ "${topology}" != "all" ]]; then
        local valid=false
        for t in ${TOPOLOGIES}; do
            if [[ "${topology}" == "${t}" ]]; then
                valid=true
                break
            fi
        done
        if [[ "${valid}" == "false" ]]; then
            log_error "Invalid topology: '${topology}'. Must be one of: single, multi, ha, all"
            exit 1
        fi
    fi

    check_prerequisites

    if [[ "${topology}" == "all" ]]; then
        for t in ${TOPOLOGIES}; do
            create_cluster "${t}" "${k8s_version}" "${dry_run}"
        done
    else
        create_cluster "${topology}" "${k8s_version}" "${dry_run}"
    fi

    log_success "Setup complete."
}

main "$@"
