#!/usr/bin/env bash
# KubeVigil E2E — Teardown Kind Clusters
#
# Destroys Kind clusters created by setup-clusters.sh.
#
# Usage:
#   ./teardown-clusters.sh [--topology single|multi|ha|all] [--yes] [--help]
#
# Options:
#   --topology TOPOLOGY   Cluster topology to teardown: single, multi, ha, all (default: all)
#   --yes                 Skip confirmation prompt (non-interactive mode)
#   --help                Show this help message

set -euo pipefail

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

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Destroy Kind clusters created for KubeVigil E2E testing.

Options:
  --topology TOPOLOGY   Cluster to teardown: single, multi, ha, all (default: all)
  --yes                 Skip confirmation prompt
  --help                Show this help message

Examples:
  $(basename "$0") --yes                    # Delete all E2E clusters non-interactively
  $(basename "$0") --topology single --yes  # Delete only the single-node cluster
EOF
}

# ---------------------------------------------------------------------------
# Core Logic
# ---------------------------------------------------------------------------

delete_cluster() {
    local topo="${1:?topology required}"
    local name
    name="$(cluster_name_for "${topo}")"

    if ! cluster_exists "${name}"; then
        log_info "Cluster '${name}' does not exist — nothing to delete."
        return 0
    fi

    log_info "Deleting Kind cluster '${name}'..."
    kind delete cluster --name "${name}"
    log_success "Cluster '${name}' deleted."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local topology="all"
    local auto_yes=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --topology)
                topology="${2:?--topology requires a value}"
                shift 2
                ;;
            --yes)
                auto_yes=true
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

    # Confirmation prompt.
    if [[ "${auto_yes}" == "false" ]]; then
        local targets
        if [[ "${topology}" == "all" ]]; then
            targets="all E2E clusters (single, multi, ha)"
        else
            targets="cluster '$(cluster_name_for "${topology}")'"
        fi
        printf "This will delete %s. Continue? [y/N] " "${targets}"
        read -r confirm
        if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
            log_info "Aborted."
            exit 0
        fi
    fi

    check_prerequisites

    if [[ "${topology}" == "all" ]]; then
        for t in ${TOPOLOGIES}; do
            delete_cluster "${t}"
        done
    else
        delete_cluster "${topology}"
    fi

    log_success "Teardown complete."
}

main "$@"
