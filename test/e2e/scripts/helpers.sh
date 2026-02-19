#!/usr/bin/env bash
# KubeVigil E2E Test Helpers
#
# Shared library sourced by all E2E orchestration scripts.
# Provides logging, prerequisite checks, Kind cluster management,
# namespace utilities, and common variables.
#
# Usage:
#   source "$(dirname "$0")/helpers.sh"
#
# Requirements:
#   - bash 3.2+ (macOS compatible, no GNU-specific flags)
#   - kind (for cluster operations)
#   - kubectl (for cluster interaction)

set -euo pipefail

# ---------------------------------------------------------------------------
# Directory Variables
# ---------------------------------------------------------------------------

# Directory where this script lives.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Root of the e2e test tree (test/e2e/).
E2E_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Project root (repository top level).
PROJECT_ROOT="$(cd "${E2E_ROOT}/../.." && pwd)"

# ---------------------------------------------------------------------------
# Color Constants
#
# Safe for terminals that support ANSI escapes. When stdout is not a TTY
# (e.g., CI logs piped to a file) colors are still emitted, which is fine
# for most CI renderers. Override by setting NO_COLOR=1 before sourcing.
# ---------------------------------------------------------------------------

if [[ "${NO_COLOR:-0}" == "1" ]]; then
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    NC=""
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
fi

# ---------------------------------------------------------------------------
# Logging Functions
#
# Each emits a timestamped, color-tagged line to stderr so that stdout
# remains clean for machine-parseable output.
# ---------------------------------------------------------------------------

# _timestamp returns the current time in HH:MM:SS format.
# Uses -j on macOS (BSD date) which is the default; also works with GNU date.
_timestamp() {
    date +"%H:%M:%S"
}

# log_info prints an informational message.
# Usage: log_info "Deploying scenario manifests"
log_info() {
    printf "${BLUE}[%s INFO]${NC}  %s\n" "$(_timestamp)" "$*" >&2
}

# log_warn prints a warning message.
# Usage: log_warn "Retrying in 5 seconds"
log_warn() {
    printf "${YELLOW}[%s WARN]${NC}  %s\n" "$(_timestamp)" "$*" >&2
}

# log_error prints an error message.
# Usage: log_error "Failed to create namespace"
log_error() {
    printf "${RED}[%s ERROR]${NC} %s\n" "$(_timestamp)" "$*" >&2
}

# log_success prints a success message.
# Usage: log_success "All nodes are Ready"
log_success() {
    printf "${GREEN}[%s OK]${NC}    %s\n" "$(_timestamp)" "$*" >&2
}

# ---------------------------------------------------------------------------
# Prerequisite Checks
# ---------------------------------------------------------------------------

# check_prerequisites verifies that required CLI tools are installed and
# reachable on PATH. Exits with code 2 and a descriptive error if any
# tool is missing.
check_prerequisites() {
    local missing=0

    if ! command -v kind &>/dev/null; then
        log_error "kind is not installed or not on PATH."
        log_error "Install it from: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
        missing=1
    fi

    if ! command -v kubectl &>/dev/null; then
        log_error "kubectl is not installed or not on PATH."
        log_error "Install it from: https://kubernetes.io/docs/tasks/tools/"
        missing=1
    fi

    if [[ "$missing" -ne 0 ]]; then
        log_error "Missing prerequisites. Cannot continue."
        exit 2
    fi

    log_info "Prerequisites satisfied: kind=$(kind version 2>/dev/null | head -1), kubectl=$(kubectl version --client -o yaml 2>/dev/null | grep gitVersion | awk '{print $2}')"
}

# ---------------------------------------------------------------------------
# Kind Cluster Helpers
# ---------------------------------------------------------------------------

# cluster_exists checks whether a Kind cluster with the given name exists.
# Returns 0 (true) if it exists, 1 (false) otherwise.
#
# Usage:
#   if cluster_exists "kubevigil-e2e-single"; then ...
cluster_exists() {
    local name="${1:?cluster name required}"
    kind get clusters 2>/dev/null | grep -qx "${name}"
}

# ---------------------------------------------------------------------------
# Kubernetes Helpers
# ---------------------------------------------------------------------------

# wait_for_nodes_ready polls the cluster until all nodes report Ready status
# or the timeout (in seconds) is exceeded.
#
# Usage:
#   wait_for_nodes_ready "kind-kubevigil-e2e-single" 120
wait_for_nodes_ready() {
    local context="${1:?kube context required}"
    local timeout="${2:-120}"
    local interval=5
    local elapsed=0

    log_info "Waiting up to ${timeout}s for all nodes to be Ready (context: ${context})"

    while true; do
        # Count total nodes and ready nodes. If they match and are non-zero,
        # all nodes are ready.
        local total
        local ready
        total=$(kubectl --context "${context}" get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
        ready=$(kubectl --context "${context}" get nodes --no-headers 2>/dev/null | grep -c ' Ready' || true)

        if [[ "${total}" -gt 0 && "${total}" == "${ready}" ]]; then
            log_success "All ${total} node(s) are Ready."
            return 0
        fi

        if [[ "${elapsed}" -ge "${timeout}" ]]; then
            log_error "Timed out after ${timeout}s waiting for nodes to be Ready."
            log_error "Current node status:"
            kubectl --context "${context}" get nodes 2>/dev/null >&2 || true
            return 1
        fi

        sleep "${interval}"
        elapsed=$((elapsed + interval))
    done
}

# create_namespace creates a namespace if it does not already exist.
#
# Usage:
#   create_namespace "kind-kubevigil-e2e-single" "kv-e2e-network"
create_namespace() {
    local context="${1:?kube context required}"
    local name="${2:?namespace name required}"

    if kubectl --context "${context}" get namespace "${name}" &>/dev/null; then
        log_info "Namespace '${name}' already exists."
    else
        kubectl --context "${context}" create namespace "${name}"
        log_success "Created namespace '${name}'."
    fi
}

# delete_e2e_namespaces deletes all namespaces whose names match the
# pattern kv-e2e-*. This is the standard cleanup routine run at the
# end of E2E test sessions.
#
# Usage:
#   delete_e2e_namespaces "kind-kubevigil-e2e-single"
delete_e2e_namespaces() {
    local context="${1:?kube context required}"

    local namespaces
    namespaces=$(kubectl --context "${context}" get namespaces -o name 2>/dev/null \
        | grep '/kv-e2e-' \
        | sed 's|^namespace/||' || true)

    if [[ -z "${namespaces}" ]]; then
        log_info "No kv-e2e-* namespaces to clean up."
        return 0
    fi

    log_info "Deleting E2E namespaces: ${namespaces}"
    for ns in ${namespaces}; do
        kubectl --context "${context}" delete namespace "${ns}" --wait=false 2>/dev/null || true
        log_info "  Deleted namespace '${ns}'."
    done

    log_success "E2E namespace cleanup complete."
}
