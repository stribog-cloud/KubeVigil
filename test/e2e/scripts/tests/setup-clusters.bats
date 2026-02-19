#!/usr/bin/env bats
# KubeVigil E2E — Tests for setup-clusters.sh
#
# Validates cluster creation logic including topology selection, config file
# mapping, skip-when-exists behavior, and error handling. All Kind and kubectl
# commands are mocked; no real clusters are created.

load test_helper

# Path to the script under test (does not exist yet -- TDD).
SETUP_SCRIPT="${SCRIPT_DIR}/setup-clusters.sh"

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------

@test "setup-clusters: --help prints usage and exits 0" {
    run bash "${SETUP_SCRIPT}" --help
    assert_exit_code 0
    assert_output_contains "Usage"
}

# ---------------------------------------------------------------------------
# Topology Selection — Config File Mapping
# ---------------------------------------------------------------------------

@test "setup-clusters: --topology single selects kind-single-node.yaml config" {
    # Mock kind and kubectl so the script does not fail on prerequisites.
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""

    run bash "${SETUP_SCRIPT}" --topology single --dry-run
    assert_exit_code 0
    assert_output_contains "kind-single-node.yaml"
}

@test "setup-clusters: --topology multi selects kind-multi-node.yaml config" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""

    run bash "${SETUP_SCRIPT}" --topology multi --dry-run
    assert_exit_code 0
    assert_output_contains "kind-multi-node.yaml"
}

@test "setup-clusters: --topology ha selects kind-ha-control-plane.yaml config" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""

    run bash "${SETUP_SCRIPT}" --topology ha --dry-run
    assert_exit_code 0
    assert_output_contains "kind-ha-control-plane.yaml"
}

# ---------------------------------------------------------------------------
# Invalid Topology
# ---------------------------------------------------------------------------

@test "setup-clusters: --topology invalid exits non-zero with error" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""

    run bash "${SETUP_SCRIPT}" --topology invalid
    [ "$status" -ne 0 ]
    assert_output_contains "invalid"
}

# ---------------------------------------------------------------------------
# --topology all
# ---------------------------------------------------------------------------

@test "setup-clusters: --topology all creates all three clusters" {
    # Mock kind to return no existing clusters, and succeed on creation.
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""

    run bash "${SETUP_SCRIPT}" --topology all --dry-run
    assert_exit_code 0
    # Should reference all three cluster names.
    assert_output_contains "kubevigil-e2e-single"
    assert_output_contains "kubevigil-e2e-multi"
    assert_output_contains "kubevigil-e2e-ha"
}

# ---------------------------------------------------------------------------
# Skip When Cluster Already Exists
# ---------------------------------------------------------------------------

@test "setup-clusters: skips creation when cluster already exists" {
    # Mock kind to report the cluster already exists.
    mock_command "kind" 0 "kubevigil-e2e-single"
    mock_command "kubectl" 0 ""

    run bash "${SETUP_SCRIPT}" --topology single
    assert_exit_code 0
    # Should indicate skipping, not creating.
    assert_output_contains "already exists"
    assert_output_not_contains "Creating cluster"
}

# ---------------------------------------------------------------------------
# Missing Prerequisites
# ---------------------------------------------------------------------------

@test "setup-clusters: exits with error when kind is not available" {
    # Do not mock kind; restrict PATH to prevent finding the real binary.
    unmock_command "kind"
    mock_command "kubectl" 0 ""
    export PATH="${MOCK_DIR}:/usr/bin:/bin"

    run bash "${SETUP_SCRIPT}" --topology single
    [ "$status" -ne 0 ]
    assert_output_contains "kind"
}

# ---------------------------------------------------------------------------
# Command Construction
# ---------------------------------------------------------------------------

@test "setup-clusters: constructs correct kind create cluster command" {
    # Use a mock that records its arguments for inspection.
    local kind_log="${BATS_TEST_TMPDIR}/kind_args.log"
    cat > "${MOCK_DIR}/kind" <<SCRIPT
#!/usr/bin/env bash
echo "\$@" >> "${kind_log}"
exit 0
SCRIPT
    chmod +x "${MOCK_DIR}/kind"
    mock_command "kubectl" 0 "kubevigil-e2e-single-control-plane   Ready   control-plane   5m   v1.30.0"

    run bash "${SETUP_SCRIPT}" --topology single
    assert_exit_code 0

    # The kind invocation should include "create cluster", the cluster name,
    # and a --config flag pointing to the kind config file.
    if [ -f "${kind_log}" ]; then
        local args
        args="$(cat "${kind_log}")"
        [[ "${args}" == *"create cluster"* ]] || {
            echo "Expected 'create cluster' in kind args: ${args}" >&2
            return 1
        }
        [[ "${args}" == *"kubevigil-e2e-single"* ]] || {
            echo "Expected cluster name in kind args: ${args}" >&2
            return 1
        }
        [[ "${args}" == *"--config"* ]] || {
            echo "Expected --config flag in kind args: ${args}" >&2
            return 1
        }
    fi
}

# ---------------------------------------------------------------------------
# Cluster Name Convention
# ---------------------------------------------------------------------------

@test "setup-clusters: uses kubevigil-e2e- prefix for cluster names" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""

    run bash "${SETUP_SCRIPT}" --topology single --dry-run
    assert_exit_code 0
    assert_output_contains "kubevigil-e2e-"
}
