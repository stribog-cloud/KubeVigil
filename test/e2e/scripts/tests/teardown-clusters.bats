#!/usr/bin/env bats
# KubeVigil E2E — Tests for teardown-clusters.sh
#
# Validates cluster teardown logic including topology selection, confirmation
# bypass, and graceful handling of non-existent clusters. All Kind commands
# are mocked; no real clusters are destroyed.

load test_helper

# Path to the script under test (does not exist yet -- TDD).
TEARDOWN_SCRIPT="${SCRIPT_DIR}/teardown-clusters.sh"

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------

@test "teardown-clusters: --help prints usage and exits 0" {
    run bash "${TEARDOWN_SCRIPT}" --help
    assert_exit_code 0
    assert_output_contains "Usage"
}

# ---------------------------------------------------------------------------
# --yes Flag
# ---------------------------------------------------------------------------

@test "teardown-clusters: --yes flag skips confirmation prompt" {
    # Mock kind to report the cluster exists and succeed on deletion.
    mock_command "kind" 0 "kubevigil-e2e-single"

    run bash "${TEARDOWN_SCRIPT}" --topology single --yes
    assert_exit_code 0
    # Should not ask for confirmation.
    assert_output_not_contains "Are you sure"
    assert_output_not_contains "Confirm"
}

# ---------------------------------------------------------------------------
# Topology-Specific Deletion
# ---------------------------------------------------------------------------

@test "teardown-clusters: --topology single deletes kubevigil-e2e-single" {
    # Record kind delete commands.
    local kind_log="${BATS_TEST_TMPDIR}/kind_args.log"
    cat > "${MOCK_DIR}/kind" <<SCRIPT
#!/usr/bin/env bash
echo "\$@" >> "${kind_log}"
# Simulate cluster existing for 'get clusters'.
if [[ "\$1" == "get" ]]; then
    echo "kubevigil-e2e-single"
fi
exit 0
SCRIPT
    chmod +x "${MOCK_DIR}/kind"

    run bash "${TEARDOWN_SCRIPT}" --topology single --yes
    assert_exit_code 0

    # Verify the delete command targeted the single-node cluster.
    if [ -f "${kind_log}" ]; then
        local args
        args="$(cat "${kind_log}")"
        [[ "${args}" == *"delete cluster"* ]] || {
            echo "Expected 'delete cluster' in kind args: ${args}" >&2
            return 1
        }
        [[ "${args}" == *"kubevigil-e2e-single"* ]] || {
            echo "Expected cluster name in kind args: ${args}" >&2
            return 1
        }
    fi
}

@test "teardown-clusters: --topology multi deletes kubevigil-e2e-multi" {
    mock_command "kind" 0 "kubevigil-e2e-multi"

    run bash "${TEARDOWN_SCRIPT}" --topology multi --yes
    assert_exit_code 0
    assert_output_contains "kubevigil-e2e-multi"
}

@test "teardown-clusters: --topology ha deletes kubevigil-e2e-ha" {
    mock_command "kind" 0 "kubevigil-e2e-ha"

    run bash "${TEARDOWN_SCRIPT}" --topology ha --yes
    assert_exit_code 0
    assert_output_contains "kubevigil-e2e-ha"
}

# ---------------------------------------------------------------------------
# --topology all
# ---------------------------------------------------------------------------

@test "teardown-clusters: --topology all deletes all clusters" {
    mock_command "kind" 0 "kubevigil-e2e-single
kubevigil-e2e-multi
kubevigil-e2e-ha"

    run bash "${TEARDOWN_SCRIPT}" --topology all --yes
    assert_exit_code 0
    # All three cluster names should appear in output.
    assert_output_contains "kubevigil-e2e-single"
    assert_output_contains "kubevigil-e2e-multi"
    assert_output_contains "kubevigil-e2e-ha"
}

# ---------------------------------------------------------------------------
# Graceful Handling of Non-Existent Clusters
# ---------------------------------------------------------------------------

@test "teardown-clusters: handles gracefully when cluster does not exist" {
    # Mock kind to return no clusters.
    mock_command "kind" 0 ""

    run bash "${TEARDOWN_SCRIPT}" --topology single --yes
    assert_exit_code 0
    # Should indicate the cluster was not found or already deleted.
    assert_output_contains "does not exist"
}

@test "teardown-clusters: handles mixed existence (some clusters exist, some do not)" {
    # Only single exists; multi and ha do not.
    mock_command "kind" 0 "kubevigil-e2e-single"

    run bash "${TEARDOWN_SCRIPT}" --topology all --yes
    assert_exit_code 0
    # Should still succeed; non-existent clusters are skipped gracefully.
    assert_output_contains "kubevigil-e2e-single"
}
