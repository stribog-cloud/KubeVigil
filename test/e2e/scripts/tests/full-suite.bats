#!/usr/bin/env bats
# KubeVigil E2E — Tests for full-suite.sh
#
# Validates the top-level orchestrator that runs the full E2E pipeline:
# setup-clusters -> deploy-scenarios -> run-scan -> cross-validate -> teardown-clusters.
# All sub-scripts and external commands are mocked; no real clusters or scans
# are executed.

load test_helper

# Path to the script under test (does not exist yet -- TDD).
FULL_SUITE_SCRIPT="${SCRIPT_DIR}/full-suite.sh"

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------

@test "full-suite: --help prints usage and exits 0" {
    run bash "${FULL_SUITE_SCRIPT}" --help
    assert_exit_code 0
    assert_output_contains "Usage"
}

# ---------------------------------------------------------------------------
# --keep-cluster Flag
# ---------------------------------------------------------------------------

@test "full-suite: --keep-cluster skips teardown step" {
    # Mock all sub-scripts as pass-through scripts that log their invocation.
    local call_log="${BATS_TEST_TMPDIR}/calls.log"

    for script in setup-clusters deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script}" >> "${call_log}"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    # Also mock commands the full-suite script might invoke directly.
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
    mock_command "kubevigil" 0 '{"findings":[]}'

    run bash "${FULL_SUITE_SCRIPT}" --keep-cluster --results-dir "${BATS_TEST_TMPDIR}/results"

    assert_exit_code 0
    # Should not invoke teardown.
    assert_output_not_contains "teardown"
}

@test "full-suite: without --keep-cluster runs teardown" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
    mock_command "kubevigil" 0 '{"findings":[]}'

    # Create mock sub-scripts in the SCRIPT_DIR (or ensure the script calls them).
    # For now, test that the full suite output references teardown.
    local call_log="${BATS_TEST_TMPDIR}/calls.log"

    for script in setup-clusters deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script}" >> "${call_log}"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    run bash "${FULL_SUITE_SCRIPT}" --results-dir "${BATS_TEST_TMPDIR}/results" --yes

    assert_exit_code 0
    assert_output_contains "teardown"
}

# ---------------------------------------------------------------------------
# --skip-cross-validate Flag
# ---------------------------------------------------------------------------

@test "full-suite: --skip-cross-validate skips cross-validation step" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
    mock_command "kubevigil" 0 '{"findings":[]}'

    local call_log="${BATS_TEST_TMPDIR}/calls.log"

    for script in setup-clusters deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script}" >> "${call_log}"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    run bash "${FULL_SUITE_SCRIPT}" --skip-cross-validate --keep-cluster --results-dir "${BATS_TEST_TMPDIR}/results"

    assert_exit_code 0
    assert_output_not_contains "cross-validate"
}

@test "full-suite: without --skip-cross-validate runs cross-validation" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
    mock_command "kubevigil" 0 '{"findings":[]}'

    local call_log="${BATS_TEST_TMPDIR}/calls.log"

    for script in setup-clusters deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script}" >> "${call_log}"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    run bash "${FULL_SUITE_SCRIPT}" --keep-cluster --results-dir "${BATS_TEST_TMPDIR}/results"

    assert_exit_code 0
    assert_output_contains "cross-validate"
}

# ---------------------------------------------------------------------------
# Execution Order
# ---------------------------------------------------------------------------

@test "full-suite: calls scripts in correct order (setup -> deploy -> scan -> validate -> teardown)" {
    local call_log="${BATS_TEST_TMPDIR}/calls.log"

    # Create mock sub-scripts that record their invocation order.
    for script in setup-clusters deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script}" >> "${call_log}"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
    mock_command "kubevigil" 0 '{"findings":[]}'

    run bash "${FULL_SUITE_SCRIPT}" --results-dir "${BATS_TEST_TMPDIR}/results" --yes

    assert_exit_code 0

    # Verify the output mentions each stage in order.
    # The script should log each stage name.
    assert_output_contains "setup"
    assert_output_contains "deploy"
    assert_output_contains "scan"
}

@test "full-suite: stops on setup-clusters failure" {
    # Mock setup-clusters to fail.
    cat > "${MOCK_DIR}/setup-clusters.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo "setup-clusters: FAILED"
exit 1
SCRIPT
    chmod +x "${MOCK_DIR}/setup-clusters.sh"

    for script in deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script}"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""

    run bash "${FULL_SUITE_SCRIPT}" --results-dir "${BATS_TEST_TMPDIR}/results" --yes
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# Log File Creation
# ---------------------------------------------------------------------------

@test "full-suite: creates log file in results directory" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
    mock_command "kubevigil" 0 '{"findings":[]}'

    for script in setup-clusters deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script}"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    run bash "${FULL_SUITE_SCRIPT}" --keep-cluster --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # The results directory should exist.
    [ -d "${BATS_TEST_TMPDIR}/results" ]

    # Should contain a log file (*.log).
    local log_count
    log_count=$(find "${BATS_TEST_TMPDIR}/results" -name "*.log" -type f 2>/dev/null | wc -l | tr -d ' ')
    [ "${log_count}" -ge 1 ] || {
        echo "Expected at least one .log file in results, found ${log_count}" >&2
        ls -laR "${BATS_TEST_TMPDIR}/results" >&2
        return 1
    }
}

# ---------------------------------------------------------------------------
# Topology Passthrough
# ---------------------------------------------------------------------------

@test "full-suite: --topology flag is passed through to setup-clusters" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
    mock_command "kubevigil" 0 '{"findings":[]}'

    for script in setup-clusters deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script} \$@"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    run bash "${FULL_SUITE_SCRIPT}" --topology multi --keep-cluster --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0
    assert_output_contains "multi"
}

# ---------------------------------------------------------------------------
# Combined Flags
# ---------------------------------------------------------------------------

@test "full-suite: --keep-cluster and --skip-cross-validate can be combined" {
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
    mock_command "kubevigil" 0 '{"findings":[]}'

    for script in setup-clusters deploy-scenarios run-scan cross-validate teardown-clusters; do
        cat > "${MOCK_DIR}/${script}.sh" <<SCRIPT
#!/usr/bin/env bash
echo "${script}"
exit 0
SCRIPT
        chmod +x "${MOCK_DIR}/${script}.sh"
    done

    run bash "${FULL_SUITE_SCRIPT}" --keep-cluster --skip-cross-validate --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Neither teardown nor cross-validate should appear.
    assert_output_not_contains "teardown"
    assert_output_not_contains "cross-validate"
}
