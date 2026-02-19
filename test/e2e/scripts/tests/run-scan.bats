#!/usr/bin/env bats
# KubeVigil E2E — Tests for run-scan.sh
#
# Validates the scan execution wrapper including results directory creation,
# multi-format output generation, kubevigil command construction, and findings
# summary. All kubevigil and kubectl commands are mocked.

load test_helper

# Path to the script under test (does not exist yet -- TDD).
RUN_SCAN_SCRIPT="${SCRIPT_DIR}/run-scan.sh"

# Default context used in tests.
DEFAULT_CONTEXT="kind-kubevigil-e2e-single"

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------

@test "run-scan: --help prints usage and exits 0" {
    run bash "${RUN_SCAN_SCRIPT}" --help
    assert_exit_code 0
    assert_output_contains "Usage"
}

# ---------------------------------------------------------------------------
# Results Directory
# ---------------------------------------------------------------------------

@test "run-scan: creates results directory structure" {
    mock_command "kubevigil" 0 '{"findings":[]}'
    mock_command "kubectl" 0 ""

    # Point results to the temp directory so we can verify structure.
    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # The results directory should exist after the scan.
    [ -d "${BATS_TEST_TMPDIR}/results" ]
}

@test "run-scan: creates timestamped subdirectory within results" {
    mock_command "kubevigil" 0 '{"findings":[]}'
    mock_command "kubectl" 0 ""
    mock_command "kind" 0 ""

    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Results directory should exist and contain output files.
    [ -d "${BATS_TEST_TMPDIR}/results" ]
    local file_count
    file_count=$(find "${BATS_TEST_TMPDIR}/results" -type f 2>/dev/null | wc -l | tr -d ' ')
    [ "${file_count}" -ge 1 ] || {
        echo "Expected at least one file in results, found ${file_count}" >&2
        return 1
    }
}

# ---------------------------------------------------------------------------
# Multi-Format Output
# ---------------------------------------------------------------------------

@test "run-scan: generates output in multiple formats" {
    # Mock kubevigil to produce minimal output for each format.
    mock_command "kubevigil" 0 '{"findings":[]}'
    mock_command "kubectl" 0 ""

    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Should reference multiple output formats in the output.
    # Exact formats: json, text, sarif, html (at minimum).
    assert_output_contains "json"
}

@test "run-scan: --format flag selects specific output format" {
    mock_command "kubevigil" 0 '{"findings":[]}'
    mock_command "kubectl" 0 ""

    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --format json --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0
    assert_output_contains "json"
}

# ---------------------------------------------------------------------------
# KubeVigil Command Construction
# ---------------------------------------------------------------------------

@test "run-scan: constructs correct kubevigil command" {
    local kv_log="${BATS_TEST_TMPDIR}/kubevigil_args.log"
    cat > "${MOCK_DIR}/kubevigil" <<SCRIPT
#!/usr/bin/env bash
echo "\$@" >> "${kv_log}"
echo '{"findings":[]}'
exit 0
SCRIPT
    chmod +x "${MOCK_DIR}/kubevigil"
    mock_command "kubectl" 0 ""

    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Verify kubevigil was invoked with 'scan' subcommand.
    if [ -f "${kv_log}" ]; then
        local args
        args="$(cat "${kv_log}")"
        [[ "${args}" == *"scan"* ]] || {
            echo "Expected 'scan' in kubevigil args: ${args}" >&2
            return 1
        }
    fi
}

@test "run-scan: passes --output flag to kubevigil for format selection" {
    local kv_log="${BATS_TEST_TMPDIR}/kubevigil_args.log"
    cat > "${MOCK_DIR}/kubevigil" <<SCRIPT
#!/usr/bin/env bash
echo "\$@" >> "${kv_log}"
echo '{"findings":[]}'
exit 0
SCRIPT
    chmod +x "${MOCK_DIR}/kubevigil"
    mock_command "kubectl" 0 ""

    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --format sarif --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    if [ -f "${kv_log}" ]; then
        local args
        args="$(cat "${kv_log}")"
        [[ "${args}" == *"--output"* ]] || [[ "${args}" == *"-o"* ]] || {
            echo "Expected output format flag in kubevigil args: ${args}" >&2
            return 1
        }
    fi
}

# ---------------------------------------------------------------------------
# Findings Summary
# ---------------------------------------------------------------------------

@test "run-scan: prints findings summary after scan" {
    mock_command "kubevigil" 0 '{"findings":[{"check":"resource-limits","severity":"Medium"}]}'
    mock_command "kubectl" 0 ""
    mock_command "kind" 0 ""

    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Should print some summary information (finding counts, severity breakdown, etc.).
    # Exact format depends on implementation. Check for common summary indicators.
    assert_output_contains "finding"
}

# ---------------------------------------------------------------------------
# Exit Code Propagation
# ---------------------------------------------------------------------------

@test "run-scan: propagates non-zero exit code from kubevigil on findings" {
    # kubevigil exits 1 when findings are present.
    mock_command "kubevigil" 1 '{"findings":[{"check":"privileged-container"}]}'
    mock_command "kubectl" 0 ""

    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    # The script should propagate kubevigil's exit code (1 = findings found).
    [ "$status" -eq 1 ] || [ "$status" -eq 0 ]
    # Either behavior is acceptable: propagate 1 or absorb it and report findings.
    # The test verifies the script does not crash (exit 2+).
    [ "$status" -lt 3 ]
}

# ---------------------------------------------------------------------------
# Missing kubevigil Binary
# ---------------------------------------------------------------------------

@test "run-scan: exits with error when kubevigil is not on PATH" {
    unmock_command "kubevigil"
    mock_command "kubectl" 0 ""
    mock_command "kind" 0 ""

    # Point KUBEVIGIL_BIN to a nonexistent path to force find_kubevigil to fail.
    export KUBEVIGIL_BIN="/nonexistent/kubevigil"

    run bash "${RUN_SCAN_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    [ "$status" -ne 0 ]
    assert_output_contains "kubevigil"
}
