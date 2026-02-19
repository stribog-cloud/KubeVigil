#!/usr/bin/env bats
# KubeVigil E2E — Tests for cross-validate.sh
#
# Validates cross-validation logic that compares KubeVigil scan results
# against other Kubernetes security tools (kubescape, trivy, kube-bench, etc.).
# All tool commands are mocked; no real scans are executed.

load test_helper

# Path to the script under test (does not exist yet -- TDD).
CROSS_VALIDATE_SCRIPT="${SCRIPT_DIR}/cross-validate.sh"

# Default context used in tests.
DEFAULT_CONTEXT="kind-kubevigil-e2e-single"

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------

@test "cross-validate: --help prints usage and exits 0" {
    run bash "${CROSS_VALIDATE_SCRIPT}" --help
    assert_exit_code 0
    assert_output_contains "Usage"
}

# ---------------------------------------------------------------------------
# Unavailable Tools — Skip with Install Message
# ---------------------------------------------------------------------------

@test "cross-validate: skips unavailable tools with install message" {
    # Do not mock any third-party tools; only mock kubectl.
    mock_command "kubectl" 0 ""
    export PATH="${MOCK_DIR}:/usr/bin:/bin"

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Should print skip messages for tools that are not found.
    # Common tools: kubescape, trivy, kube-bench, polaris.
    assert_output_contains "not found"
}

@test "cross-validate: skips kubescape when not installed and shows install hint" {
    mock_command "kubectl" 0 ""
    export PATH="${MOCK_DIR}:/usr/bin:/bin"

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0
    assert_output_contains "kubescape"
}

@test "cross-validate: skips trivy when not installed and shows install hint" {
    mock_command "kubectl" 0 ""
    export PATH="${MOCK_DIR}:/usr/bin:/bin"

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0
    assert_output_contains "trivy"
}

# ---------------------------------------------------------------------------
# Available Tools — Run and Save Output
# ---------------------------------------------------------------------------

@test "cross-validate: runs available tools and saves output" {
    mock_command "kubectl" 0 ""
    mock_command "kubescape" 0 '{"results":[]}'
    mock_command "trivy" 0 '{"Results":[]}'

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Should reference the tools that were executed.
    assert_output_contains "kubescape"
    assert_output_contains "trivy"
}

@test "cross-validate: saves tool output to results directory" {
    mock_command "kubectl" 0 ""
    mock_command "kubescape" 0 '{"results":[]}'

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Verify results directory was created (output files will be implementation-specific).
    [ -d "${BATS_TEST_TMPDIR}/results" ]
}

@test "cross-validate: runs only tools that are on PATH" {
    # Mock only kubescape, leave trivy and kube-bench absent.
    mock_command "kubectl" 0 ""
    mock_command "kubescape" 0 '{"results":[]}'
    export PATH="${MOCK_DIR}:/usr/bin:/bin"

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Should run kubescape and skip others.
    assert_output_contains "kubescape"
    assert_output_contains "not found"
}

# ---------------------------------------------------------------------------
# Comparison Table
# ---------------------------------------------------------------------------

@test "cross-validate: produces comparison table" {
    mock_command "kubectl" 0 ""
    mock_command "kubescape" 0 '{"results":[]}'
    mock_command "trivy" 0 '{"Results":[]}'

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Should produce some form of comparison or summary output.
    # This may be a table, a summary, or a comparison section.
    assert_output_contains "comparison"
}

# ---------------------------------------------------------------------------
# No Tools Available
# ---------------------------------------------------------------------------

@test "cross-validate: succeeds with message when no third-party tools are available" {
    mock_command "kubectl" 0 ""
    export PATH="${MOCK_DIR}:/usr/bin:/bin"

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    # Should not fail; should inform the user that no tools were found.
    assert_output_contains "not found"
}

# ---------------------------------------------------------------------------
# Tool-Specific Flags
# ---------------------------------------------------------------------------

@test "cross-validate: --tool flag restricts to a specific tool" {
    mock_command "kubectl" 0 ""
    mock_command "kubescape" 0 '{"results":[]}'
    mock_command "trivy" 0 '{"Results":[]}'

    run bash "${CROSS_VALIDATE_SCRIPT}" --context "${DEFAULT_CONTEXT}" --tool kubescape --results-dir "${BATS_TEST_TMPDIR}/results"
    assert_exit_code 0

    assert_output_contains "kubescape"
    # Should not run trivy when --tool restricts to kubescape only.
    assert_output_not_contains "trivy"
}
