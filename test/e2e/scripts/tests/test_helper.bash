#!/usr/bin/env bash
# KubeVigil E2E — Shared Bats Test Helper
#
# Sourced by all .bats test files via:
#   load test_helper
#
# Provides:
#   - setup / teardown lifecycle hooks
#   - E2E_ROOT and SCRIPT_DIR variables
#   - Sources helpers.sh so tests can exercise its functions
#   - Mock creation and cleanup helpers
#   - Assertion helpers for common checks
#
# Requirements:
#   - bats-core (https://github.com/bats-core/bats-core)
#   - bash 3.2+ (macOS compatible)

# ---------------------------------------------------------------------------
# Directory Variables
# ---------------------------------------------------------------------------

# Directory containing this helper and the .bats files.
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The scripts/ directory (parent of tests/).
SCRIPT_DIR="$(cd "${TEST_DIR}/.." && pwd)"

# Root of the e2e test tree (test/e2e/).
E2E_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Project root (repository top level).
PROJECT_ROOT="$(cd "${E2E_ROOT}/../.." && pwd)"

# ---------------------------------------------------------------------------
# Source the helpers library under test
# ---------------------------------------------------------------------------

# Disable set -e while sourcing so that helpers.sh's set -euo pipefail
# does not interfere with bats' own error handling.
set +euo pipefail 2>/dev/null || true
# shellcheck source=../helpers.sh
source "${SCRIPT_DIR}/helpers.sh"

# ---------------------------------------------------------------------------
# PATH Mocking Infrastructure
#
# mock_command creates lightweight fake executables in MOCK_DIR, which is
# prepended to PATH. unmock_command removes them. teardown restores the
# original PATH so mocks never leak between tests.
# ---------------------------------------------------------------------------

# Save the original PATH before any mocks are applied.
ORIGINAL_PATH="${PATH}"

# MOCK_DIR is a per-test temporary directory for mock executables.
# It is created fresh in setup() and removed in teardown().
MOCK_DIR=""

# ---------------------------------------------------------------------------
# Bats Lifecycle Hooks
# ---------------------------------------------------------------------------

# setup runs before each test. Creates a temp directory for test artifacts
# and a separate directory for mock executables.
setup() {
    # Create a per-test temp directory for artifacts (files, outputs, etc.).
    BATS_TEST_TMPDIR="$(mktemp -d)"
    export BATS_TEST_TMPDIR

    # Create the mock directory and prepend it to PATH.
    MOCK_DIR="$(mktemp -d)"
    export MOCK_DIR
    export PATH="${MOCK_DIR}:${ORIGINAL_PATH}"

    # Baseline-mock both cluster tools so prerequisite checks pass by default
    # and no test depends on a real kind/kubectl being installed on the host.
    # Tests re-mock with specific output as needed (same path, overwritten),
    # and the "tool missing" tests unmock the specific tool explicitly.
    mock_command "kind" 0 ""
    mock_command "kubectl" 0 ""
}

# teardown runs after each test (pass or fail). Removes temp directories
# and restores the original PATH.
teardown() {
    # Restore PATH to its pre-mock state.
    export PATH="${ORIGINAL_PATH}"

    # Clean up the test artifact directory.
    if [[ -n "${BATS_TEST_TMPDIR:-}" && -d "${BATS_TEST_TMPDIR}" ]]; then
        rm -rf "${BATS_TEST_TMPDIR}"
    fi

    # Clean up the mock directory.
    if [[ -n "${MOCK_DIR:-}" && -d "${MOCK_DIR}" ]]; then
        rm -rf "${MOCK_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# Mock Helpers
# ---------------------------------------------------------------------------

# mock_command creates a mock executable that exits with the given code
# and writes the given stdout string.
#
# Usage:
#   mock_command "kind" 0 "kubevigil-e2e-single"
#   mock_command "kubectl" 1 ""
#
# The mock is placed in MOCK_DIR which is already on PATH, so the next
# invocation of <name> will hit the mock instead of the real binary.
mock_command() {
    local name="${1:?mock name required}"
    local exit_code="${2:-0}"
    local stdout_text="${3:-}"

    local mock_path="${MOCK_DIR}/${name}"

    # Write a tiny shell script that emits the canned output and exits.
    cat > "${mock_path}" <<MOCK_SCRIPT
#!/usr/bin/env bash
if [[ -n "${stdout_text}" ]]; then
    printf '%s\n' '${stdout_text}'
fi
exit ${exit_code}
MOCK_SCRIPT

    chmod +x "${mock_path}"
}

# unmock_command removes a previously created mock, causing subsequent
# calls to fall through to the real binary (or fail if it does not exist).
#
# Usage:
#   unmock_command "kind"
unmock_command() {
    local name="${1:?mock name required}"
    rm -f "${MOCK_DIR}/${name}"
}

# ---------------------------------------------------------------------------
# Assertion Helpers
#
# These operate on the bats-provided $output and $status variables, which
# are set automatically by bats' `run` keyword.
# ---------------------------------------------------------------------------

# assert_output_contains checks that $output contains the expected substring.
#
# Usage:
#   run some_function
#   assert_output_contains "All nodes are Ready"
assert_output_contains() {
    local expected="${1:?expected substring required}"

    if [[ "${output}" != *"${expected}"* ]]; then
        echo "assert_output_contains FAILED" >&2
        echo "  expected to find: ${expected}" >&2
        echo "  in output:        ${output}" >&2
        return 1
    fi
}

# assert_output_not_contains checks that $output does NOT contain the
# unexpected substring.
#
# Usage:
#   run some_function
#   assert_output_not_contains "ERROR"
assert_output_not_contains() {
    local unexpected="${1:?unexpected substring required}"

    if [[ "${output}" == *"${unexpected}"* ]]; then
        echo "assert_output_not_contains FAILED" >&2
        echo "  expected NOT to find: ${unexpected}" >&2
        echo "  in output:            ${output}" >&2
        return 1
    fi
}

# assert_file_exists checks that a file exists at the given path.
#
# Usage:
#   assert_file_exists "${BATS_TEST_TMPDIR}/report.json"
assert_file_exists() {
    local path="${1:?file path required}"

    if [[ ! -f "${path}" ]]; then
        echo "assert_file_exists FAILED" >&2
        echo "  file does not exist: ${path}" >&2
        return 1
    fi
}

# assert_exit_code checks that $status (set by bats' `run`) equals the
# expected exit code.
#
# Usage:
#   run some_function
#   assert_exit_code 0
assert_exit_code() {
    local expected="${1:?expected exit code required}"

    if [[ "${status}" -ne "${expected}" ]]; then
        echo "assert_exit_code FAILED" >&2
        echo "  expected: ${expected}" >&2
        echo "  actual:   ${status}" >&2
        echo "  output:   ${output}" >&2
        return 1
    fi
}
