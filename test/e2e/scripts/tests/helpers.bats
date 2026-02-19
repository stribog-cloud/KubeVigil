#!/usr/bin/env bats
# KubeVigil E2E — Tests for helpers.sh
#
# Validates logging functions, prerequisite checks, and Kind cluster helpers
# defined in helpers.sh. All external commands (kind, kubectl) are mocked so
# that tests run without real cluster infrastructure.

load test_helper

# ---------------------------------------------------------------------------
# check_prerequisites
# ---------------------------------------------------------------------------

@test "helpers: check_prerequisites returns 0 when kind and kubectl are available" {
    mock_command "kind" 0 "kind v0.20.0 go1.21.3 darwin/arm64"
    mock_command "kubectl" 0 "gitVersion: v1.29.0"

    run check_prerequisites
    assert_exit_code 0
}

@test "helpers: check_prerequisites exits non-zero when kind is missing" {
    # Only mock kubectl; leave kind unmocked so command -v fails.
    unmock_command "kind"
    mock_command "kubectl" 0 "gitVersion: v1.29.0"

    # Remove any real 'kind' from PATH by restricting PATH to only MOCK_DIR
    # and essential system directories that do NOT contain kind.
    export PATH="${MOCK_DIR}:/usr/bin:/bin"

    run check_prerequisites
    [ "$status" -ne 0 ]
    assert_output_contains "kind"
}

@test "helpers: check_prerequisites exits non-zero when kubectl is missing" {
    mock_command "kind" 0 "kind v0.20.0"

    # Ensure kubectl is not found on PATH.
    unmock_command "kubectl"
    export PATH="${MOCK_DIR}:/usr/bin:/bin"

    run check_prerequisites
    [ "$status" -ne 0 ]
    assert_output_contains "kubectl"
}

# ---------------------------------------------------------------------------
# Logging Functions
# ---------------------------------------------------------------------------

@test "helpers: log_info produces output containing INFO" {
    run log_info "test informational message"
    assert_exit_code 0
    assert_output_contains "INFO"
}

@test "helpers: log_info includes the message text" {
    run log_info "deploying scenario manifests"
    assert_exit_code 0
    assert_output_contains "deploying scenario manifests"
}

@test "helpers: log_warn produces output containing WARN" {
    run log_warn "retrying in 5 seconds"
    assert_exit_code 0
    assert_output_contains "WARN"
}

@test "helpers: log_warn includes the message text" {
    run log_warn "connection timeout"
    assert_exit_code 0
    assert_output_contains "connection timeout"
}

@test "helpers: log_error produces output containing ERROR" {
    run log_error "failed to create namespace"
    assert_exit_code 0
    assert_output_contains "ERROR"
}

@test "helpers: log_error includes the message text" {
    run log_error "cluster unreachable"
    assert_exit_code 0
    assert_output_contains "cluster unreachable"
}

@test "helpers: log_success produces output containing OK" {
    run log_success "all nodes are ready"
    assert_exit_code 0
    assert_output_contains "OK"
}

@test "helpers: log_success includes the message text" {
    run log_success "deployment complete"
    assert_exit_code 0
    assert_output_contains "deployment complete"
}

# ---------------------------------------------------------------------------
# cluster_exists
# ---------------------------------------------------------------------------

@test "helpers: cluster_exists returns 0 when cluster is in kind output" {
    mock_command "kind" 0 "kubevigil-e2e-single
kubevigil-e2e-multi
kubevigil-e2e-ha"

    run cluster_exists "kubevigil-e2e-single"
    assert_exit_code 0
}

@test "helpers: cluster_exists returns 1 when cluster is not found" {
    mock_command "kind" 0 "kubevigil-e2e-single
kubevigil-e2e-multi"

    run cluster_exists "kubevigil-e2e-ha"
    assert_exit_code 1
}

@test "helpers: cluster_exists returns 1 when kind returns empty output" {
    mock_command "kind" 0 ""

    run cluster_exists "kubevigil-e2e-single"
    assert_exit_code 1
}

@test "helpers: cluster_exists does not match partial cluster names" {
    # "kubevigil-e2e-single" should not match "kubevigil-e2e-single-extra"
    mock_command "kind" 0 "kubevigil-e2e-single-extra"

    run cluster_exists "kubevigil-e2e-single"
    assert_exit_code 1
}
