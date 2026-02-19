#!/usr/bin/env bats
# KubeVigil E2E — Tests for deploy-scenarios.sh
#
# Validates scenario deployment logic including per-category deployment,
# deploy-all mode, namespace creation, cleanup flag, and context targeting.
# All kubectl commands are mocked; no real resources are deployed.

load test_helper

# Path to the script under test (does not exist yet -- TDD).
DEPLOY_SCRIPT="${SCRIPT_DIR}/deploy-scenarios.sh"

# Default context used in tests.
DEFAULT_CONTEXT="kind-kubevigil-e2e-single"

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------

@test "deploy-scenarios: --help prints usage and exits 0" {
    run bash "${DEPLOY_SCRIPT}" --help
    assert_exit_code 0
    assert_output_contains "Usage"
}

# ---------------------------------------------------------------------------
# Single Scenario Deployment
# ---------------------------------------------------------------------------

@test "deploy-scenarios: --scenario workload-security deploys only that category" {
    mock_command "kubectl" 0 ""

    run bash "${DEPLOY_SCRIPT}" --scenario workload-security --context "${DEFAULT_CONTEXT}"
    assert_exit_code 0
    assert_output_contains "workload-security"
    # Should not deploy other categories.
    assert_output_not_contains "rbac"
    assert_output_not_contains "network"
}

@test "deploy-scenarios: --scenario rbac deploys RBAC scenarios" {
    mock_command "kubectl" 0 ""

    run bash "${DEPLOY_SCRIPT}" --scenario rbac --context "${DEFAULT_CONTEXT}"
    assert_exit_code 0
    assert_output_contains "rbac"
}

@test "deploy-scenarios: --scenario network deploys network scenarios" {
    mock_command "kubectl" 0 ""

    run bash "${DEPLOY_SCRIPT}" --scenario network --context "${DEFAULT_CONTEXT}"
    assert_exit_code 0
    assert_output_contains "network"
}

@test "deploy-scenarios: --scenario image-security deploys image security scenarios" {
    mock_command "kubectl" 0 ""

    run bash "${DEPLOY_SCRIPT}" --scenario image-security --context "${DEFAULT_CONTEXT}"
    assert_exit_code 0
    assert_output_contains "image-security"
}

# ---------------------------------------------------------------------------
# Deploy All Scenarios
# ---------------------------------------------------------------------------

@test "deploy-scenarios: --scenario all deploys everything" {
    mock_command "kubectl" 0 ""

    run bash "${DEPLOY_SCRIPT}" --scenario all --context "${DEFAULT_CONTEXT}"
    assert_exit_code 0
    # Should reference multiple scenario categories.
    assert_output_contains "workload-security"
    assert_output_contains "rbac"
    assert_output_contains "network"
}

# ---------------------------------------------------------------------------
# --context Flag
# ---------------------------------------------------------------------------

@test "deploy-scenarios: --context flag sets target cluster" {
    # Record kubectl invocations to verify context usage.
    local kubectl_log="${BATS_TEST_TMPDIR}/kubectl_args.log"
    cat > "${MOCK_DIR}/kubectl" <<SCRIPT
#!/usr/bin/env bash
echo "\$@" >> "${kubectl_log}"
exit 0
SCRIPT
    chmod +x "${MOCK_DIR}/kubectl"

    run bash "${DEPLOY_SCRIPT}" --scenario workload-security --context "kind-kubevigil-e2e-multi"
    assert_exit_code 0

    # Verify kubectl was invoked with the correct context.
    if [ -f "${kubectl_log}" ]; then
        local args
        args="$(cat "${kubectl_log}")"
        [[ "${args}" == *"kind-kubevigil-e2e-multi"* ]] || {
            echo "Expected context in kubectl args: ${args}" >&2
            return 1
        }
    fi
}

# ---------------------------------------------------------------------------
# --clean Flag
# ---------------------------------------------------------------------------

@test "deploy-scenarios: --clean flag triggers namespace deletion before deploy" {
    local kubectl_log="${BATS_TEST_TMPDIR}/kubectl_args.log"
    cat > "${MOCK_DIR}/kubectl" <<SCRIPT
#!/usr/bin/env bash
echo "\$@" >> "${kubectl_log}"
# Return empty namespace list for 'get namespaces'.
if [[ "\$*" == *"get namespaces"* ]]; then
    echo ""
fi
exit 0
SCRIPT
    chmod +x "${MOCK_DIR}/kubectl"

    run bash "${DEPLOY_SCRIPT}" --scenario workload-security --context "${DEFAULT_CONTEXT}" --clean
    assert_exit_code 0

    # The clean flag should trigger deletion of existing kv-e2e-* namespaces.
    if [ -f "${kubectl_log}" ]; then
        local args
        args="$(cat "${kubectl_log}")"
        [[ "${args}" == *"delete"* ]] || [[ "${args}" == *"get namespaces"* ]] || {
            echo "Expected namespace cleanup in kubectl args: ${args}" >&2
            return 1
        }
    fi
}

# ---------------------------------------------------------------------------
# Namespace Creation
# ---------------------------------------------------------------------------

@test "deploy-scenarios: creates kv-e2e-* namespaces" {
    local kubectl_log="${BATS_TEST_TMPDIR}/kubectl_args.log"
    cat > "${MOCK_DIR}/kubectl" <<SCRIPT
#!/usr/bin/env bash
echo "\$@" >> "${kubectl_log}"
exit 0
SCRIPT
    chmod +x "${MOCK_DIR}/kubectl"

    run bash "${DEPLOY_SCRIPT}" --scenario workload-security --context "${DEFAULT_CONTEXT}"
    assert_exit_code 0

    # Should apply namespace.yaml which contains kv-e2e- namespace definitions.
    if [ -f "${kubectl_log}" ]; then
        local args
        args="$(cat "${kubectl_log}")"
        [[ "${args}" == *"namespace.yaml"* ]] || {
            echo "Expected namespace.yaml reference in kubectl args: ${args}" >&2
            return 1
        }
    fi
}

# ---------------------------------------------------------------------------
# Summary Output
# ---------------------------------------------------------------------------

@test "deploy-scenarios: prints summary of deployed resources" {
    mock_command "kubectl" 0 ""

    run bash "${DEPLOY_SCRIPT}" --scenario workload-security --context "${DEFAULT_CONTEXT}"
    assert_exit_code 0
    # Should print some form of summary or completion message.
    # The exact wording will be determined by implementation.
    assert_output_contains "deploy"
}

# ---------------------------------------------------------------------------
# Invalid Scenario
# ---------------------------------------------------------------------------

@test "deploy-scenarios: --scenario nonexistent exits non-zero" {
    mock_command "kubectl" 0 ""

    run bash "${DEPLOY_SCRIPT}" --scenario nonexistent --context "${DEFAULT_CONTEXT}"
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# Default Context
# ---------------------------------------------------------------------------

@test "deploy-scenarios: uses default context when --context is not specified" {
    mock_command "kubectl" 0 ""

    # The script should have a sensible default context (kubevigil-e2e-single).
    run bash "${DEPLOY_SCRIPT}" --scenario workload-security
    assert_exit_code 0
}
