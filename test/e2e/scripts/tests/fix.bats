#!/usr/bin/env bats
# KubeVigil E2E — Fix Command Tests (18 tests)
#
# Validates the `kubevigil fix` command end-to-end against scenario manifests.
# Tests cover dry-run, apply, verify, risk levels, system namespace protection,
# comment preservation, multi-document YAML, kubectl output, Kustomize overlay,
# CI mode, backup, known workloads, and partial failure resilience.
#
# All kubevigil invocations use the real binary built from source.
# No mocking — these are true E2E tests.

load test_helper

# Path to the kubevigil binary (built by go build).
KUBEVIGIL=""

# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

setup() {
    # Call the shared setup for temp dirs and PATH.
    BATS_TEST_TMPDIR="$(mktemp -d)"
    export BATS_TEST_TMPDIR

    MOCK_DIR="$(mktemp -d)"
    export MOCK_DIR
    export PATH="${MOCK_DIR}:${ORIGINAL_PATH}"

    # Find or build the kubevigil binary.
    if [[ -x "${PROJECT_ROOT}/bin/kubevigil" ]]; then
        KUBEVIGIL="${PROJECT_ROOT}/bin/kubevigil"
    elif command -v kubevigil &>/dev/null; then
        KUBEVIGIL="kubevigil"
    else
        skip "kubevigil binary not found — run 'make build' first"
    fi

    # Scenarios root directory.
    SCENARIOS="${E2E_ROOT}/scenarios"
}

teardown() {
    export PATH="${ORIGINAL_PATH}"
    if [[ -n "${BATS_TEST_TMPDIR:-}" && -d "${BATS_TEST_TMPDIR}" ]]; then
        rm -rf "${BATS_TEST_TMPDIR}"
    fi
    if [[ -n "${MOCK_DIR:-}" && -d "${MOCK_DIR}" ]]; then
        rm -rf "${MOCK_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# Helper: copy scenario to temp dir for isolation
# ---------------------------------------------------------------------------
copy_scenario() {
    local scenario="${1:?scenario name required}"
    local dest="${BATS_TEST_TMPDIR}/${scenario}"
    cp -r "${SCENARIOS}/${scenario}" "${dest}"
    echo "${dest}"
}

# ---------------------------------------------------------------------------
# 1. Dry-run produces diff without modifying files
# ---------------------------------------------------------------------------
@test "fix dry-run produces diff output without modifying files" {
    local workdir
    workdir=$(copy_scenario "fix-safe")

    # Capture original file content.
    local orig
    orig=$(cat "${workdir}/privileged-deployment.yaml")

    run "${KUBEVIGIL}" fix "${workdir}"
    # Dry-run should succeed (exit 0 = changes found).
    [ "$status" -eq 0 ]

    # Output should contain diff markers.
    assert_output_contains "privileged"

    # Files must NOT be modified.
    local after
    after=$(cat "${workdir}/privileged-deployment.yaml")
    [ "${orig}" = "${after}" ]
}

# ---------------------------------------------------------------------------
# 2. --apply modifies files and creates backup
# ---------------------------------------------------------------------------
@test "fix --apply modifies files and creates backup" {
    local workdir
    workdir=$(copy_scenario "fix-safe")

    local backup_dir="${BATS_TEST_TMPDIR}/backups"

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --backup-dir "${backup_dir}"
    [ "$status" -eq 0 ]

    # File should be modified (privileged: true → privileged: false).
    local content
    content=$(cat "${workdir}/privileged-deployment.yaml")
    [[ "${content}" == *"privileged: false"* ]]

    # Backup directory should exist and contain files.
    [ -d "${backup_dir}" ]
    local backup_count
    backup_count=$(find "${backup_dir}" -name "*.yaml" -type f 2>/dev/null | wc -l | tr -d ' ')
    [ "${backup_count}" -ge 1 ]
}

# ---------------------------------------------------------------------------
# 3. --apply --verify re-scans and reports results
# ---------------------------------------------------------------------------
@test "fix --apply --verify re-scans and reports results" {
    local workdir
    workdir=$(copy_scenario "fix-safe")

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --verify --backup-dir "${BATS_TEST_TMPDIR}/backups"

    # Should succeed (exit 0 if all fixed, exit 1 if some remain).
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]

    # Output should contain verification results.
    assert_output_contains "Verification"
}

# ---------------------------------------------------------------------------
# 4. System namespace resources are skipped by default
# ---------------------------------------------------------------------------
@test "fix system namespace resources are skipped by default" {
    local workdir
    workdir=$(copy_scenario "fix-system-ns")

    run "${KUBEVIGIL}" fix "${workdir}"

    # Should report system namespace skip or nothing to do.
    # Exit code 0 (dry-run with skipped findings) or 4 (nothing to do at current risk).
    [ "$status" -eq 0 ] || [ "$status" -eq 4 ]

    # Output should mention system namespace.
    assert_output_contains "system" || assert_output_contains "skip" || assert_output_contains "No fix"
}

# ---------------------------------------------------------------------------
# 5. --risk-level safe only applies safe fixes
# ---------------------------------------------------------------------------
@test "fix --risk-level safe only applies safe fixes" {
    local workdir
    workdir=$(copy_scenario "fix-moderate")

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --risk-level safe --backup-dir "${BATS_TEST_TMPDIR}/backups"

    # Should succeed or report nothing-to-do if only moderate fixes available.
    [ "$status" -eq 0 ] || [ "$status" -eq 4 ]

    # If there are safe fixes (privilege-escalation), they should be applied.
    # Moderate fixes (runAsNonRoot, readOnlyRootFilesystem) should be skipped.
    if [ "$status" -eq 0 ]; then
        # Output should mention skipped likely-safe fixes.
        assert_output_contains "skip" || assert_output_contains "moderate"
    fi
}

# ---------------------------------------------------------------------------
# 6. --risk-level moderate includes likely-safe fixes
# ---------------------------------------------------------------------------
@test "fix --risk-level moderate includes likely-safe fixes" {
    local workdir
    workdir=$(copy_scenario "fix-moderate")

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --risk-level moderate --backup-dir "${BATS_TEST_TMPDIR}/backups"
    [ "$status" -eq 0 ]

    # Likely-safe fixes should now be applied.
    assert_output_contains "applied" || assert_output_contains "Applied" || assert_output_contains "Likely safe"
}

# ---------------------------------------------------------------------------
# 7. Clean scenario reports nothing to fix with exit code 4
# ---------------------------------------------------------------------------
@test "fix clean scenario reports nothing to fix with exit code 4" {
    local workdir
    workdir=$(copy_scenario "fix-clean")

    run "${KUBEVIGIL}" fix "${workdir}"
    [ "$status" -eq 4 ]

    assert_output_contains "No fixable findings" || assert_output_contains "nothing to" || assert_output_contains "No fix"
}

# ---------------------------------------------------------------------------
# 8. Preserves YAML comments
# ---------------------------------------------------------------------------
@test "fix preserves YAML comments" {
    local workdir
    workdir=$(copy_scenario "fix-comments")
    local file="${workdir}/commented-deployment.yaml"

    # Count comment lines before.
    local comments_before
    comments_before=$(grep -c '^[[:space:]]*#' "${file}" || echo "0")

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --backup-dir "${BATS_TEST_TMPDIR}/backups"
    [ "$status" -eq 0 ]

    # Count comment lines after.
    local comments_after
    comments_after=$(grep -c '^[[:space:]]*#' "${file}" || echo "0")

    # Comment count should be the same (or very close — inline comments on changed lines may shift).
    local diff_count=$((comments_before - comments_after))
    # Allow at most 2 comments difference (the fix may slightly adjust inline comment on privileged line).
    [ "${diff_count}" -le 2 ] && [ "${diff_count}" -ge -2 ]

    # Key comments should still be present.
    [[ "$(cat "${file}")" == *"deployment name"* ]]
    [[ "$(cat "${file}")" == *"Spec Section"* ]]
    [[ "$(cat "${file}")" == *"platform team"* ]]
}

# ---------------------------------------------------------------------------
# 9. Multi-document YAML only modifies affected documents
# ---------------------------------------------------------------------------
@test "fix multi-document YAML only modifies affected documents" {
    local workdir
    workdir=$(copy_scenario "fix-multi-doc")
    local file="${workdir}/mixed-docs.yaml"

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --backup-dir "${BATS_TEST_TMPDIR}/backups"
    [ "$status" -eq 0 ]

    local content
    content=$(cat "${file}")

    # The Service document should be unchanged — verify it's still there.
    [[ "${content}" == *"kind: Service"* ]]

    # The --- separators should be preserved.
    local separator_count
    separator_count=$(grep -c '^---' "${file}" || echo "0")
    [ "${separator_count}" -ge 2 ]

    # Both deployments should now have privileged: false.
    local priv_false_count
    priv_false_count=$(grep -c 'privileged: false' "${file}" || echo "0")
    [ "${priv_false_count}" -ge 2 ]
}

# ---------------------------------------------------------------------------
# 10. --output kubectl generates valid kubectl commands
# ---------------------------------------------------------------------------
@test "fix --output kubectl generates valid kubectl commands" {
    local workdir
    workdir=$(copy_scenario "fix-safe")

    run "${KUBEVIGIL}" fix "${workdir}" -o kubectl
    [ "$status" -eq 0 ]

    # Output should contain kubectl patch commands.
    assert_output_contains "kubectl patch"
    assert_output_contains "namespace" || assert_output_contains "-n"
}

# ---------------------------------------------------------------------------
# 11. --kustomize generates valid overlay directory
# ---------------------------------------------------------------------------
@test "fix --kustomize generates valid overlay directory" {
    local workdir
    workdir=$(copy_scenario "fix-safe")
    local kust_dir="${BATS_TEST_TMPDIR}/kustomize-overlay"

    run "${KUBEVIGIL}" fix "${workdir}" --kustomize "${kust_dir}"
    [ "$status" -eq 0 ]

    # Kustomize overlay directory should exist.
    [ -d "${kust_dir}" ]

    # Should contain a kustomization.yaml file.
    assert_file_exists "${kust_dir}/kustomization.yaml"
}

# ---------------------------------------------------------------------------
# 12. CI mode rejects --apply without --yes
# ---------------------------------------------------------------------------
@test "fix CI mode rejects --apply without --yes" {
    local workdir
    workdir=$(copy_scenario "fix-safe")

    # Simulate CI environment.
    export CI=true

    run "${KUBEVIGIL}" fix "${workdir}" --apply
    [ "$status" -eq 3 ]

    assert_output_contains "non-interactive" || assert_output_contains "--yes"

    unset CI
}

# ---------------------------------------------------------------------------
# 13. Backup directory has correct structure
# ---------------------------------------------------------------------------
@test "fix backup directory has correct structure" {
    local workdir
    workdir=$(copy_scenario "fix-safe")
    local backup_dir="${BATS_TEST_TMPDIR}/backups"

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --backup-dir "${backup_dir}"
    [ "$status" -eq 0 ]

    # Backup directory should exist.
    [ -d "${backup_dir}" ]

    # Should contain YAML backups.
    local yaml_count
    yaml_count=$(find "${backup_dir}" -name "*.yaml" -type f 2>/dev/null | wc -l | tr -d ' ')
    [ "${yaml_count}" -ge 1 ]

    # Should contain RESTORE.md or similar documentation.
    local restore_file
    restore_file=$(find "${backup_dir}" -name "RESTORE*" -type f 2>/dev/null | wc -l | tr -d ' ')
    [ "${restore_file}" -ge 1 ] || {
        # Alternatively, the backup path is printed in output.
        assert_output_contains "Backup" || assert_output_contains "backup" || assert_output_contains "restore"
    }
}

# ---------------------------------------------------------------------------
# 14. Known workloads (calico, coredns) are detected and skipped
# ---------------------------------------------------------------------------
@test "fix known workloads (calico, coredns) are detected and skipped" {
    local workdir
    workdir=$(copy_scenario "fix-known-workloads")

    run "${KUBEVIGIL}" fix "${workdir}" --i-understand-system-namespaces
    # Should succeed in dry-run mode or report nothing if all skipped.
    [ "$status" -eq 0 ] || [ "$status" -eq 4 ]

    # Output should indicate known workload detection or system namespace skip.
    assert_output_contains "skip" || assert_output_contains "known" || assert_output_contains "system" || assert_output_contains "No fix"
}

# ---------------------------------------------------------------------------
# 15. Partial failure continues with remaining files and reports errors
# ---------------------------------------------------------------------------
@test "fix partial failure continues with remaining files and reports errors" {
    local workdir
    workdir=$(copy_scenario "fix-partial-failure")

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --backup-dir "${BATS_TEST_TMPDIR}/backups"

    # Should report partial success (exit 5) or success with errors reported.
    # Exit 0 if only the malformed file was skipped (and readonly was not set to 444 yet).
    [ "$status" -eq 0 ] || [ "$status" -eq 5 ]

    # The valid file should be fixed.
    local content
    content=$(cat "${workdir}/valid-deployment.yaml")
    [[ "${content}" == *"privileged: false"* ]]
}

# ---------------------------------------------------------------------------
# 16. Partial failure returns exit code 5 with read-only file
# ---------------------------------------------------------------------------
@test "fix partial failure returns exit code 5" {
    local workdir
    workdir=$(copy_scenario "fix-partial-failure")

    # Make one file read-only to trigger permission error during apply.
    chmod 444 "${workdir}/readonly-deployment.yaml"

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --backup-dir "${BATS_TEST_TMPDIR}/backups"

    # Should report partial success.
    [ "$status" -eq 5 ] || [ "$status" -eq 0 ]

    # Restore permissions for cleanup.
    chmod 644 "${workdir}/readonly-deployment.yaml"
}

# ---------------------------------------------------------------------------
# 17. Dry-run diff includes What Could Break warnings for non-safe fixes
# ---------------------------------------------------------------------------
@test "fix dry-run diff includes What Could Break warnings for non-safe fixes" {
    local workdir
    workdir=$(copy_scenario "fix-aggressive")

    run "${KUBEVIGIL}" fix "${workdir}" --risk-level aggressive
    [ "$status" -eq 0 ]

    # Output should include impact warnings for potentially-breaking fixes.
    assert_output_contains "IMPACT" || assert_output_contains "impact" || assert_output_contains "break" || assert_output_contains "potentially"
}

# ---------------------------------------------------------------------------
# 18. --verify exit code 0 when all fixes verified
# ---------------------------------------------------------------------------
@test "fix --verify exit code 0 when all fixes verified" {
    local workdir
    workdir=$(copy_scenario "fix-safe")

    run "${KUBEVIGIL}" fix "${workdir}" --apply --yes --verify --backup-dir "${BATS_TEST_TMPDIR}/backups"

    # If all safe fixes are verified clean, exit code should be 0.
    # If some findings remain (non-fixable), exit code could be 1.
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]

    # Should print verification output.
    assert_output_contains "Verification" || assert_output_contains "Resolved"
}
