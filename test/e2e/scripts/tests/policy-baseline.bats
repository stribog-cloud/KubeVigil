#!/usr/bin/env bats
# KubeVigil E2E — Policy & Baseline Command Tests (15 tests)
#
# Validates `kubevigil policy validate`, `kubevigil policy list`, and the
# scan-time `--policy-file`, `--save-baseline`, `--baseline`, and
# `--fail-on-new` flags end-to-end against small inline YAML manifests and
# CEL policy files written to a temp directory. Manifest mode only — no live
# cluster is required.
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
# Fixture helpers
# ---------------------------------------------------------------------------

# write_deployment writes a minimal Deployment manifest with no labels or
# annotations at all, so the custom policies below (missing 'team' label /
# missing 'owner' annotation) always flag it.
write_deployment() {
    local path="${1:?path required}"
    local name="${2:-policy-demo}"
    cat > "${path}" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${name}
  template:
    metadata:
      labels:
        app: ${name}
    spec:
      containers:
        - name: app
          image: nginx:1.25
EOF
}

# write_privileged_deployment writes a Deployment with a privileged container,
# which trips the built-in "privileged" checker — used as a stable, known
# finding set for baseline tests.
write_privileged_deployment() {
    local path="${1:?path required}"
    cat > "${path}" <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: baseline-demo
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: baseline-demo
  template:
    metadata:
      labels:
        app: baseline-demo
    spec:
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            privileged: true
EOF
}

# write_privileged_deployment_plus_extra writes the same Deployment as above
# plus a second, entirely separate Deployment with hostNetwork enabled — a
# resource/check combination guaranteed to be absent from a baseline captured
# against the first manifest alone.
write_privileged_deployment_plus_extra() {
    local path="${1:?path required}"
    write_privileged_deployment "${path}"
    cat >> "${path}" <<'EOF'
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: baseline-extra
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: baseline-extra
  template:
    metadata:
      labels:
        app: baseline-extra
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: nginx:1.25
EOF
}

# write_team_label_policy writes a single-policy CEL file flagging Deployments
# missing a 'team' label.
write_team_label_policy() {
    local path="${1:?path required}"
    local id="${2:-require-team-label}"
    cat > "${path}" <<EOF
version: v1
policies:
  - id: ${id}
    name: Deployments must have a team label
    description: Ensures every Deployment carries a team ownership label for accountability.
    severity: medium
    category: workload
    message: Deployment is missing the required 'team' label
    remediation: Add a 'team' label to metadata.labels identifying the owning team.
    expression: "!has(object.metadata.labels) || !('team' in object.metadata.labels)"
    match:
      kinds:
        - Deployment
EOF
}

# write_owner_annotation_policy writes a single-policy CEL file flagging
# Deployments missing an 'owner' annotation.
write_owner_annotation_policy() {
    local path="${1:?path required}"
    local id="${2:-require-owner-annotation}"
    cat > "${path}" <<EOF
version: v1
policies:
  - id: ${id}
    name: Deployments must have an owner annotation
    severity: low
    category: workload
    message: Deployment is missing the required 'owner' annotation
    expression: "!has(object.metadata.annotations) || !('owner' in object.metadata.annotations)"
    match:
      kinds:
        - Deployment
EOF
}

# ---------------------------------------------------------------------------
# 1. policy validate: valid single-policy file exits 0
# ---------------------------------------------------------------------------
@test "policy validate: valid single-policy file exits 0" {
    local policy_file="${BATS_TEST_TMPDIR}/policy.yaml"
    write_team_label_policy "${policy_file}"

    run "${KUBEVIGIL}" policy validate "${policy_file}"
    assert_exit_code 0
    assert_output_contains "OK:"
    assert_output_contains "1 policies valid"
}

# ---------------------------------------------------------------------------
# 2. policy validate: valid policy directory exits 0
# ---------------------------------------------------------------------------
@test "policy validate: valid policy directory exits 0" {
    local dir="${BATS_TEST_TMPDIR}/policies"
    mkdir -p "${dir}"
    write_team_label_policy "${dir}/01-team.yaml" "require-team-label-a"
    write_owner_annotation_policy "${dir}/02-owner.yaml"

    run "${KUBEVIGIL}" policy validate "${dir}"
    assert_exit_code 0
    assert_output_contains "OK:"
    assert_output_contains "2 policies valid"
}

# ---------------------------------------------------------------------------
# 3. policy validate: invalid CEL expression exits 3
# ---------------------------------------------------------------------------
@test "policy validate: invalid CEL expression exits 3" {
    local policy_file="${BATS_TEST_TMPDIR}/bad-cel.yaml"
    cat > "${policy_file}" <<'EOF'
version: v1
policies:
  - id: broken-expression
    name: Broken CEL expression
    severity: low
    expression: "object.spec.replicas +"
EOF

    run "${KUBEVIGIL}" policy validate "${policy_file}"
    assert_exit_code 3
    assert_output_contains "Policy error"
    assert_output_contains "broken-expression"
}

# ---------------------------------------------------------------------------
# 4. policy validate: invalid severity exits 3
# ---------------------------------------------------------------------------
@test "policy validate: invalid severity exits 3" {
    local policy_file="${BATS_TEST_TMPDIR}/bad-severity.yaml"
    cat > "${policy_file}" <<'EOF'
version: v1
policies:
  - id: bad-severity-policy
    name: Bad severity value
    severity: extreme
    expression: "true"
EOF

    run "${KUBEVIGIL}" policy validate "${policy_file}"
    assert_exit_code 3
    assert_output_contains "Policy error"
    assert_output_contains "unknown severity"
}

# ---------------------------------------------------------------------------
# 5. policy validate: duplicate policy id across directory files exits 3
# ---------------------------------------------------------------------------
@test "policy validate: duplicate policy id across directory files exits 3" {
    local dir="${BATS_TEST_TMPDIR}/dup-policies"
    mkdir -p "${dir}"
    cat > "${dir}/a.yaml" <<'EOF'
version: v1
policies:
  - id: dup-policy
    name: First definition
    severity: low
    expression: "true"
EOF
    cat > "${dir}/b.yaml" <<'EOF'
version: v1
policies:
  - id: dup-policy
    name: Second definition
    severity: low
    expression: "true"
EOF

    run "${KUBEVIGIL}" policy validate "${dir}"
    assert_exit_code 3
    assert_output_contains "duplicate policy id"
    assert_output_contains "dup-policy"
}

# ---------------------------------------------------------------------------
# 6. policy validate: nonexistent path exits 3
# ---------------------------------------------------------------------------
@test "policy validate: nonexistent path exits 3" {
    run "${KUBEVIGIL}" policy validate "${BATS_TEST_TMPDIR}/does-not-exist.yaml"
    assert_exit_code 3
    assert_output_contains "Policy error"
}

# ---------------------------------------------------------------------------
# 7. policy list: lists policies from a single file
# ---------------------------------------------------------------------------
@test "policy list: lists policies from a single file" {
    local policy_file="${BATS_TEST_TMPDIR}/policy.yaml"
    write_team_label_policy "${policy_file}"

    run "${KUBEVIGIL}" policy list "${policy_file}"
    assert_exit_code 0
    assert_output_contains "require-team-label"
    assert_output_contains "Medium"
    assert_output_contains "Total: 1 policies"
}

# ---------------------------------------------------------------------------
# 8. policy list: lists policies from a directory
# ---------------------------------------------------------------------------
@test "policy list: lists policies from a directory" {
    local dir="${BATS_TEST_TMPDIR}/policies"
    mkdir -p "${dir}"
    write_team_label_policy "${dir}/01-team.yaml" "require-team-label-a"
    write_owner_annotation_policy "${dir}/02-owner.yaml"

    run "${KUBEVIGIL}" policy list "${dir}"
    assert_exit_code 0
    assert_output_contains "require-team-label-a"
    assert_output_contains "require-owner-annotation"
    assert_output_contains "Total: 2 policies"
}

# ---------------------------------------------------------------------------
# 9. scan --policy-file: custom finding appears in output (single file)
# ---------------------------------------------------------------------------
@test "scan --policy-file: custom finding appears in output (single file)" {
    local manifest="${BATS_TEST_TMPDIR}/deploy.yaml"
    local policy_file="${BATS_TEST_TMPDIR}/policy.yaml"
    write_deployment "${manifest}"
    write_team_label_policy "${policy_file}"

    run "${KUBEVIGIL}" scan -f "${manifest}" --policy-file "${policy_file}"
    # The bare manifest also trips several built-in high-severity checks, so
    # the default fail-on threshold ("high") may push exit to 1 — only the
    # custom finding's presence in the report matters for this test.
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]

    assert_output_contains "require-team-label"
    assert_output_contains "missing the required 'team' label"
}

# ---------------------------------------------------------------------------
# 10. scan --policy-file: custom findings from a directory appear in output
# ---------------------------------------------------------------------------
@test "scan --policy-file: custom findings from a directory appear in output" {
    local manifest="${BATS_TEST_TMPDIR}/deploy.yaml"
    local dir="${BATS_TEST_TMPDIR}/policies"
    mkdir -p "${dir}"
    write_deployment "${manifest}"
    write_team_label_policy "${dir}/01-team.yaml" "require-team-label-a"
    write_owner_annotation_policy "${dir}/02-owner.yaml"

    run "${KUBEVIGIL}" scan -f "${manifest}" --policy-file "${dir}"
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]

    assert_output_contains "require-team-label-a"
    assert_output_contains "require-owner-annotation"
}

# ---------------------------------------------------------------------------
# 11. scan --save-baseline: writes baseline JSON and exits 0
# ---------------------------------------------------------------------------
@test "scan --save-baseline: writes baseline JSON and exits 0" {
    local manifest="${BATS_TEST_TMPDIR}/priv.yaml"
    local baseline_file="${BATS_TEST_TMPDIR}/baseline.json"
    write_privileged_deployment "${manifest}"

    run "${KUBEVIGIL}" scan -f "${manifest}" --save-baseline "${baseline_file}"
    assert_exit_code 0
    assert_output_contains "Baseline written"

    assert_file_exists "${baseline_file}"
    local content
    content=$(cat "${baseline_file}")
    [[ "${content}" == *'"version": "v1"'* ]]
    [[ "${content}" == *'"fingerprints"'* ]]
}

# ---------------------------------------------------------------------------
# 12. scan --baseline --fail-on-new: exits 0 when nothing new
# ---------------------------------------------------------------------------
@test "scan --baseline --fail-on-new: exits 0 and reports no drift when nothing new" {
    local manifest="${BATS_TEST_TMPDIR}/priv.yaml"
    local baseline_file="${BATS_TEST_TMPDIR}/baseline.json"
    write_privileged_deployment "${manifest}"

    run "${KUBEVIGIL}" scan -f "${manifest}" --save-baseline "${baseline_file}"
    [ "$status" -eq 0 ]

    # Re-scanning the identical manifest against its own baseline must show
    # zero new findings.
    run "${KUBEVIGIL}" scan -f "${manifest}" --baseline "${baseline_file}" --fail-on-new
    assert_exit_code 0
    assert_output_contains "Baseline drift: 0 new"
}

# ---------------------------------------------------------------------------
# 13. scan --baseline --fail-on-new: exits 1 when a new finding appears
# ---------------------------------------------------------------------------
@test "scan --baseline --fail-on-new: exits 1 and reports drift when a new finding appears" {
    local manifest="${BATS_TEST_TMPDIR}/priv.yaml"
    local manifest_plus="${BATS_TEST_TMPDIR}/priv-plus.yaml"
    local baseline_file="${BATS_TEST_TMPDIR}/baseline.json"
    write_privileged_deployment "${manifest}"
    write_privileged_deployment_plus_extra "${manifest_plus}"

    run "${KUBEVIGIL}" scan -f "${manifest}" --save-baseline "${baseline_file}"
    [ "$status" -eq 0 ]

    # The second manifest adds a whole new Deployment (hostNetwork), which the
    # baseline above has never seen — this must be classified as new drift.
    run "${KUBEVIGIL}" scan -f "${manifest_plus}" --baseline "${baseline_file}" --fail-on-new
    assert_exit_code 1
    assert_output_contains "Baseline drift:"

    [[ "${output}" =~ Baseline\ drift:\ ([0-9]+)\ new ]]
    [ "${BASH_REMATCH[1]}" -gt 0 ]
}

# ---------------------------------------------------------------------------
# 14. scan --fail-on-new without --baseline: exits 3
# ---------------------------------------------------------------------------
@test "scan --fail-on-new without --baseline exits 3" {
    local manifest="${BATS_TEST_TMPDIR}/priv.yaml"
    write_privileged_deployment "${manifest}"

    run "${KUBEVIGIL}" scan -f "${manifest}" --fail-on-new
    # This error is returned as a silent exitError (no message is printed —
    # cobra's SilenceErrors suppresses it and execute() only maps the code),
    # so only the exit code is asserted here.
    assert_exit_code 3
}

# ---------------------------------------------------------------------------
# 15. scan --baseline: exits 3 when the baseline file does not exist
# ---------------------------------------------------------------------------
@test "scan --baseline: exits 3 when the baseline file does not exist" {
    local manifest="${BATS_TEST_TMPDIR}/priv.yaml"
    write_privileged_deployment "${manifest}"

    run "${KUBEVIGIL}" scan -f "${manifest}" --baseline "${BATS_TEST_TMPDIR}/does-not-exist.json"
    assert_exit_code 3
    assert_output_contains "Baseline error"
}
