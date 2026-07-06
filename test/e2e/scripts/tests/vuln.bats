#!/usr/bin/env bats
# KubeVigil E2E — Vulnerability Command Tests (kubevigil vuln)
#
# Validates `kubevigil vuln` end-to-end: flag/input validation and SBOM parsing
# (deterministic, offline) plus one network-guarded live smoke against OSV.dev
# that skips gracefully when api.osv.dev is unreachable.
#
# All kubevigil invocations use the real binary built from source. No mocking.

load test_helper

KUBEVIGIL=""

setup() {
    BATS_TEST_TMPDIR="$(mktemp -d)"
    export BATS_TEST_TMPDIR

    if [[ -x "${PROJECT_ROOT}/bin/kubevigil" ]]; then
        KUBEVIGIL="${PROJECT_ROOT}/bin/kubevigil"
    elif command -v kubevigil &>/dev/null; then
        KUBEVIGIL="kubevigil"
    else
        skip "kubevigil binary not found — run 'make build' first"
    fi
}

teardown() {
    if [[ -n "${BATS_TEST_TMPDIR:-}" && -d "${BATS_TEST_TMPDIR}" ]]; then
        rm -rf "${BATS_TEST_TMPDIR}"
    fi
}

# write_spdx writes a small SPDX SBOM with a known-vulnerable package.
write_spdx() {
    cat > "${BATS_TEST_TMPDIR}/app.spdx.json" <<'JSON'
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {"name": "django", "versionInfo": "3.2.0", "externalRefs": [
      {"referenceType": "purl", "referenceLocator": "pkg:pypi/django@3.2.0"}]}
  ]
}
JSON
}

# ---------------------------------------------------------------------------
# Deterministic, offline tests
# ---------------------------------------------------------------------------

@test "vuln: --help prints usage" {
    run "${KUBEVIGIL}" vuln --help
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"--sbom"* ]]
    [[ "${output}" == *"OSV.dev"* ]]
}

@test "vuln: missing --sbom exits 3" {
    run "${KUBEVIGIL}" vuln
    [ "${status}" -eq 3 ]
}

@test "vuln: nonexistent SBOM path exits 3" {
    run "${KUBEVIGIL}" vuln --sbom "${BATS_TEST_TMPDIR}/nope.json"
    [ "${status}" -eq 3 ]
}

@test "vuln: unrecognized SBOM format exits 3" {
    echo '{"foo":"bar"}' > "${BATS_TEST_TMPDIR}/bad.json"
    run "${KUBEVIGIL}" vuln --sbom "${BATS_TEST_TMPDIR}/bad.json"
    [ "${status}" -eq 3 ]
}

@test "vuln: invalid --min-severity exits 3" {
    write_spdx
    run "${KUBEVIGIL}" vuln --sbom "${BATS_TEST_TMPDIR}/app.spdx.json" --min-severity nonsense
    [ "${status}" -eq 3 ]
}

# ---------------------------------------------------------------------------
# Network-guarded live smoke against OSV.dev
# ---------------------------------------------------------------------------

# osv_reachable returns 0 if a live vuln scan can reach OSV.dev.
osv_reachable() {
    write_spdx
    run "${KUBEVIGIL}" vuln --sbom "${BATS_TEST_TMPDIR}/app.spdx.json" -o json
    # exit 2 == scan/network error; anything else means OSV was reachable.
    [ "${status}" -ne 2 ]
}

@test "vuln: live scan reports CVEs for a known-vulnerable package" {
    write_spdx
    run "${KUBEVIGIL}" vuln --sbom "${BATS_TEST_TMPDIR}/app.spdx.json" --image myapp:test -o json
    if [ "${status}" -eq 2 ]; then
        skip "OSV.dev unreachable"
    fi
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"image-vulnerability"* ]]
    [[ "${output}" == *"django"* ]]
}

@test "vuln: --fail-on critical exits 1 when a critical CVE is present" {
    write_spdx
    if ! osv_reachable; then
        skip "OSV.dev unreachable"
    fi
    run "${KUBEVIGIL}" vuln --sbom "${BATS_TEST_TMPDIR}/app.spdx.json" --fail-on critical -o text
    # django 3.2.0 carries critical CVEs → exit 1.
    [ "${status}" -eq 1 ]
}
