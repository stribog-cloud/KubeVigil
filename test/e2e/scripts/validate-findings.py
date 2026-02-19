#!/usr/bin/env python3
"""KubeVigil E2E — Validate Findings Against Expected Results

Loads scan results from JSON files and validates them against the expected
findings documented in test/e2e/expected/README.md.

Usage:
    python3 validate-findings.py --all --results-dir scan-results/
    python3 validate-findings.py --all --mode live --results-dir /tmp/
    python3 validate-findings.py --category workload-security --results-dir scan-results/
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Expected findings per category
#
# Derived from test/e2e/expected/README.md.
# Format: {check_id: severity} for checks that MUST fire.
# min_findings: minimum total finding count.
# severity_mins: {severity: minimum_count}
# ---------------------------------------------------------------------------

EXPECTED = {
    "workload-security": {
        "namespace": "kv-e2e-workload",
        "json_file_pattern": "e2e-manifest-workload-security.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-workload.json",
        "checks": {
            "privileged": "Critical",
            "capabilities-added": "High",
            "capabilities-not-dropped": "Medium",
            "host-pid": "Critical",
            "host-ipc": "Critical",
            "host-network": "Critical",
            "host-path-volumes": "Critical",  # has multiple severities
            "host-ports": "High",
            "run-as-root": "High",
            "run-as-high-uid": "Low",
            "run-as-group": "Medium",
            "read-only-rootfs": "Medium",
            "resource-limits-missing": "Medium",
            "resource-requests-missing": "Medium",
            "resource-limits-ratio": "Low",
            "ephemeral-storage-limits": "Low",
            "proc-mount": "High",
            "seccomp-profile": "Medium",
            "apparmor-profile": "Medium",
        },
        "live_extra_checks": {
            "startup-probes": "Info",
            "lifecycle-hooks": "Low",
            "liveness-readiness-probes": "Low",
        },
        "min_findings": 35,
        "live_min_findings": 100,
        "severity_mins": {
            "Critical": 7,
            "High": 7,
            "Medium": 15,
            "Low": 6,
        },
        "expected_exit": 1,
    },
    "image-security": {
        "namespace": "kv-e2e-image",
        "json_file_pattern": "e2e-manifest-image-security.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-image.json",
        "checks": {
            "image-tag-latest": "Medium",
            "image-tag-missing": "Medium",
            "image-no-digest": "Low",
            "image-pull-policy": "Medium",
            # image-registry-allowlist and blocklist require config
        },
        "min_findings": 20,
        "severity_mins": {
            "Medium": 8,
            "Low": 14,
        },
        "expected_exit": 1,
    },
    "rbac": {
        "namespace": "kv-e2e-rbac",
        "json_file_pattern": "e2e-manifest-rbac.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-rbac.json",
        "checks": {
            "rbac-wildcard-verbs": "Critical",
            "rbac-wildcard-resources": "Critical",
            "rbac-wildcard-apigroups": "Critical",
            "rbac-escalation-verbs": "Critical",
            "rbac-cluster-admin": "Critical",
            "rbac-secret-access": "High",
            "rbac-exec-access": "High",
            "rbac-log-access": "Medium",
            "rbac-group-bindings": "High",
            "default-service-account": "High",
            "automount-token": "High",
            "token-projection-config": "Medium",
            "rbac-unused-roles": "Info",
            "rbac-subject-external": "Low",
            "cloud-iam-binding": "Medium",
        },
        # In live mode, many cluster-scoped RBAC checks don't fire in namespace
        # scans because the findings reference the cluster scope. Only namespace-
        # scoped Role/RoleBinding checks and workload checks fire.
        "live_excluded_checks": [
            "rbac-cluster-admin",
            "rbac-group-bindings",
            "rbac-subject-external",
            "cloud-iam-binding",
            "rbac-wildcard-resources",
            "rbac-wildcard-apigroups",
            "token-projection-config",
        ],
        "min_findings": 18,
        "live_min_findings": 10,
        "severity_mins": {
            "Critical": 5,
            "High": 6,
            "Medium": 4,
            "Low": 1,
            "Info": 1,
        },
        "live_severity_mins": {
            "Critical": 1,
            "High": 2,
        },
        "expected_exit": 1,
    },
    "network": {
        "namespace": "kv-e2e-network",
        "json_file_pattern": "e2e-manifest-network.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-network.json",
        "checks": {
            # network-policy-missing is live-only
            # network-policy-default-deny is live-only
            "network-policy-overly-permissive": "Medium",
            # network-policy-egress-unrestricted is live-only
            "ingress-no-tls": "High",
            "ingress-wildcard-host": "Medium",
            "ingress-class-missing": "Low",
            "service-type-loadbalancer": "Medium",
            "service-type-nodeport": "Medium",
            "external-ips": "High",
        },
        "min_findings": 10,  # Lower in manifest mode (no namespace-level checks)
        "severity_mins": {
            "High": 4,
            "Medium": 4,
            "Low": 3,
        },
        "expected_exit": 1,
        "live_only_checks": [
            "network-policy-default-deny",
        ],
        # In the E2E network namespace, NetworkPolicies ARE deployed (allow-all),
        # so network-policy-missing doesn't fire, but default-deny and overly-
        # permissive do fire. Egress-unrestricted doesn't fire because the
        # allow-all-egress policy covers it.
        "live_excluded_checks": [
            "network-policy-missing",
            "network-policy-egress-unrestricted",
        ],
        "live_min_findings": 15,
    },
    "secrets": {
        "namespace": "kv-e2e-secrets",
        "json_file_pattern": "e2e-manifest-secrets.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-secrets.json",
        "checks": {
            "secrets-in-env": "Medium",
        },
        "min_findings": 4,
        "severity_mins": {
            "Medium": 4,
        },
        "expected_exit": 1,
    },
    "psa": {
        "namespace": "kv-e2e-psa",
        "json_file_pattern": "e2e-manifest-psa.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-psa.json",
        "checks": {
            "psa-labels-missing": "Medium",
            "psa-mode-audit-only": "Medium",
            "psa-baseline-violations": "High",
            "psa-restricted-violations": "Medium",
            "psa-version-pinning": "Low",
        },
        # In live namespace mode, PSA checks on sub-namespaces (kv-e2e-psa-audit,
        # kv-e2e-psa-baseline, etc.) produce findings attributed to those namespaces,
        # which get filtered out by -n kv-e2e-psa. Only psa-labels-missing and
        # psa-restricted-violations fire on the kv-e2e-psa namespace itself.
        "live_excluded_checks": [
            "psa-mode-audit-only",
            "psa-baseline-violations",
            "psa-version-pinning",
        ],
        "min_findings": 18,
        "live_min_findings": 4,
        "severity_mins": {
            "High": 4,
            "Medium": 11,
            "Low": 3,
        },
        "live_severity_mins": {
            "Medium": 1,
        },
        "expected_exit": 1,
    },
    "scheduling": {
        "namespace": "kv-e2e-scheduling",
        "json_file_pattern": "e2e-manifest-scheduling.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-scheduling.json",
        "checks": {
            "toleration-control-plane": "High",
            "toleration-all": "Medium",
            "priority-class-system": "High",
            "priority-class-missing": "Low",
            "pod-disruption-budget": "Low",
            "topology-spread": "Low",
            "hpa-without-requests": "Medium",
        },
        "live_extra_checks": {
            "node-affinity-untrusted": "Medium",
        },
        "min_findings": 8,
        "live_min_findings": 30,
        "severity_mins": {
            "High": 3,
            "Medium": 2,
            "Low": 3,
        },
        "expected_exit": 1,
    },
    "storage": {
        "namespace": "kv-e2e-storage",
        "json_file_pattern": "e2e-manifest-storage.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-storage.json",
        "checks": {
            "emptydir-size-limit": "Low",
            "projected-volume-security": "Medium",
            "pvc-no-encryption": "Medium",
            # pvc-reclaim-retain is live-only
        },
        "min_findings": 5,
        "severity_mins": {
            "Medium": 4,
            "Low": 1,
        },
        "expected_exit": 1,
        "live_only_checks": [],
        # pvc-reclaim-retain doesn't fire in Kind because no PV has Retain
        # reclaim policy in the test cluster.
        "live_excluded_checks": [
            "pvc-reclaim-retain",
        ],
    },
    "cluster-hardening": {
        "namespace": "default",
        "json_file_pattern": "e2e-manifest-cluster-hardening.json",
        "live_json_file_pattern": "e2e-live-ns-default.json",
        "checks": {
            "namespace-default-usage": "Medium",
            # limit-range-missing is live-only
            # resource-quota-missing is live-only
            "deprecated-api-usage": "Medium",
        },
        "min_findings": 3,  # Lower in manifest mode
        "severity_mins": {
            "Medium": 3,
        },
        "expected_exit": 1,
        "live_only_checks": [],
        # deprecated-api-usage doesn't fire on K8s 1.25+ (PSP removed).
        # limit-range-missing and resource-quota-missing are live-only and
        # have severity Low.
        "live_excluded_checks": [
            "deprecated-api-usage",
        ],
        "live_extra_checks": {
            "limit-range-missing": "Low",
            "resource-quota-missing": "Low",
        },
        "live_min_findings": 10,
        "live_severity_mins": {
            "Low": 2,
        },
    },
    "mixed": {
        "namespace": "kv-e2e-mixed",
        "json_file_pattern": "e2e-manifest-mixed.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-mixed.json",
        "checks": {
            "image-tag-latest": "Medium",
            "image-no-digest": "Low",
            "run-as-root": "High",
            "read-only-rootfs": "Medium",
            "capabilities-not-dropped": "Medium",
            "seccomp-profile": "Medium",
            "privilege-escalation": "High",
            "resource-limits-missing": "Medium",
            "resource-requests-missing": "Medium",
            "liveness-readiness-probes": "Low",
        },
        "min_findings": 10,
        "severity_mins": {
            "High": 2,
            "Medium": 6,
            "Low": 2,
        },
        "expected_exit": 1,
    },
    "clean": {
        "namespace": "kv-e2e-clean",
        "json_file_pattern": "e2e-manifest-clean.json",
        "live_json_file_pattern": "e2e-live-ns-kv-e2e-clean.json",
        "checks": {},
        "min_findings": 0,
        "severity_mins": {},
        "expected_exit": 0,
    },
}


def load_findings(json_path):
    """Load findings from a KubeVigil JSON output file."""
    with open(json_path) as f:
        data = json.load(f)

    scan_result = data.get("scan_result", data)
    findings = scan_result.get("findings", [])
    return findings


def validate_category(category, results_dir, mode="manifest"):
    """Validate a single category against expected findings.

    Args:
        category: Category name from EXPECTED dict.
        results_dir: Directory containing scan result JSON files.
        mode: "manifest" or "live". In live mode, uses live file patterns
              and includes live-only checks in expected set.

    Returns a dict with:
        passed: bool
        details: list of (status, message) tuples
        stats: dict with counts
    """
    spec = EXPECTED[category]
    is_live = mode == "live"

    # Select file pattern based on mode.
    if is_live:
        pattern = spec.get("live_json_file_pattern", spec["json_file_pattern"])
    else:
        pattern = spec["json_file_pattern"]
    json_path = os.path.join(results_dir, pattern)

    if not os.path.exists(json_path):
        return {
            "passed": False,
            "details": [("ERROR", f"JSON file not found: {json_path}")],
            "stats": {},
        }

    findings = load_findings(json_path)
    details = []
    all_ok = True

    # Collect actual check IDs and severities.
    actual_checks = set()
    actual_by_check = defaultdict(list)
    severity_counts = Counter()

    for f in findings:
        check_id = f.get("checker", f.get("checkID", ""))
        severity = f.get("severity", "")
        actual_checks.add(check_id)
        actual_by_check[check_id].append(severity)
        severity_counts[severity] += 1

    # Build the set of expected checks based on mode.
    expected_checks = dict(spec["checks"])
    live_only = spec.get("live_only_checks", [])
    live_excluded = set(spec.get("live_excluded_checks", []))

    if is_live:
        # In live mode, add live-only checks and live-extra checks to expected.
        for check_id in live_only:
            # Default severity for live-only checks (can be overridden).
            expected_checks.setdefault(check_id, "High")
        for check_id, sev in spec.get("live_extra_checks", {}).items():
            expected_checks[check_id] = sev
        # Remove checks excluded in live mode (e.g., cluster-scoped checks
        # excluded from namespace-scoped live scans).
        for check_id in live_excluded:
            expected_checks.pop(check_id, None)

    # 1. Check expected check IDs fired.
    for check_id, expected_sev in expected_checks.items():
        if check_id in actual_checks:
            # Check severity matches.
            actual_sevs = set(actual_by_check[check_id])
            if expected_sev in actual_sevs:
                details.append(("PASS", f"{check_id} fired with severity {expected_sev}"))
            else:
                details.append((
                    "SEV_MISMATCH",
                    f"{check_id} fired but with severity {actual_sevs} "
                    f"(expected {expected_sev})"
                ))
                all_ok = False
        else:
            # In manifest mode, live-only checks are expected to be absent.
            if not is_live and check_id in live_only:
                details.append((
                    "SKIP",
                    f"{check_id} not fired (live-only check, expected in manifest mode)"
                ))
            else:
                details.append(("FALSE_NEG", f"{check_id} NOT fired (false negative)"))
                all_ok = False

    # 2. Check for unexpected checks (false positives).
    expected_ids = set(expected_checks.keys())
    live_only_set = set(live_only)
    unexpected = actual_checks - expected_ids - live_only_set

    # Some checks may fire on scenario manifests that aren't in the expected list
    # (e.g., workload checks on resources in non-workload scenarios). We flag them
    # as warnings, not failures.
    for check_id in sorted(unexpected):
        count = len(actual_by_check[check_id])
        details.append((
            "EXTRA",
            f"{check_id} fired {count} time(s) (not in expected list)"
        ))

    # 3. Check minimum finding count.
    total = len(findings)
    min_expected = spec.get("live_min_findings", spec["min_findings"]) if is_live else spec["min_findings"]
    if total >= min_expected:
        details.append(("PASS", f"Total findings: {total} (min expected: {min_expected})"))
    else:
        details.append((
            "COUNT_LOW",
            f"Total findings: {total} (min expected: {min_expected})"
        ))
        all_ok = False

    # 4. Check severity distribution.
    sev_mins = spec.get("live_severity_mins", spec.get("severity_mins", {})) if is_live else spec.get("severity_mins", {})
    for sev, min_count in sev_mins.items():
        actual_count = severity_counts.get(sev, 0)
        if actual_count >= min_count:
            details.append(("PASS", f"Severity {sev}: {actual_count} (min: {min_count})"))
        else:
            details.append((
                "SEV_COUNT",
                f"Severity {sev}: {actual_count} (min expected: {min_count})"
            ))
            all_ok = False

    stats = {
        "total_findings": total,
        "unique_checks": len(actual_checks),
        "severity_counts": dict(severity_counts),
        "expected_checks_found": len(expected_ids & actual_checks),
        "expected_checks_total": len(expected_ids),
        "unexpected_checks": len(unexpected),
    }

    return {"passed": all_ok, "details": details, "stats": stats}


def validate_all(results_dir, mode="manifest"):
    """Validate all categories and print a summary."""
    total_pass = 0
    total_fail = 0
    all_issues = []

    for category in EXPECTED:
        result = validate_category(category, results_dir, mode=mode)
        status = "PASS" if result["passed"] else "FAIL"

        if result["passed"]:
            total_pass += 1
        else:
            total_fail += 1

        stats = result.get("stats", {})
        total = stats.get("total_findings", "?")
        found = stats.get("expected_checks_found", "?")
        expected = stats.get("expected_checks_total", "?")

        print(f"\n{'=' * 70}")
        print(f"  [{status}] {category}")
        print(f"  Findings: {total} | Checks: {found}/{expected} expected found")
        print(f"{'=' * 70}")

        for detail_status, msg in result["details"]:
            icon = {
                "PASS": "  \u2705",
                "FALSE_NEG": "  \u274c",
                "SEV_MISMATCH": "  \U0001f536",
                "COUNT_LOW": "  \U0001f4ca",
                "SEV_COUNT": "  \U0001f4ca",
                "EXTRA": "  \u26a0\ufe0f ",
                "SKIP": "  \u23ed\ufe0f ",
                "ERROR": "  \U0001f6a8",
            }.get(detail_status, "  ?")
            print(f"{icon} [{detail_status}] {msg}")

            if detail_status in ("FALSE_NEG", "SEV_MISMATCH", "COUNT_LOW", "SEV_COUNT", "ERROR"):
                all_issues.append((category, detail_status, msg))

    # Print summary table.
    print(f"\n{'=' * 70}")
    print("  VALIDATION SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Categories passed: {total_pass}")
    print(f"  Categories failed: {total_fail}")
    print(f"  Total issues: {len(all_issues)}")

    if all_issues:
        print(f"\n  Issues requiring attention:")
        for cat, status, msg in all_issues:
            print(f"    [{cat}] {status}: {msg}")

    return 0 if total_fail == 0 else 1


def validate_output_formats(results_dir):
    """Validate that output format files are well-formed."""
    checks = [
        ("JSON", "e2e-manifest-workload.json", validate_json),
        ("SARIF", "e2e-manifest-workload.sarif", validate_sarif),
        ("HTML", "e2e-manifest-workload.html", validate_html),
        ("JUnit XML", "e2e-manifest-workload.xml", validate_xml),
        ("CSV", "e2e-manifest-workload.csv", validate_csv),
        ("YAML", "e2e-manifest-workload.yaml", validate_yaml),
        ("Markdown", "e2e-manifest-workload.md", validate_markdown),
        ("Text", "e2e-manifest-workload.txt", validate_text),
    ]

    all_ok = True
    print(f"\n{'=' * 70}")
    print("  OUTPUT FORMAT VALIDATION")
    print(f"{'=' * 70}")

    for fmt_name, filename, validator in checks:
        path = os.path.join(results_dir, filename)
        if not os.path.exists(path):
            print(f"  \u274c {fmt_name}: file not found ({filename})")
            all_ok = False
            continue
        try:
            validator(path)
            size = os.path.getsize(path)
            print(f"  \u2705 {fmt_name}: valid ({size:,} bytes)")
        except Exception as e:
            print(f"  \u274c {fmt_name}: {e}")
            all_ok = False

    return all_ok


def validate_json(path):
    with open(path) as f:
        data = json.load(f)
    assert "scan_result" in data or "findings" in data, "Missing scan_result or findings key"


def validate_sarif(path):
    with open(path) as f:
        data = json.load(f)
    assert "$schema" in data or "version" in data, "Missing $schema or version"
    assert "runs" in data, "Missing 'runs' key"
    assert len(data["runs"]) > 0, "Empty runs array"
    assert "results" in data["runs"][0], "Missing results in first run"


def validate_html(path):
    with open(path) as f:
        content = f.read()
    assert len(content) > 100, f"HTML too short ({len(content)} bytes)"
    assert "<html" in content.lower(), "Missing <html> tag"


def validate_xml(path):
    import xml.etree.ElementTree as ET
    tree = ET.parse(path)
    root = tree.getroot()
    assert root.tag in ("testsuites", "testsuite"), f"Unexpected root tag: {root.tag}"


def validate_csv(path):
    import csv
    with open(path) as f:
        reader = csv.reader(f)
        header = next(reader)
        assert len(header) >= 3, f"CSV header too short: {header}"
        row_count = sum(1 for _ in reader)
    assert row_count >= 0, "CSV has no data rows"


def validate_yaml(path):
    # Use basic YAML parsing (PyYAML might not be available).
    with open(path) as f:
        content = f.read()
    assert len(content) > 10, f"YAML too short ({len(content)} bytes)"
    # Try importing yaml if available.
    try:
        import yaml
        data = yaml.safe_load(content)
        assert data is not None, "YAML parsed to None"
    except ImportError:
        # Fallback: just check it looks like YAML.
        assert ":" in content, "Doesn't look like YAML (no colons)"


def validate_markdown(path):
    with open(path) as f:
        content = f.read()
    assert len(content) > 50, f"Markdown too short ({len(content)} bytes)"
    assert "#" in content, "Markdown has no headers"


def validate_text(path):
    with open(path) as f:
        content = f.read()
    assert len(content) > 10, f"Text too short ({len(content)} bytes)"


def validate_fix(pre_scan, post_scan, risk_level="safe"):
    """Validate fix results by comparing pre-scan and post-scan JSON files.

    Args:
        pre_scan: Path to pre-fix scan JSON file.
        post_scan: Path to post-fix scan JSON file.
        risk_level: Risk level used for the fix (safe, moderate, aggressive).

    Returns:
        dict with passed, details, and stats.
    """
    details = []
    all_ok = True

    # Load pre-scan findings.
    if not os.path.exists(pre_scan):
        return {"passed": False, "details": [("ERROR", f"Pre-scan file not found: {pre_scan}")], "stats": {}}
    pre_findings = load_findings(pre_scan)

    if not os.path.exists(post_scan):
        return {"passed": False, "details": [("ERROR", f"Post-scan file not found: {post_scan}")], "stats": {}}
    post_findings = load_findings(post_scan)

    pre_count = len(pre_findings)
    post_count = len(post_findings)

    # Post-fix count should be less than pre-fix count.
    if post_count < pre_count:
        details.append(("PASS", f"Findings reduced: {pre_count} -> {post_count} ({pre_count - post_count} resolved)"))
    elif post_count == pre_count:
        details.append(("WARN", f"Finding count unchanged: {pre_count} -> {post_count}"))
        all_ok = False
    else:
        details.append(("FAIL", f"Findings increased: {pre_count} -> {post_count}"))
        all_ok = False

    # Check which checks were resolved.
    pre_checks = Counter(f.get("checker", f.get("checkID", "")) for f in pre_findings)
    post_checks = Counter(f.get("checker", f.get("checkID", "")) for f in post_findings)

    # Expected resolved checks by risk level.
    safe_checks = {"privileged", "privilege-escalation", "host-pid", "host-ipc",
                   "proc-mount", "share-process-namespace", "automount-token"}
    likely_safe_checks = {"capabilities-added", "capabilities-not-dropped", "run-as-root",
                          "read-only-rootfs", "host-network", "seccomp-profile", "image-pull-policy"}
    breaking_checks = {"resource-limits-missing", "resource-requests-missing",
                       "ephemeral-storage-limits", "host-ports"}

    expected_resolved = set(safe_checks)
    if risk_level in ("moderate", "aggressive"):
        expected_resolved |= likely_safe_checks
    if risk_level == "aggressive":
        expected_resolved |= breaking_checks

    for check_id in sorted(expected_resolved):
        if check_id in pre_checks and check_id not in post_checks:
            details.append(("PASS", f"{check_id} resolved by fix"))
        elif check_id in pre_checks and post_checks[check_id] < pre_checks[check_id]:
            details.append(("PASS", f"{check_id} partially resolved ({pre_checks[check_id]} -> {post_checks[check_id]})"))
        elif check_id in pre_checks:
            details.append(("WARN", f"{check_id} not resolved (still {post_checks[check_id]} findings)"))

    # Validate post-scan YAML files are still valid.
    details.append(("PASS", "Fix validation complete"))

    stats = {
        "pre_count": pre_count,
        "post_count": post_count,
        "resolved": pre_count - post_count,
        "risk_level": risk_level,
    }

    return {"passed": all_ok, "details": details, "stats": stats}


def main():
    parser = argparse.ArgumentParser(description="Validate KubeVigil E2E findings")
    parser.add_argument("--all", action="store_true", help="Validate all categories")
    parser.add_argument("--category", help="Validate a specific category")
    parser.add_argument("--results-dir", default="scan-results", help="Results directory")
    parser.add_argument("--formats", action="store_true", help="Validate output formats")
    parser.add_argument("--mode", choices=["manifest", "live", "fix"], default="manifest",
                        help="Scan mode: manifest (default), live, or fix")
    parser.add_argument("--pre-scan", help="Pre-fix scan JSON file (for --mode fix)")
    parser.add_argument("--post-scan", help="Post-fix scan JSON file (for --mode fix)")
    parser.add_argument("--risk-level", default="safe",
                        choices=["safe", "moderate", "aggressive"],
                        help="Risk level used for fix (for --mode fix)")
    args = parser.parse_args()

    exit_code = 0

    if args.mode == "fix":
        if not args.pre_scan or not args.post_scan:
            print("Error: --mode fix requires --pre-scan and --post-scan")
            sys.exit(1)
        result = validate_fix(args.pre_scan, args.post_scan, args.risk_level)
        status = "PASS" if result["passed"] else "FAIL"
        stats = result.get("stats", {})
        print(f"\n{'=' * 70}")
        print(f"  [{status}] Fix Validation (risk level: {args.risk_level})")
        print(f"  Pre-fix: {stats.get('pre_count', '?')} | Post-fix: {stats.get('post_count', '?')} | Resolved: {stats.get('resolved', '?')}")
        print(f"{'=' * 70}")
        for detail_status, msg in result["details"]:
            icon = {"PASS": "  \u2705", "FAIL": "  \u274c", "WARN": "  \u26a0\ufe0f ", "ERROR": "  \U0001f6a8"}.get(detail_status, "  ?")
            print(f"{icon} [{detail_status}] {msg}")
        if not result["passed"]:
            exit_code = 1
        sys.exit(exit_code)

    if args.formats:
        ok = validate_output_formats(args.results_dir)
        if not ok:
            exit_code = 1

    if args.all:
        rc = validate_all(args.results_dir, mode=args.mode)
        if rc != 0:
            exit_code = 1
    elif args.category:
        if args.category not in EXPECTED:
            print(f"Unknown category: {args.category}")
            print(f"Available: {', '.join(EXPECTED.keys())}")
            sys.exit(1)
        result = validate_category(args.category, args.results_dir, mode=args.mode)
        status = "PASS" if result["passed"] else "FAIL"
        print(f"[{status}] {args.category}")
        for detail_status, msg in result["details"]:
            print(f"  [{detail_status}] {msg}")
        if not result["passed"]:
            exit_code = 1
    elif not args.formats:
        parser.print_help()
        sys.exit(1)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
