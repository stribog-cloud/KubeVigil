# KubeVigil Scan Report

## Executive Summary

**Posture Score: 89/100**

| Metric | Value |
|--------|-------|
| KubeVigil | dev |
| Scan Mode | Manifest |
| Duration | 50ms |
| Total Findings | 3 |
| Resources Affected | 3 |
| Namespaces | 2 |
| Checks Run | 25 |
| Checks with Findings | 3 |
| Checks Clean | 22 |
| Checks Skipped | 2 |
| Checks Errored | 0 |
| Pass Rate | 88% |

### Findings by Check

| Severity | Check | Findings | Resources |
|----------|-------|----------|-----------|
| 🔴 Critical | privileged | 1 | 1 |
| 🟠 High | run-as-root | 1 | 1 |
| 🟡 Medium | read-only-rootfs | 1 | 1 |

## Findings (3 total)

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 1 |
| 🟡 Medium | 1 |
| 🔵 Low | 0 |
| ⬜ Info | 0 |

## Compliance Summary

### CIS

| Control | Title | Severity | Resources |
|---------|-------|----------|-----------|
| 5.2.1 | Minimize the admission of privileged containers | Critical | 1 |
| 5.2.6 | Minimize the admission of root containers | High | 1 |
| 5.2.4 | Minimize the admission of containers with readOnlyRootFilesystem | Medium | 1 |

### MITRE

| Control | Title | Severity | Resources |
|---------|-------|----------|-----------|
| T1611 | Escape to Host | Critical | 1 |

### NSA

| Control | Title | Severity | Resources |
|---------|-------|----------|-----------|
| 3.1 | Pod Security | Critical | 2 |

### Category Breakdown

| Category | Findings | Critical | High | Medium | Low | Info |
|----------|----------|----------|------|--------|-----|------|
| Application | 3 | 1 | 1 | 1 | 0 | 0 |

## Application Namespaces

### backend (1 findings — 🟠1)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | run-as-root | backend/Deployment/api-server (api) | Container runs as root | CIS 5.2.6 |

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

Set runAsNonRoot: true

**Affected resources:** backend/Deployment/api-server

</details>

### default (2 findings — 🔴1 🟡1)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🔴 Critical | privileged | default/Deployment/nginx (nginx) | Container runs in privileged mode | CIS 5.2.1 · MITRE T1611 · NSA 3.1 |
| 🟡 Medium | read-only-rootfs | default/StatefulSet/worker (worker) | Root filesystem is not read-only | CIS 5.2.4 · NSA 3.1 |

<details>
<summary>Remediation: privileged (1 resources affected)</summary>

Set securityContext.privileged to false

**Affected resources:** default/Deployment/nginx

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

Set readOnlyRootFilesystem: true

**Affected resources:** default/StatefulSet/worker

</details>

