# JUnit Integration

KubeVigil produces JUnit XML output, the de facto standard for test results in CI/CD systems. Every major CI platform -- Jenkins, GitLab CI, CircleCI, Azure DevOps, TeamCity -- can parse JUnit XML and display results natively.

## Generate JUnit Output

Write JUnit XML to a file by specifying an `.xml` extension:

```bash
kubevigil scan -f ./manifests/ -o results.xml
```

Or pipe to stdout with the format name:

```bash
kubevigil scan -f ./manifests/ -o junit > kubevigil-results.xml
```

## JUnit Output Structure

KubeVigil maps its findings to JUnit concepts:

| JUnit Concept | KubeVigil Mapping |
|---------------|-------------------|
| `<testsuites>` | Top-level wrapper. `tests` and `failures` attributes reflect total finding count. |
| `<testsuite>` | One per unique check ID (e.g., `privileged`, `run-as-root`). |
| `<testcase>` | One per finding. `name` is the resource (e.g., `default/Deployment/nginx`), `classname` is the check ID. |
| `<failure>` | Every finding is a failure. `message` is the finding description, `type` is the severity level. The failure body includes severity, message, remediation, and framework mappings. |
| `<properties>` | Top-level properties include posture score, severity counts, check coverage, and resource counts. |

This structure gives CI dashboards a natural drill-down: suite (check) to case (resource) to failure detail.

## Jenkins

Jenkins publishes JUnit results through the JUnit plugin (bundled with most installations).

### Jenkinsfile

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'kubevigil scan -f ./k8s/ -o junit > kubevigil-results.xml'
            }
            post {
                always {
                    junit 'kubevigil-results.xml'
                }
            }
        }
    }
}
```

After the build, findings appear under the **Test Results** tab with trend graphs over time.

### Failure Thresholds in Jenkins

To fail the build on high-severity findings while still recording all results:

```groovy
stage('Security Scan') {
    steps {
        sh 'kubevigil scan -f ./k8s/ -o junit --fail-on high > kubevigil-results.xml || true'
    }
    post {
        always {
            junit 'kubevigil-results.xml'
        }
    }
}
```

Use `|| true` to ensure the JUnit file is always published, then configure Jenkins quality gates to fail on the test result counts.

## GitLab CI

GitLab CI ingests JUnit XML through the `artifacts:reports:junit` directive. Findings appear inline in merge request diffs.

### `.gitlab-ci.yml`

```yaml
kubevigil:
  stage: test
  image: golang:1.22
  script:
    - go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest
    - kubevigil scan -f ./k8s/ -o junit > kubevigil-results.xml
  artifacts:
    when: always
    reports:
      junit: kubevigil-results.xml
```

Key points:

- `when: always` ensures results are uploaded even on scan failure.
- GitLab displays findings in the **Tests** tab of the merge request.
- Test suite names (check IDs) and case names (resources) provide a clear breakdown.

## CircleCI

CircleCI stores JUnit results for display in the **Tests** tab.

### `.circleci/config.yml`

```yaml
version: 2.1
jobs:
  security-scan:
    docker:
      - image: cimg/go:1.22
    steps:
      - checkout
      - run:
          name: Install KubeVigil
          command: go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest
      - run:
          name: Run KubeVigil
          command: kubevigil scan -f ./k8s/ -o junit > kubevigil-results.xml
      - store_test_results:
          path: kubevigil-results.xml
      - store_artifacts:
          path: kubevigil-results.xml
```

## Azure DevOps

Publish JUnit results with the `PublishTestResults` task:

```yaml
steps:
  - script: kubevigil scan -f ./k8s/ -o junit > kubevigil-results.xml
    displayName: Run KubeVigil

  - task: PublishTestResults@2
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: kubevigil-results.xml
      testRunTitle: KubeVigil Security Scan
    condition: always()
    displayName: Publish Results
```

## Using Properties for Dashboard Metrics

The top-level `<properties>` element contains aggregate scan metrics that CI systems can extract:

| Property | Description |
|----------|-------------|
| `posture_score` | Overall security posture score (0-100) |
| `total_findings` | Total number of findings |
| `critical` | Count of **Critical** findings |
| `high` | Count of **High** findings |
| `medium` | Count of **Medium** findings |
| `low` | Count of **Low** findings |
| `info` | Count of **Info** findings |
| `checks_run` | Number of checks executed |
| `checks_with_findings` | Number of checks that produced findings |
| `checks_clean` | Number of checks with zero findings |

These properties enable building dashboards that track posture score trends over time.

## See Also

- [Output Formats](../scanning/output-formats.md) -- all 8 supported formats
- [SARIF Integration](sarif.md) -- GitHub Code Scanning integration
- [IDE Integration](ide.md) -- editor workflows
- [Exit Codes](../reference/exit-codes.md) -- scan and fix exit codes
