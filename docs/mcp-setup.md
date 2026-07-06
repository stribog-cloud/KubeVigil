# MCP Server — AI Assistant Integration

KubeVigil includes a built-in [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server that lets AI assistants scan Kubernetes clusters, query findings,
and provide remediation guidance through natural conversation.

## Prerequisites

1. **KubeVigil installed** — see [Installation](../README.md#installation)
2. **kubeconfig configured** — `kubectl cluster-info` works for live cluster scans
3. **An MCP-compatible AI assistant** — Claude Desktop, Cursor, VS Code, or
   Claude Code

## Setup

### Claude Desktop

Add the following to your Claude Desktop configuration file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "kubevigil",
      "args": ["mcp-server"],
      "env": {
        "KUBECONFIG": "/path/to/your/.kube/config"
      }
    }
  }
}
```

If `kubevigil` is not on your PATH, use the full path to the binary:

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "/usr/local/bin/kubevigil",
      "args": ["mcp-server"]
    }
  }
}
```

To use a custom KubeVigil configuration file, add `--config`:

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "kubevigil",
      "args": ["mcp-server", "--config", "/path/to/.kubevigil.yaml"]
    }
  }
}
```

Restart Claude Desktop after editing the configuration.

### Cursor

Add the following to your Cursor MCP configuration at `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "kubevigil",
      "args": ["mcp-server"],
      "env": {
        "KUBECONFIG": "/path/to/your/.kube/config"
      }
    }
  }
}
```

### VS Code with Copilot

MCP support in VS Code is available in recent versions. Add the following to
your VS Code settings (`settings.json`):

```json
{
  "mcp": {
    "servers": {
      "kubevigil": {
        "command": "kubevigil",
        "args": ["mcp-server"],
        "env": {
          "KUBECONFIG": "/path/to/your/.kube/config"
        }
      }
    }
  }
}
```

### Claude Code (CLI)

Add a `.mcp.json` file to your project root or `~/.claude/mcp.json` for global
configuration:

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "kubevigil",
      "args": ["mcp-server"]
    }
  }
}
```

### Workspace root (path confinement)

MCP `scan_manifests` accepts filesystem paths from AI agents. KubeVigil confines reads to a
**workspace root** so prompt injection cannot request arbitrary files (for example `~/.ssh/id_rsa`).

| Mechanism | Value |
|-----------|-------|
| CLI flag | `--workspace-root /path/to/manifest/tree` |
| Environment | `KUBEVIGIL_WORKSPACE_ROOT=/path/to/manifest/tree` |
| Default if unset | Process current working directory at server start |

**Always set an explicit narrow root** in MCP configuration — do not rely on cwd when the IDE
launches the server from `$HOME` or `/`.

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "kubevigil",
      "args": ["mcp-server", "--workspace-root", "/path/to/your/repo"],
      "env": {
        "KUBECONFIG": "/path/to/your/.kube/config"
      }
    }
  }
}
```

CLI `kubevigil scan -f` is **not** workspace-confined — operators supply trusted paths in CI
and local workflows. See ADR-003 and the threat model for scope.

### Verification

After configuring your AI assistant, verify the integration by asking:

> "What security checks does KubeVigil support?"

The assistant should respond with a list of the 110 available checks grouped by
category. If it does, the MCP server is connected and working.

## Available Tools

The MCP server exposes 6 tools:

| Tool | Description |
|------|-------------|
| `scan_cluster` | Scan a live Kubernetes cluster for security misconfigurations |
| `scan_manifests` | Scan YAML manifest files or directories for security issues |
| `get_summary` | Get a security posture summary of the most recent scan |
| `get_findings` | Query and filter findings with pagination |
| `list_checks` | Browse available security checks by category or scan mode |
| `get_remediation` | Get detailed fix guidance for a specific check or finding |

## Example Conversations

### 1. Full Cluster Scan with Drill-Down

Start with a broad scan, then drill into specific findings:

> **You:** Scan my production cluster for security issues.
>
> **Assistant:** I scanned your cluster and found 247 findings across 110 checks:
>
> | Severity | Count |
> |----------|-------|
> | Critical | 3     |
> | High     | 28    |
> | Medium   | 89    |
> | Low      | 127   |
>
> Top issues: `privileged` (3 findings), `run-as-root` (15 findings),
> `capabilities-added` (10 findings).
>
> **You:** Show me the critical findings.
>
> **Assistant:** Here are the 3 critical findings:
>
> 1. **privileged** on `payments/payment-processor` — Container runs in
>    privileged mode, granting full host access.
> 2. **privileged** on `default/debug-pod` — Container runs in privileged mode.
> 3. **privileged** on `monitoring/node-agent` — Container runs in privileged
>    mode.
>
> **You:** How do I fix the privileged container issue on payment-processor?
>
> **Assistant:** Set `securityContext.privileged` to `false` in the container
> spec:
>
> ```yaml
> securityContext:
>   privileged: false        # was: true
>   allowPrivilegeEscalation: false
> ```
>
> This check maps to CIS Benchmark 5.2.1 and MITRE ATT&CK T1611 (Escape to
> Host). KubeVigil can auto-fix this with `kubevigil fix --apply`.

### 2. Manifest Review Before Deployment

Check a deployment YAML before applying it to the cluster:

> **You:** Check the file `deploy/api-server.yaml` for security issues.
>
> **Assistant:** I scanned `deploy/api-server.yaml` and found 8 findings:
>
> - 1 High: `run-as-root` — No `runAsNonRoot: true` set
> - 2 Medium: `image-tag-latest`, `no-resource-limits`
> - 5 Low: `no-liveness-probe`, `no-readiness-probe`, `automount-token`,
>   `no-seccomp-profile`, `no-security-context`
>
> **You:** Which of these can be auto-fixed?
>
> **Assistant:** 5 of the 8 findings are auto-fixable:
>
> | Check | Safety | Auto-fixable |
> |-------|--------|-------------|
> | `run-as-root` | Likely Safe | Yes |
> | `no-resource-limits` | Potentially Breaking | Yes |
> | `automount-token` | Safe | Yes |
> | `no-seccomp-profile` | Likely Safe | Yes |
> | `no-security-context` | Likely Safe | Yes |
>
> Run `kubevigil fix deploy/api-server.yaml --apply --risk-level moderate` to
> apply safe and likely-safe fixes.

### 3. Compliance Check

Query findings by compliance framework:

> **You:** What CIS benchmark violations does my cluster have?
>
> **Assistant:** Your cluster has findings mapping to 42 CIS Kubernetes
> Benchmark v1.8 controls. The most common violations:
>
> - **5.2.1** Minimize privileged containers — 3 findings
> - **5.2.6** Minimize root containers — 15 findings
> - **5.2.8** Minimize capabilities — 10 findings
> - **5.1.6** Ensure automount service account tokens is not set to true — 22 findings
>
> **You:** Show me only the high-severity CIS violations in the payments namespace.
>
> **Assistant:** Found 4 high-severity CIS findings in `payments`:
>
> 1. `run-as-root` on `payments/payment-processor` (CIS 5.2.6)
> 2. `capabilities-added` on `payments/payment-processor` (CIS 5.2.8)
> 3. `run-as-root` on `payments/transaction-service` (CIS 5.2.6)
> 4. `no-resource-limits` on `payments/queue-worker` (CIS 5.2.9)

### 4. Check Exploration

Browse available checks without scanning:

> **You:** What security checks does KubeVigil run?
>
> **Assistant:** KubeVigil runs 110 checks across 12 categories:
>
> | Category | Checks |
> |----------|--------|
> | Workload | 25 |
> | RBAC | 15 |
> | Network | 12 |
> | Image | 9 |
> | Scheduling | 8 |
> | Secrets | 7 |
> | PSA | 6 |
> | Supply Chain | 5 |
> | Storage | 5 |
> | Cluster | 10 |
> | Cloud | 4 |
> | CRD | 4 |
>
> **You:** Show me the RBAC checks.
>
> **Assistant:** 15 RBAC checks:
>
> - `rbac-wildcard-verbs` (High) — Roles with wildcard verb permissions
> - `rbac-wildcard-resources` (High) — Roles with wildcard resource access
> - `rbac-cluster-admin` (Critical) — ClusterRoleBindings to cluster-admin
> - `rbac-bind-escalate` (High) — Roles with bind/escalate permissions
> - `rbac-secret-access` (Medium) — Roles with access to secrets
> - ... and 10 more
>
> **You:** What does the cluster-admin-binding check look for?
>
> **Assistant:** `rbac-cluster-admin` checks for ClusterRoleBindings that grant
> the `cluster-admin` ClusterRole to users, groups, or service accounts.
> Cluster-admin provides unrestricted access to all resources in all
> namespaces.
>
> **Remediation:** Replace cluster-admin bindings with more restrictive
> custom roles that grant only the permissions needed. Map to CIS Benchmark
> 5.1.1 and MITRE ATT&CK T1078.004 (Cloud Accounts).

### 5. Multi-Namespace Comparison

Compare security posture across namespaces:

> **You:** Scan the staging namespace.
>
> **Assistant:** Scanned `staging`: 45 findings (0 Critical, 5 High, 18 Medium,
> 22 Low).
>
> **You:** Now scan the production namespace.
>
> **Assistant:** Scanned `production`: 12 findings (0 Critical, 1 High,
> 4 Medium, 7 Low). Production has significantly fewer findings than staging
> (12 vs 45), suggesting better security hardening in production workloads.

## Troubleshooting

### "MCP server not found"

The AI assistant cannot find the `kubevigil` binary. Ensure it is on your PATH
or use the full path in your MCP configuration:

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "/usr/local/bin/kubevigil",
      "args": ["mcp-server"]
    }
  }
}
```

Find where kubevigil is installed:

```bash
which kubevigil
```

### macOS Gatekeeper blocks KubeVigil

On macOS, downloaded binaries carry a `com.apple.provenance` attribute that
Gatekeeper may block. Claude Desktop silently fails to enable the MCP toggle
when this happens — no error is shown.

**Symptoms:** The kubevigil toggle in Claude Desktop stays off and won't flip
on. No tools appear in Settings → Connectors → kubevigil.

**Fix:** Create a shell wrapper script that invokes the binary. macOS does not
gate shell scripts the same way it gates Mach-O binaries:

```bash
# Create the wrapper
cat > ~/.local/bin/kubevigil-mcp << 'EOF'
#!/bin/bash
exec /path/to/kubevigil mcp-server "$@"
EOF
chmod +x ~/.local/bin/kubevigil-mcp
```

Then update your Claude Desktop config to use the wrapper:

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "/Users/yourname/.local/bin/kubevigil-mcp",
      "env": {
        "KUBECONFIG": "/Users/yourname/.kube/config"
      }
    }
  }
}
```

Restart Claude Desktop after making this change.

**Alternative:** If you build from source (`go build ./cmd/kubevigil`), the
resulting binary may still acquire the provenance attribute depending on your
macOS version. The wrapper approach works regardless.

### "Connection refused"

The MCP server uses stdio transport (stdin/stdout), not network sockets. Verify
your MCP configuration specifies `"command"` (not a URL) and uses `"args":
["mcp-server"]`:

```bash
# Test that the binary starts correctly
echo '{}' | kubevigil mcp-server
# Should produce JSON-RPC output, not an error
```

### "No scan results available"

Tools like `get_findings`, `get_summary`, and `get_remediation` require a scan
to be run first. Ask the assistant to run `scan_cluster` or `scan_manifests`
before querying results:

> "Scan my cluster first, then show me the critical findings."

### "Kubeconfig not found"

For live cluster scans, the MCP server needs access to your kubeconfig. Set the
`KUBECONFIG` environment variable in your MCP configuration:

```json
{
  "mcpServers": {
    "kubevigil": {
      "command": "kubevigil",
      "args": ["mcp-server"],
      "env": {
        "KUBECONFIG": "/Users/yourname/.kube/config"
      }
    }
  }
}
```

If you use multiple kubeconfig contexts, specify the context when asking for a
scan:

> "Scan my staging cluster using the staging-context kubeconfig context."

## CLI Reference

```
kubevigil mcp-server [flags]

Flags:
  -h, --help                    help for mcp-server
      --transport string        transport type (stdio) (default "stdio")
      --workspace-root string   root directory for manifest scans (default: KUBEVIGIL_WORKSPACE_ROOT or cwd)

Global Flags:
      --config string   config file path (default: auto-discover)
      --no-color        disable colored output
  -o, --output string   output format or file path (text, json, markdown, yaml, html, sarif, junit, csv; or report.html, report.json, etc.) (default "text")
  -v, --verbose         enable verbose logging
```

Note: `-o/--output` is a persistent flag registered on the root command, so it
applies to `mcp-server` (and every other subcommand) even though it is more
commonly used with `scan`.
