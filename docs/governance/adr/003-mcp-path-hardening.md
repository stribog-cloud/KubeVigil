---
title: "ADR-003 MCP and Fix Path Hardening"
created: 2026-07-02
type: project/adr
status: accepted
tags: [adr, kubevigil, security, mcp]
---

# ADR-003: MCP and Fix Path Hardening (v0.5.0)

## Status

Accepted (implemented v0.5.0)

## Context

MCP tools and fix `--apply` accept filesystem paths from AI agents and CI — untrusted input per Security Posture Standard.

## Decision

- `os.Lstat` on paths to reject symlinks
- `filepath.Rel` boundary checks on backup targets
- YAML document count and file size limits
- Namespace/context length validation in MCP scan_cluster

## Consequences

- Additional tests in `internal/mcp` and `internal/fix`
- Security architecture review recorded per Security Posture §3