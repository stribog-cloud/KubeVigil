---
title: "ADR-001 No Live Cluster Patching"
created: 2026-07-02
type: project/adr
status: accepted
tags: [adr, kubevigil, safety]
---

# ADR-001: No Live Cluster Patching

## Status

Accepted

## Context

KubeVigil can remediate misconfigurations. Applying changes directly to a live cluster creates irreversible blast radius.

## Decision

The fix command only modifies local manifest files or emits kubectl/Helm/Kustomize artifacts. No Kubernetes write API calls.

## Consequences

- Operators must review and apply changes through their GitOps pipeline
- Eliminates entire class of accidental production mutation incidents
- SAR alignment: Safety by Design (Engineering Charter §3.5)