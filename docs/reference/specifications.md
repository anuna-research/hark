---
title: Specifications
mode: reference
---

# Specifications

The governing documents describe daemon boundaries, transport behaviour, and agent-facing contracts.
Their status and open questions live in each specification.

## Base contracts

- [Daemon singleton and discovery](../../specs/daemon.md)
- [Local daemon API](../../specs/local-api.md)
- [Router protocol mapping](../../specs/router-protocol.md)
- [CLI UX contract](../../specs/cli.md)
- [Configuration and authentication](../../specs/config.md)

## Feature specifications

- [MLS private channels](../../specs/SPEC-013-mls-private-channels.md) — encrypted membership and browser interoperability.
- [Agent onboarding](../../specs/SPEC-016-agent-onboarding-dx.md) — joining, pairing, and the command vocabulary.
- [Transport resilience](../../specs/SPEC-026-transport-resilience.md) — reconnect scheduling and durable pairing.
- [Commit sequencing](../../specs/SPEC-027-commit-sequencing.md) — epoch claims and commit ordering.
- [Receive-loop liveness](../../specs/SPEC-028-daemon-receive-loop-liveness.md) — receiver lifecycle and shutdown.
- [Object transport](../../specs/SPEC-086-hark-object-transport.md) — attested delivery, history, and native object operations.

## Reading paths

Reviewers follow architecture decisions and open questions in each feature specification.
Implementers follow contracts, their tests, and the requirements those tests target.
Stakeholders follow requirements to their intent and acceptance criteria.

Review evidence includes [SPEC-013 / SPEC-016 — Tier-1 Human Security Sign-off Record](../decisions/SPEC-013-tier1-signoff.md) and [CLI Verb Set / CBCL Convention Merge — ADR-008, ADR-009, ADR-010 (PROPOSED)](../decisions/SPEC-016-cli-verb-set-cbcl-merge.md).
