# 0003 — Adapter-based, in-memory scan imports

- **Status:** Accepted
- **Date:** 2026-11-13

## Context

Different scanners export findings in different formats. Imported files are untrusted, may be malformed or malicious, and must not be executed or persisted to disk. The design must allow additional scanner integrations without changing persistence or deduplication logic.

## Decision

Define a small adapter interface that converts a bounded byte payload into validated `ImportRow` objects. Ship documented Generic JSON and Generic CSV adapters. Keep parsing in memory, reject unknown fields where the schema is strict, bound file size and row count, and process each batch atomically.

Canonical finding identity is derived from asset name, vulnerability key, and locator. CVE identifiers deduplicate across scanner sources; non-CVE findings require a namespace-qualified external identifier. Scanner source is retained as provenance, not identity.

Import jobs record safe metadata and errors. Failed batches roll back and do not partially mutate inventory.

## Consequences

- New scanners implement an adapter and fixtures without modifying the database model.
- Duplicate detection is stable across scanners and repeat observations update history instead of creating duplicates.
- Malicious content is never executed or written to disk.
- Vendor-specific adapters require recorded, licensed export fixtures and dedicated security review.
- Attachments, SARIF, and SBOM ingestion need separate designs because they carry different trust and size characteristics.
