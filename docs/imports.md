# Scan import contract

## General rules

Create assets first. Asset identifiers are lowercase canonical strings (letters, digits, dot, underscore, colon, slash and hyphen). A batch contains 1–1,000 rows, is UTF-8 (optional BOM), and is at most 2 MiB **file content**. The API/edge allow a small additional multipart envelope. Unknown fields, duplicate JSON keys, duplicate/unknown CSV headers, inconsistent CSV row widths, non-finite scores, invalid identifiers, control bytes and invalid UTF-8 are rejected. Archives, executables, XML and spreadsheets are not adapters.

The parser never executes files, invokes subprocesses, resolves paths, requests user-supplied URLs, or treats a description as trusted HTML. Files remain in bounded in-memory multipart storage. No raw upload is retained. A failed batch records only a sanitized reason and basename. Asset validation/import writes are transactional; any error rolls back the entire batch. Concurrent unique-key conflicts require retrying the whole batch and return a safe message.

## JSON (`generic-json`)

```json
{
  "schema_version": "1.0",
  "findings": [{
    "asset": "server-01",
    "title": "Apache Log4j remote code execution",
    "cve_id": "CVE-2021-44228",
    "description": "Scanner observation; validate installed version.",
    "cvss_score": 10,
    "locator": "tcp/443",
    "source": "your-scanner"
  }]
}
```

| Field | Requirement |
| --- | --- |
| `asset` | Required existing asset name, max 200 |
| `title` | Required nonempty string, max 300 |
| `cve_id` | `CVE-YYYY-NNNN…`, max 30; uppercase, optional if `external_id` exists |
| `external_id` | Namespace-qualified key, e.g. `nessus:plugin-12345`; max 200, optional if CVE exists |
| `description` | Optional text, max 10,000; default empty |
| `cvss_score` | Optional finite numeric 0–10, or JSON null; never a custom priority score |
| `locator` | Optional stable endpoint/package locator, max 200; default empty |
| `source` | Optional scanner provenance, max 100; default `generic` |

At least one vulnerability identity is required. If both exist, the CVE is the canonical key. A scanner score is labeled `import`; authoritative NVD enrichment replaces it with `nvd` provenance. Missing scores remain null, not zero. Titles/descriptions from later duplicate imports do not silently replace a shared vulnerability definition. A CVE not in the mirror is stored as pending enrichment, not presented as NVD-verified.

## CSV (`generic-csv`)

```csv
asset,title,cve_id,external_id,description,cvss_score,locator,source
server-01,Log4Shell,CVE-2021-44228,,Check installed version,10,tcp/443,my-scanner
server-01,Legacy TLS,,my-scanner:tls-old,Review protocol policy,5.3,tcp/443,my-scanner
```

`asset` and `title` headers are required; identity requirements still apply per row. Only documented field names are accepted. Empty optional cells use defaults/null; textual `null` is not JSON null. Standard CSV quoting applies to commas/newlines. Use the same stable locator across scanners if observations should deduplicate.

## Identity and re-observation

Fingerprint = SHA-256(JSON array of canonical asset name, canonical vulnerability key, locator). The scanner source is deliberately excluded. Different assets or locators create distinct findings. Reimport increments observation count and last-seen; it does not remove assignments, notes, first-seen, or history. A verified finding is reopened with a fresh deadline and retained original first-seen. Accepted risk stays accepted until explicitly reopened, while observations remain visible.

No scan disappearance automatically closes a finding. Verification requires an authorized person's recorded evidence; VulnWatch does not run scans or validate the evidence's truth.

## Adding an adapter

1. Implement the `Adapter` protocol in `backend/app/adapters`: an allowlisted extension and `parse(text) -> list[dict]`.
2. Normalize vendor fields into `ImportRow`, not database models. Namespace non-CVE scanner keys. Never run uploaded programs or follow network targets embedded in files.
3. Register the adapter in `ADAPTERS`. All adapters inherit byte/row limits and strict row validation.
4. Add parser fixtures, malformed/malicious payload tests, duplicate identity tests and a documented schema/version.
5. Expose the adapter in the frontend selector. The available contracts are also listed at `/api/imports/adapters`.

Third-party scanner licenses and export semantics must be reviewed before shipping a vendor-specific adapter.
