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

## Vendor adapters

Vendor adapters accept a locally produced export file. VulnWatch never calls a scanner API, needs no vendor SDK, and never runs the scanner. Export the report with the vendor's own tooling, then upload the file.

Unlike the generic adapters, vendor reports describe scanned artifacts, not VulnWatch inventory. They therefore require an explicit target asset:

```sh
curl -b cookies.txt -H 'Origin: http://localhost:8080' -H "X-CSRF-Token: $CSRF" \
  -F 'file=@trivy.json' \
  'http://localhost:8080/api/imports?adapter=trivy-json&asset=payments-api'
```

`asset` must name an existing asset. The importer never derives an asset name from a container image tag, repository path, or project label, because doing so would silently attribute findings to the wrong inventory. `GET /api/imports/adapters` reports `requires_asset` for each contract.

Vendor identifiers map to canonical identity as follows. A CVE identifier becomes the shared vulnerability key, so the same CVE observed by Trivy, Grype, or Dependency-Check updates one finding when the asset and locator also match. A vendor advisory without a CVE is stored under a namespace-qualified external key (`trivy:`, `grype:`, `dependency-check:`) or under `ghsa:` when the identifier is a GHSA ID.

| Adapter | Extension | Schema | Target locator | CVSS source |
| --- | --- | --- | --- | --- |
| `trivy-json` | `.json` | `SchemaVersion` 2 | `pkg:<PkgName>@<InstalledVersion>` | First finite `CVSS.*.V40Score`, then `V3Score`, then `V2Score` |
| `grype-json` | `.json` | Grype JSON document | `pkg:<artifact.name>@<artifact.version>` | First finite `vulnerability.cvss[].metrics.baseScore` |
| `dependency-check-json` | `.json` | `reportSchema` 1.1 | `pkg:<dependency.fileName>` | `cvssv4.baseScore`, then `cvssv3.baseScore`, then `cvssv2.score` |

Scores are copied exactly as exported and labeled `import`; they are never recomputed and never presented as VulnWatch's custom priority. Severity labels from the vendor are not used. Missing, non-numeric, non-finite, or out-of-range scores remain null.

### Trivy JSON (`trivy-json`)

Produced by `trivy image -f json -o trivy.json <image>`. Every entry in every `Results[].Vulnerabilities[]` array is imported, including OS packages and language packages. `Results[].Vulnerabilities` may be absent. `SchemaVersion` must be the number `2`. Container `ArtifactName` and `Metadata` are ignored for identity; the explicit `asset` query parameter is authoritative.

### Grype JSON (`grype-json`)

Produced by `grype <target> -o json`. Every entry in `matches[]` is imported. `matches` must be an array; `vulnerability.id` and `artifact.name` are required. `artifact.version` is optional and only affects the locator. `source.target` is ignored for identity.

### OWASP Dependency-Check JSON (`dependency-check-json`)

Produced by `dependency-check --format JSON --out dependency-check.json`. `reportSchema` must be a string. Every entry in `dependencies[].vulnerabilities[]` is imported; dependencies without vulnerabilities are skipped. `vulnerabilities[].name` is required and is normally a CVE identifier. `projectInfo.name` is ignored for identity.

### Fixture provenance and licensing

The files in `samples/` are synthetic. They reproduce the field structure of each tool's documented JSON output but contain invented package versions, descriptions explicitly marked as synthetic, and zeroed hashes. No vendor export, NVD record, or third-party advisory text is redistributed, so no vendor license or redistribution clause applies to the fixtures. Real reports may contain data you are not permitted to upload; treat exported files as confidential.

## Identity and re-observation

Fingerprint = SHA-256(JSON array of canonical asset name, canonical vulnerability key, locator). The scanner source is deliberately excluded. Different assets or locators create distinct findings. Reimport increments observation count and last-seen; it does not remove assignments, notes, first-seen, or history. A verified finding is reopened with a fresh deadline and retained original first-seen. Accepted risk stays accepted until explicitly reopened, while observations remain visible.

No scan disappearance automatically closes a finding. Verification requires an authorized person's recorded evidence; VulnWatch does not run scans or validate the evidence's truth.

## Adding an adapter

1. Implement the `Adapter` protocol in `backend/app/adapters`: an allowlisted `extension`, `schema_version`, `documentation` anchor, `requires_asset` flag and `parse(text, asset) -> list[dict]`. Keep shared JSON loading and row validation in `backend/app/adapters/core.py`.
2. Normalize vendor fields into `ImportRow`, not database models. Namespace non-CVE scanner keys. Never run uploaded programs or follow network targets embedded in files.
3. Set `requires_asset` when the export describes an artifact rather than an inventory asset; never guess the asset from vendor metadata.
4. Register the adapter in `ADAPTERS`. All adapters inherit byte/row limits, duplicate-key rejection, non-finite number rejection and strict row validation.
5. Add parser fixtures, malformed/malicious payload tests, cross-adapter deduplication tests, and a documented schema/version.
6. Expose the adapter in the frontend selector. The available contracts are also listed at `/api/imports/adapters`.

Third-party scanner export semantics must be reviewed against the vendor's published format before shipping a vendor-specific adapter, and fixtures must be synthetic or licensed for redistribution.
