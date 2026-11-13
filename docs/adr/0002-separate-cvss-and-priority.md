# 0002 — Keep CVSS separate from custom risk priority

- **Status:** Accepted
- **Date:** 2026-11-13

## Context

CVSS describes the severity of a vulnerability in a standardized way, but it does not account for the criticality or exposure of a specific asset. Security teams need a prioritization score that incorporates local context without misrepresenting that score as an official CVSS rating.

## Decision

Store the CVSS base score and vector exactly as supplied by NVD. Compute a separate, clearly labeled **custom priority** from the CVSS base score (or an explicitly labeled unknown-score baseline), asset criticality, exposure, and configurable thresholds. Persist each assessment as an immutable snapshot with the policy inputs that produced it.

The API and UI must never label the custom priority as CVSS. Policy changes append new assessments instead of rewriting history.

## Consequences

- Reports and trends are reproducible and auditable.
- Analysts can see both the standardized severity and the organization-specific priority.
- The custom formula is transparent and configurable, but it is not a substitute for a formal CVSS environmental score.
- Unknown CVSS values must remain visibly unknown rather than defaulting to a fabricated score.
- Future EPSS or CISA KEV context must be separately sourced and labeled, not folded silently into CVSS.
