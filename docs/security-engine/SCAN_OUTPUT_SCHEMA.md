# Security engine output contract

All outputs are JSON-compatible dictionaries. `COMPLETED` means the scanner execution completed; it does not mean the target is secure. Vulnerability findings can coexist with `COMPLETED`. A `FAILED` response retains all ten coverage records marked `INCONCLUSIVE`, has empty findings/evidence, and a summary of 10 inconclusive categories. It includes a generic sanitized `error` plus `error_code`; it must never be interpreted as a successful scan.

## Top-level fields

| Field | Type | Purpose |
|---|---|---|
| `scan_id` | string | Echoes the input scan ID. |
| `status` | `COMPLETED` or `FAILED` | Scanner execution status. `PARTIAL` is not implemented. |
| `coverage` | Coverage[] | Exactly ten OWASP API Security Top 10 (2023) records, in canonical order. Unimplemented categories are `INCONCLUSIVE`, never implied `PASS`. |
| `findings` | Finding[] | Evidence-backed vulnerability findings. |
| `evidence` | Evidence[] | Sanitized request/response evidence. |
| `summary` | object | Coverage counts, not HTTP request counts. |
| `error` | string, on failure | Generic sanitized failure message. |
| `error_code` | string, on failure | Currently `SCAN_FAILED`. |

## Coverage

`owasp_id`, `category`, `status` (`PASS`, `FAIL`, `INCONCLUSIVE`, `NOT_APPLICABLE`), `reason`.

## Finding

`id`, `owasp_id`, `title`, `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), `status`, `confidence` (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`), `endpoint`, `method`, `evidence_id`, `rationale`, `remediation`.

The current model has a singular `evidence_id` per finding. The orchestrator validates that finding IDs and evidence IDs are unique, every finding evidence reference resolves, the evidence record points back to the same finding, and no evidence references an unknown finding. Invalid relationships fail the scan with a sanitized error.

## Evidence

`evidence_id`, `finding_id`, `check_id`, UTC `timestamp`, `request`, `response`, `notes`.

- Request: `method`, `url`, sanitized `headers`.
- Response: nullable `status_code`, sanitized `headers`, redacted `body_excerpt`.
- Never store bearer tokens, cookies, API keys or sensitive personal/vehicle data in evidence.

## Summary

`tested`, `passed`, `failed`, `inconclusive`, `not_applicable`. These partition the ten OWASP coverage records. `tested` equals 10 for a completed scan, not the number of network requests.

## Fixtures

- `samples/scan_success_crapi.json`: actual successful combined scan captured on 2026-10-30; identifiers and response fields shown as captured, sensitive values redacted by the engine.
- `samples/scan_failed_example.json`: representative failed-contract shape for an invalid input; illustrative fixture.
- `samples/scan_inconclusive_example.json`: representative completed scan where detectors cannot reach a verdict; illustrative fixture.
- `samples/scan_partial_status.md`: explains that partial scans are not supported and must not be fabricated as a current output.
