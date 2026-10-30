# Backend integration and testing notes

## Stable public entry point

```python
from security_engine.engine import run_security_scan
result: dict = run_security_scan(scan_input: dict)
```

Call synchronously from a worker/background task rather than a latency-sensitive HTTP request handler. The current engine is synchronous and does not persist scans, progress, findings or evidence. The backend owns persistence, scan IDs/lifecycle, authorization policy and report generation.

## Integration contract notes for Member 1

1. Validate/authorize the caller and target before invoking the engine; the engine independently validates the supplied scope.
2. Pass the exact input fields documented in `SCAN_INPUT_SCHEMA.md`; unknown keys are rejected.
3. Persist the returned `coverage`, `findings`, `evidence`, and `summary`. Every completed scan returns all ten OWASP 2023 categories; unimplemented categories are explicitly `INCONCLUSIVE`.
4. Finding/evidence link is one-to-one in current model: `finding.evidence_id` ↔ `evidence.evidence_id`, and `evidence.finding_id` ↔ `finding.id`.
5. Current status values are only `COMPLETED` and `FAILED`; there is no `PARTIAL` status or progress callback. A `FAILED` result still includes ten INCONCLUSIVE coverage records, no findings/evidence, and a sanitized error.
6. `summary.tested` is coverage-record count, not request count.
7. Keep credential references symbolic; configure actual token values in the process environment/secret manager.
8. Do not persist or expose raw credentials. Evidence is sanitized but should still be handled as security-sensitive data.

## Independent installation

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest security_engine_tests -q
```

Set secrets in the same PowerShell session (do not commit `.env` or tokens):

```powershell
$env:CRAPI_USER_A_TOKEN = "<user-a-token>"
$env:CRAPI_USER_B_TOKEN = "<user-b-token>"
```

Use `samples/scan_input_valid.json` as the generic structure, or `samples/scan_input_crapi_example.json` for the authorized local crAPI lab input. Update the target, host allowlist, paths, endpoint and object reference only for a system explicitly authorized for testing. Then call `run_security_scan(input_dict)` from Python and serialize the returned dictionary with `json.dumps(result, indent=2)`.

## Tests currently present

The branch includes tests for API8 CORS behavior, BOLA model validation, credential resolution, redaction, request-client safety, scope validation (including private-IP and DNS failure cases), all-ten coverage output, evidence referential integrity, and engine failure-contract shape. Latest local run after these changes: **50 passed**. Reported working environment: Python 3.14.6, Pydantic 2.14.2, HTTPX 0.28.1 and pytest 9.2.0; supported dependency ranges are declared in `requirements.txt`. The manual crAPI combined scan captured in `samples/scan_success_crapi.json` completed with API1 FAIL/HIGH/CONFIRMED and API8 FAIL/LOW/HIGH.

Not currently present: a dedicated API1 detector mocked unit-test suite, a repeatable end-to-end crAPI integration test, and partial-scan tests (the engine does not support PARTIAL). The real crAPI run is manual integration evidence, not a repeatable automated test.

## Known limitations / pre-merge review

- Only API1 and limited API8 detectors are implemented.
- No `PARTIAL` status, detector timeout isolation, progress events, persistence, PDF generation or backend integration in this package.
- API8 does not prove browser exploitability; latest captured API8 response was HTTP 401 with wildcard ACAO.
- The safe client restricts methods to GET/HEAD/OPTIONS; model endpoint enum accepts additional methods, but those methods are skipped/rejected by safe execution.
- Current summary counts the ten OWASP coverage records (not HTTP requests).
- Private, loopback, link-local, reserved and unspecified addresses are blocked by default. An isolated lab target requires `allow_private_targets: true` and an exact `authorized_ips` allowlist. DNS is resolved at scan validation and rechecked before each request; this detects changed resolutions but is not socket-level DNS pinning, so enforce outbound network policy at deployment for stronger SSRF/rebinding protection.
- Add dedicated API1 behavior tests before expanding detector coverage.
- Confirm Member 1's PostgreSQL schema can represent the singular `evidence_id` and current status enums before integration.
