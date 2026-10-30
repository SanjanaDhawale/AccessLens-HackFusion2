# AccessLens Security Engine – Member 2 Handoff

## Scope

This branch contains a synchronous, safe-scope API security scan engine with two registered detectors: API1 BOLA and limited API8 wildcard CORS configuration. It is an MVP and does **not** implement the full OWASP API Security Top 10.

## Quick start

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest security_engine_tests -q
```

For API1 BOLA testing, set `CRAPI_USER_A_TOKEN` and `CRAPI_USER_B_TOKEN` in the environment. See `.env.example`; never commit real secrets.

## Public API

```python
from security_engine.engine import run_security_scan
result = run_security_scan(scan_input: dict)
```

The exact input/output contracts, OWASP implementation matrix, integration notes and fixtures are under `docs/security-engine/`. Completed scans always return all ten OWASP 2023 coverage records; unimplemented categories are `INCONCLUSIVE`. Private/loopback targets are blocked by default and require `allow_private_targets: true` plus an exact `authorized_ips` allowlist for isolated labs.

## Current verification

- Unit tests: 50 passed after coverage, evidence-integrity and target-address validation updates.
- Manual authorized crAPI combined scan: `COMPLETED`; API1 BOLA and wildcard CORS both detected with linked evidence.

## Important

`COMPLETED` means the configured detectors ran; it does not mean no vulnerabilities exist. `summary.tested` counts coverage records. `PARTIAL` is not supported. Only API1 and limited API8 checks are implemented; the remaining eight coverage entries are marked `INCONCLUSIVE`. DNS is resolved at validation and rechecked before each request; changed resolutions abort the scan. Review the contract with the backend owner before integration.
