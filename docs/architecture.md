# Architecture

1. Web dashboard submits a scan request and renders scan state, findings, matrix, and evidence.
2. Backend control plane validates requests and orchestrates scans.
3. Scope guard validates every target URL before outbound requests.
4. OpenAPI parser discovers operations and security metadata.
5. Identity/session manager maintains isolated sessions for synthetic personas.
6. Policy engine and detectors execute deterministic authorization tests.
7. Evidence/risk/reporting redacts and hashes evidence, assigns transparent risk scores, and renders reports.
8. ConnectedCar target provides synthetic vulnerable/fixed endpoints for repeatable demonstration.

The security engine is the source of truth. AI is an optional explanation layer only.
