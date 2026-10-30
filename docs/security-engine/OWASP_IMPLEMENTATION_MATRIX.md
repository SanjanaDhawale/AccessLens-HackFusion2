# OWASP API Security Top 10 implementation matrix

Status is based on executable implementation and evidence available in this branch, not merely the presence of a file.

| OWASP 2023 category | Status | Evidence / limitation |
|---|---|---|
| API1 – Broken Object Level Authorization (BOLA) | Implemented; manual lab verification completed | Owner positive-control and cross-account test against local crAPI. Combined scan produced HIGH / CONFIRMED finding with linked evidence. Unit tests currently emphasize models/scope; dedicated mocked detector-behavior test coverage should be added. |
| API2 – Broken Authentication | Not implemented | No detector or execution evidence. |
| API3 – Broken Object Property Level Authorization | Not implemented | No detector or execution evidence. |
| API4 – Unrestricted Resource Consumption | Not implemented | No detector or execution evidence. |
| API5 – Broken Function Level Authorization | Not implemented | No detector or execution evidence. |
| API6 – Unrestricted Access to Sensitive Business Flows | Not implemented | No detector or execution evidence. |
| API7 – Server-Side Request Forgery (SSRF) | Not implemented | No detector or execution evidence. |
| API8 – Security Misconfiguration | Limited implementation; manual lab verification completed | Checks wildcard `Access-Control-Allow-Origin` using explicit untrusted Origin. Combined scan found wildcard CORS on a 401 response. This establishes permissive CORS configuration, not authenticated browser data exposure or exploitability. No complete security-header/TLS/configuration audit. |
| API9 – Improper Inventory Management | Not implemented | No detector or execution evidence. |
| API10 – Unsafe Consumption of APIs | Not implemented | No detector or execution evidence. |

All ten categories are now emitted in every completed scan. API1 and limited API8 execute detectors; API2–API7, API9 and API10 are represented as `INCONCLUSIVE` because they are not implemented. The product must be described as a limited MVP, not full OWASP API Top 10 coverage.
