# Shared contracts — source of truth

All members must preserve these interfaces. Discuss changes before modifying them.

## Finding object
```json
{
  "id": "FIND-001",
  "type": "BOLA",
  "severity": "CRITICAL",
  "endpoint": "/vehicles/{vin}",
  "method": "GET",
  "verdict": "FAIL",
  "confidence": "CONFIRMED",
  "requirement_id": "SEC-AUTHZ-001",
  "evidence_id": "EVD-001",
  "risk_score": 5
}
```
Allowed verdicts: PASS, FAIL, INCONCLUSIVE. Confidence: CONFIRMED, HIGH, MEDIUM, LOW. Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.

A PASS requires a completed test proving expected policy behaviour. Absence of a finding is not a PASS.

## Evidence object
Required fields: evidence_id, finding_id, timestamp, identity, request, response, expected_policy, observed_result, sha256. Redact authorization headers, cookies, tokens, API keys, and sensitive values before persistence or display.

## Proposed scan request
```json
{
  "target_url": "http://127.0.0.1:8001",
  "openapi_url": "http://127.0.0.1:8001/openapi.json",
  "approved_scope": ["/vehicles", "/users"],
  "mode": "vulnerable"
}
```

## Safety rules
- Every outbound request must pass engine.scope.validate_target_url.
- Only explicitly authorized hosts and paths may be tested.
- Write tests use disposable synthetic objects and must be resettable.
- Do not persist secrets or real personal data.
- AI may explain findings but must not set verdict, severity, or confidence.
