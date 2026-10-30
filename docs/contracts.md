# AccessLens — Shared API Contracts

Version: 1.0
Project: HackFusion 2.0
Status: Initial team contract

## 1. Purpose

This document defines the shared interfaces between:

- Member 1: Backend platform, discovery, orchestration, evidence and reporting.
- Member 2: OWASP API Security Engine.
- Member 3: Chat-first frontend and admin dashboard.

All members must follow these contracts. Changes require agreement between the responsible members.

## 2. Core conventions

Base API prefix: /api

Content type: application/json unless otherwise specified.

Timestamp format: ISO 8601 UTC.

Identifiers:
- Scan ID: unique string.
- Session ID: unique string.
- Finding ID: unique string.
- Evidence ID: unique string.

Standard scan statuses:
- QUEUED
- VALIDATING
- DISCOVERING
- RUNNING
- COMPLETED
- FAILED
- CANCELLED

Finding statuses:
- PASS
- FAIL
- INCONCLUSIVE
- NOT_APPLICABLE

Severity:
- CRITICAL
- HIGH
- MEDIUM
- LOW
- INFO

Confidence:
- CONFIRMED
- HIGH
- MEDIUM
- LOW
- UNKNOWN

## 3. Authorization and scope

Every scan must have explicit authorization confirmation.

The backend must validate:
- Target URL scheme.
- Authorized hostname.
- Allowed paths.
- Redirect destinations.
- Scan profile.
- Request limits.

The scanner must never assume that submitting a URL grants permission to test it.

Only explicitly authorized targets may be scanned.

## 4. Frontend-to-backend API

### 4.1 Health check

GET /api/health

Example response:

{
  "status": "ok",
  "service": "accesslens-api",
  "version": "1.0.0"
}

### 4.2 Chat interaction

POST /api/chat

Request:

{
  "session_id": "SESSION-001",
  "message": "Test my API against OWASP API Security Top 10."
}

Response:

{
  "session_id": "SESSION-001",
  "message": "Please provide your API URL or OpenAPI specification.",
  "action": "REQUEST_TARGET",
  "data": {}
}

Supported actions:

- REQUEST_TARGET
- REQUEST_AUTHORIZATION
- START_SCAN
- GET_SCAN_STATUS
- SHOW_RESULTS
- GENERATE_REPORT
- REQUEST_REMEDIATION
- UNKNOWN

The chat service must not claim a scan has run unless the backend confirms it.

### 4.3 Create scan

POST /api/scans

Content-Type: application/json

Request:

{
  "target_url": "http://localhost:8888",
  "authorization_confirmed": true,
  "authorized_hosts": [
    "localhost"
  ],
  "allowed_paths": [
    "/"
  ],
  "scan_profile": "OWASP_API_TOP_10_SAFE",
  "specification_source": "URL"
}

Response:

{
  "scan_id": "SCAN-001",
  "status": "QUEUED",
  "message": "Assessment queued successfully."
}

Important:

- authorization_confirmed must be true.
- The target must pass scope validation.
- The backend must reject invalid or out-of-scope targets.
- The scan must not start before validation succeeds.

### 4.4 OpenAPI file upload

POST /api/targets/specification

Content-Type: multipart/form-data

Form fields:

- file: OpenAPI JSON or YAML file.
- target_url: optional base URL.
- authorization_confirmed: authorization confirmation.
- authorized_hosts: agreed host scope.

Response:

{
  "specification_id": "SPEC-001",
  "status": "PARSED",
  "endpoint_count": 12,
  "message": "Specification parsed successfully."
}

File uploads must be validated for size, type, and content.

### 4.5 Get scan status

GET /api/scans/{scan_id}

Response:

{
  "scan_id": "SCAN-001",
  "status": "RUNNING",
  "progress": 45,
  "current_stage": "AUTHORIZATION_TESTING",
  "message": "Testing authorized endpoints."
}

Progress must reflect actual backend execution, not simulated frontend animation.

### 4.6 Get discovered endpoints

GET /api/scans/{scan_id}/endpoints

Response:

{
  "scan_id": "SCAN-001",
  "total_endpoints": 2,
  "endpoints": [
    {
      "path": "/api/vehicles",
      "method": "GET",
      "source": "OPENAPI"
    },
    {
      "path": "/api/vehicles/{id}",
      "method": "GET",
      "source": "OPENAPI"
    }
  ]
}

Endpoint discovery sources:

- OPENAPI
- AUTHORIZED_DISCOVERY
- USER_PROVIDED

Do not claim arbitrary endpoint discovery from a base URL alone.

### 4.7 Get findings

GET /api/scans/{scan_id}/findings

Response:

{
  "scan_id": "SCAN-001",
  "total_findings": 1,
  "findings": [
    {
      "id": "AL-001",
      "owasp_id": "API1:2023",
      "title": "Broken Object Level Authorization",
      "severity": "HIGH",
      "status": "FAIL",
      "confidence": "CONFIRMED",
      "endpoint": "/api/vehicles/{id}",
      "method": "GET",
      "evidence_id": "EVD-001",
      "rationale": "Observed unauthorized access to another user's resource.",
      "remediation": "Enforce object-level authorization for every resource."
    }
  ]
}

The example is a schema illustration, not a real finding.

### 4.8 Get evidence

GET /api/evidence/{evidence_id}

Response:

{
  "evidence_id": "EVD-001",
  "scan_id": "SCAN-001",
  "request_summary": "Sanitized request metadata",
  "response_summary": "Sanitized response metadata",
  "integrity_sha256": "example-hash",
  "created_at": "2026-10-30T10:00:00Z"
}

Never expose raw credentials, tokens, cookies, or secrets.

### 4.9 Generate and download report

POST /api/reports/{scan_id}

Response:

{
  "scan_id": "SCAN-001",
  "report_status": "GENERATED",
  "download_url": "/api/reports/SCAN-001/download"
}

GET /api/reports/{scan_id}/download

Returns the generated PDF file.

The report must include:
- Assessment scope.
- Authorization statement.
- Methodology.
- Executive summary.
- OWASP coverage.
- Findings and severity.
- Sanitized evidence references.
- Remediation recommendations.
- Limitations.
- Assessment timestamp.

## 5. Remediation workflow

POST /api/remediation/{finding_id}/request

Request:

{
  "action": "PREPARE_REMEDIATION",
  "approval_confirmed": false
}

The backend must not modify source code without explicit approval.

Source-code remediation requires:
- Source repository or supplied source files.
- A defined change scope.
- Explicit user approval.
- A reviewable patch.
- A separate approval before applying changes.

A target URL alone is insufficient to modify an application.

Retesting must also require explicit user approval.

## 6. Scanner interface — Member 1 and Member 2

Member 1 owns scan orchestration.

Member 2 owns detector implementation.

The scanner must expose a stable callable interface agreed by both members.

Conceptual input:

{
  "scan_id": "SCAN-001",
  "target_url": "http://localhost:8888",
  "authorized_hosts": [
    "localhost"
  ],
  "allowed_paths": [
    "/"
  ],
  "endpoints": [],
  "scan_profile": "OWASP_API_TOP_10_SAFE",
  "authorization_context": {}
}

Conceptual output:

{
  "scan_id": "SCAN-001",
  "status": "COMPLETED",
  "coverage": [],
  "findings": [],
  "summary": {
    "tested": 0,
    "passed": 0,
    "failed": 0,
    "inconclusive": 0,
    "not_applicable": 0
  }
}

The exact Python method signature and typed models must be finalized jointly before implementation.

The scanner must:
- Enforce scope on every request.
- Use bounded requests and timeouts.
- Avoid destructive testing.
- Redact sensitive information.
- Return evidence-backed results.
- Report untested categories honestly.

## 7. OWASP API Security Top 10 — 2023 mapping

API1:2023 — Broken Object Level Authorization

API2:2023 — Broken Authentication

API3:2023 — Broken Object Property Level Authorization

API4:2023 — Unrestricted Resource Consumption

API5:2023 — Broken Function Level Authorization

API6:2023 — Unrestricted Access to Sensitive Business Flows

API7:2023 — Server Side Request Forgery

API8:2023 — Security Misconfiguration

API9:2023 — Improper Inventory Management

API10:2023 — Unsafe Consumption of APIs

A category must not be marked PASS unless the corresponding checks actually ran and produced sufficient evidence.

## 8. Error response format

All API errors should follow this structure:

{
  "error": {
    "code": "INVALID_TARGET",
    "message": "The target URL is outside the authorized scope.",
    "details": {}
  }
}

Never expose stack traces, credentials, internal secrets, or sensitive infrastructure information to frontend users.

## 9. Ownership

Member 1:
- Backend APIs.
- Target ingestion.
- Endpoint discovery.
- Scan orchestration.
- Evidence management.
- PDF reporting.

Member 2:
- Scanner interface implementation.
- Scope guard within the engine.
- OWASP detectors.
- Security verdicts.
- Detector tests.

Member 3:
- Chat interface.
- Frontend API client.
- Scan progress and findings UI.
- Evidence and report interface.
- Admin dashboard.

## 10. Contract change policy

Any change to:
- API routes.
- Request schemas.
- Response schemas.
- Finding fields.
- Scanner interface.
- Status values.

Must be documented here and communicated to all three members before implementation.

End of contract.
