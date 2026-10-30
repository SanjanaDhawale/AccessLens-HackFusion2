# AccessLens — System Architecture

## 1. Overview

AccessLens is an AI-powered conversational API security assessment and VAPT platform.

The system accepts authorized API targets and OpenAPI specifications, discovers endpoints, performs controlled security assessments, stores evidence, and generates VAPT reports.

## 2. Architecture principles

- Modular backend architecture.
- REST-based frontend communication.
- Separation of API orchestration and security detection.
- Evidence-backed security findings.
- Strict authorization and scope validation.
- Deterministic security verdicts.
- Optional AI-assisted explanations.
- Secure handling of credentials and evidence.

## 3. Main components

### 3.1 Frontend

Responsibilities:
- Conversational interface.
- API target submission.
- Authorization confirmation.
- Scan progress.
- Endpoint inventory.
- Vulnerability results.
- Evidence presentation.
- Report downloads.
- Remediation approval.
- Admin dashboard.

### 3.2 Backend API

Technology: Python and FastAPI.

Responsibilities:
- Accept frontend requests.
- Validate incoming data.
- Manage target registration.
- Start and monitor scans.
- Coordinate discovery and scanning.
- Persist scan results.
- Serve findings and reports.

### 3.3 Target Discovery Service

Responsibilities:
- Accept API URLs.
- Parse OpenAPI JSON and YAML.
- Extract paths and HTTP methods.
- Extract operation metadata.
- Build endpoint inventory.
- Record endpoint discovery source.

Discovery sources:
- OPENAPI
- AUTHORIZED_DISCOVERY
- USER_PROVIDED

A base URL alone does not guarantee complete endpoint discovery.

### 3.4 Scope Validation Service

Responsibilities:
- Validate target schemes.
- Validate authorized hosts.
- Validate allowed paths.
- Validate redirects.
- Reject out-of-scope requests.
- Enforce scan policies.

All outbound requests must pass scope validation.

### 3.5 Scan Orchestrator

Responsibilities:
1. Validate authorization.
2. Validate target scope.
3. Discover endpoints.
4. Invoke security engine.
5. Collect findings.
6. Store evidence references.
7. Update scan progress.
8. Mark scan completion or failure.

### 3.6 OWASP Security Engine

Owned by Member 2.

Responsibilities:
- Implement OWASP API Security Top 10 checks.
- Perform controlled security tests.
- Analyze API responses.
- Validate authorization behavior.
- Generate structured findings.
- Provide confidence and severity.
- Report limitations and inconclusive results.

### 3.7 Evidence Management

Owned by Member 1.

Responsibilities:
- Collect sanitized request metadata.
- Collect sanitized response metadata.
- Redact sensitive information.
- Generate evidence identifiers.
- Calculate SHA-256 integrity hashes.
- Associate evidence with findings.

### 3.8 Reporting Engine

Owned by Member 1.

Responsibilities:
- Generate PDF VAPT reports.
- Summarize security findings.
- Include OWASP mappings.
- Include severity and confidence.
- Include evidence references.
- Include remediation guidance.
- Document assessment limitations.

### 3.9 Database

Initial technology: SQLite with SQLAlchemy.

Stores:
- Targets.
- Scans.
- Endpoints.
- Findings.
- Evidence metadata.
- Reports.
- Scan activity.

Credentials and sensitive evidence must not be stored in plaintext.

### 3.10 AI Assistant Layer

Responsibilities:
- Interpret user instructions.
- Explain security findings.
- Summarize scan results.
- Explain remediation recommendations.
- Guide the user through the workflow.

The AI assistant must not independently determine security verdicts.

## 4. Main data flow

1. User submits API URL or OpenAPI specification.
2. Backend validates authorization and scope.
3. Discovery service extracts endpoints.
4. Scan orchestrator invokes Member 2's security engine.
5. Engine executes permitted security checks.
6. Engine returns structured results.
7. Backend stores findings and sanitized evidence.
8. Reporting engine generates VAPT PDF.
9. Frontend displays results and available actions.

## 5. Initial technology stack

Backend:
- Python
- FastAPI
- Pydantic
- HTTPX
- SQLAlchemy
- SQLite
- PyYAML

Reporting:
- ReportLab
- Jinja2

Testing:
- Pytest

Frontend:
- Existing project frontend framework.

## 6. Security controls

- Explicit authorization before scanning.
- Host and path allowlists.
- Redirect validation.
- Request timeouts.
- Bounded concurrency.
- Request budgets.
- Secret redaction.
- Safe error handling.
- Audit logging.
- No destructive testing.

## 7. Initial testing environment

Use OWASP crAPI locally in an isolated environment.

Do not test public or third-party targets without explicit authorization.

## 8. Future extensions

- Additional legacy API integrations.
- Advanced authentication support.
- Expanded OWASP detector coverage.
- Source-code remediation assistance.
- Retesting after approval.
- Advanced admin analytics.