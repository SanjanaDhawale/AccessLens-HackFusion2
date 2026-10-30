# AccessLens — Team Development Workflow

## 1. Team structure

### Member 1 — Backend Platform
Primary branch: feat/connected-car-api
Secondary branch: feat/evidence-reporting

Responsibilities:
- FastAPI backend.
- API ingestion and discovery.
- Scan orchestration.
- Evidence management.
- VAPT PDF generation.

### Member 2 — Security Engine
Branch: feat/security-engine

Responsibilities:
- OWASP API Security Top 10 detectors.
- Scope enforcement.
- Response analysis.
- Security findings.
- Detector testing.

### Member 3 — Frontend
Branch: feat/dashboard

Responsibilities:
- Chat-first frontend.
- API integration.
- Scan progress interface.
- Findings and evidence UI.
- Admin dashboard.

## 2. Branch strategy

main:
Stable project version.

develop:
Integration branch.

Feature branches:
- feat/connected-car-api
- feat/evidence-reporting
- feat/security-engine
- feat/dashboard

Never push unfinished work directly to main.

## 3. Development rules

1. Inspect the repository before modifying files.
2. Follow docs/contracts.md.
3. Follow docs/architecture.md.
4. Work only on your assigned feature branch.
5. Do not overwrite another member's files.
6. Communicate shared API changes before implementing them.
7. Write tests for implemented functionality.
8. Commit changes with descriptive messages.
9. Open pull requests targeting develop.
10. Test integrated functionality before merging into main.

## 4. Integration order

Phase 1:
Finalize shared contracts.

Phase 2:
Member 1 establishes the backend foundation and API discovery.

Phase 3:
Member 2 integrates the security engine through the agreed scanner interface.

Phase 4:
Member 3 connects the frontend to the backend APIs.

Phase 5:
Member 1 completes evidence collection and PDF reporting.

Phase 6:
All members participate in end-to-end testing.

## 5. Git workflow

Before starting work:

git status
git branch --show-current
git fetch origin

Before committing:

git status
git diff --check

After testing:

git add <specific-files>
git commit -m "Describe implemented feature"
git push -u origin <feature-branch>

Create a pull request targeting develop.

## 6. Quality requirements

- No fabricated scan results.
- No hardcoded live vulnerability findings.
- No unauthorized API testing.
- No exposed credentials or secrets.
- No unreviewed destructive remediation.
- No false PASS results.
- All shared interfaces must follow docs/contracts.md.

## 7. Completion criteria

A feature is complete only when:
- Implementation exists.
- Relevant tests pass.
- Documentation is updated.
- Integration contract is respected.
- Changes are committed and pushed.
- Pull request is reviewed.