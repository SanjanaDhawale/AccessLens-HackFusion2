# AccessLens — API Security Testing Assistant

Evidence-driven API security testing for explicitly authorized targets.

## MVP
- Read/write BOLA, BFLA, missing authentication, excessive information disclosure
- OpenAPI endpoint discovery and multi-identity testing
- Evidence capture, risk scoring, reports, and fix re-scan
- AI is optional and never decides security verdicts

## Run locally
1. Create and activate a Python virtual environment.
2. Install: `pip install -r requirements.txt`
3. Copy `.env.example` to `.env`.
4. Start demo target: `uvicorn target.main:app --reload --port 8001`
5. Start control API: `uvicorn backend.main:app --reload --port 8000`
6. Open `web/index.html`.

The scaffold includes interfaces and TODOs; implement assigned modules in your feature branches.

## Safety
Only scan explicitly authorized systems. Keep the scope guard enabled. Use synthetic disposable records for write tests. Never commit credentials or real personal data.

## Team branches
- `feat/connected-car-api`
- `feat/security-engine`
- `feat/dashboard`
- `feat/evidence-reporting`

Open pull requests into `develop`, not `main`. Read `docs/contracts.md` before changing shared interfaces.
