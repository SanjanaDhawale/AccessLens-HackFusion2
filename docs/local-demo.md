# AccessLens — integrated local demo

This branch connects the User Portal, FastAPI control plane, synthetic ConnectedCar target, a deterministic BOLA authorization check, the Scan Operations Monitor, and a JSON report endpoint.

## Start (from repository root)

Install Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

Run these in **three separate terminals**:

```powershell
python -m uvicorn target.main:app --reload --port 8001
```

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

```powershell
python -m http.server 5500 --directory web
```

Open http://localhost:5500/user-portal.html and http://localhost:5500/admin-live.html.

## Demonstration

1. Enter `http://127.0.0.1:8001/vehicles/CAR-001` in the User Portal.
2. Confirm authorized scope `/vehicles/CAR-001` and approve.
3. The backend checks synthetic Alice (owner) and Bob (non-owner).
4. In vulnerable mode, Bob can read Alice's vehicle; the check reports BOLA FAIL.
5. In fixed mode, Bob receives HTTP 403; the check reports PASS.
6. The User Portal shows the verdict and offers a JSON report link; the Admin Monitor shows the scan record and findings.

Switch the synthetic target to fixed mode:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8001/mode -ContentType application/json -Body '{"mode":"fixed"}'
```

Switch back to vulnerable mode with `{"mode":"vulnerable"}`.

## Limitations and safety

- **Local-only**: the backend accepts targets on localhost / 127.0.0.1 port 8001 only.
- **Synthetic data only**: no real users, vehicles, or credentials.
- **No admin authentication**: never deploy this control plane publicly.
- **One bounded BOLA check**: no full OWASP coverage, no automated fixes.
- Reports are JSON demo summaries, not formal VAPT PDFs.
- Scan jobs live in memory and disappear on backend restart.
- Browser UI is static and the backend must be running separately.
- Do not point the system at third-party targets.

Run tests with `python -m pytest -q`.
