# Security Engine Test Results

Latest test command:

```powershell
python -m pytest security_engine_tests -q
```

Latest result in the review workspace:

```text
50 passed
```

Coverage includes:
- API8 CORS detector behavior
- BOLA input-model validation
- Credential reference resolution
- Sensitive-data redaction
- Safe HTTP method and request-scope enforcement
- Path traversal and encoded-separator rejection
- Private/loopback IP default-deny behavior
- Explicit authorized-IP allowlisting
- DNS resolution failure and public-address validation
- DNS resolution change detection between requests
- Ten-category coverage contract
- Sanitized FAILED response contract
- Evidence ID uniqueness and finding/evidence reference integrity

The successful crAPI combined scan fixture is based on the manually executed local lab scan from 2026-10-30. Its API1/API8 finding and evidence details are preserved; the eight unimplemented categories are represented as INCONCLUSIVE according to the updated coverage contract. Because target-address policy has since been tightened, rerun the live crAPI scan using the explicit `allow_private_targets` and `authorized_ips` fields before treating the latest source revision as live-integration verified.

DNS is resolved at validation and rechecked before each request. This detects resolution changes between checks but is not socket-level DNS pinning; deployment-level outbound network controls are still recommended to reduce DNS-rebinding/SSRF risk.
