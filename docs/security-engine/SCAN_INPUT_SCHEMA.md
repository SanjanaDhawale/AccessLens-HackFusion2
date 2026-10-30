# Security engine input contract

Entry point: `security_engine.engine.run_security_scan(scan_input: dict) -> dict`.

The input is validated by Pydantic `ScanInput` (`extra="forbid"`). Unknown fields are rejected.

| Field | Type | Required | Rules |
|---|---|---:|---|
| `scan_id` | string | Yes | Non-empty after trimming. |
| `target_url` | string | Yes | Valid HTTP/HTTPS URL; URL userinfo is rejected. Scope validation further checks host and path. |
| `authorized_hosts` | string[] | Yes | At least one; normalized to lowercase, trailing dot removed; blank entries rejected. Exact host allowlisting is used. |
| `allowed_paths` | string[] | Yes | At least one; absolute path prefixes; rejects leading `//`, backslashes and dot traversal. |
| `endpoints` | Endpoint[] | Yes | Each endpoint requires `path`, `method`, `source`; `operation_id` optional. |
| `scan_profile` | string | Yes | Must equal `OWASP_API_TOP_10_SAFE`. |
| `authorization_context` | object | Yes | `authorization_confirmed: bool` required; `credentials_available: bool` defaults false. Scope validator requires authorization confirmation. |
| `bola_test` | object or null | No | Optional API1 test configuration. Required for an active BOLA test; without it API1 is INCONCLUSIVE. |
| `allow_private_targets` | boolean | No | Defaults to `false`. Private, loopback, link-local, reserved and unspecified addresses are blocked unless explicitly enabled for an authorized lab. |
| `authorized_ips` | string[] | No | Defaults to `[]`. Exact IP allowlist. When private targets are enabled, every resolved target address must be included. Supports IPv4 and IPv6. |

## Endpoint object

- `path`: string beginning with one `/`; rejects `//`, backslash and control characters.
- `method`: string; normalized uppercase. Model accepts GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE. The shared safe HTTP client executes only GET, HEAD and OPTIONS.
- `operation_id`: optional string or null.
- `source`: `OPENAPI`, `AUTHORIZED_DISCOVERY`, or `USER_PROVIDED`.

## Optional `bola_test`

- `identities`: exactly two identities, one `user_a` and one `user_b`, with distinct approved `credential_ref` values.
- `credential_ref`: symbolic reference only; never put a token in the input. Current allowlist: `CRAPI_USER_A` and `CRAPI_USER_B`.
- `object_reference`: `object_id`, `object_type`, `owner_identity_id`, `read_path`.
- `test_cases`: exactly two cases: owner positive control (`OWNER_ACCESS`, expected `ALLOW`) and cross-account (`CROSS_ACCOUNT_ACCESS`, expected `DENY`). Owner and cross-account identities must be consistent with the object owner.

Credentials resolve from `CRAPI_USER_A_TOKEN` and `CRAPI_USER_B_TOKEN` environment variables. Values may be raw tokens or `Bearer ...`; tokens remain in memory and must not be logged or committed.

## Valid input example

See `samples/scan_input_valid.json` for a generic public-target shape and `samples/scan_input_crapi_example.json` for the authorized local crAPI lab example (with explicit loopback opt-in). For local crAPI, use `target_url: "http://localhost:8888"`, `authorized_hosts: ["localhost"]`, `allow_private_targets: true`, and `authorized_ips: ["127.0.0.1", "::1"]` (include only addresses actually resolved in your environment).

## Invalid input example

See `samples/scan_input_invalid.json`. It intentionally uses an unsupported profile, blank scan ID, wildcard host and unknown field; it must return `FAILED` without issuing a scan request.

## Scope and safety validation

The engine requires explicit authorization confirmation, exact authorized-host matching and allowed path-prefix matching. It resolves the target hostname and blocks private, loopback, link-local, reserved and unspecified IPs by default. For an isolated authorized lab only, set `allow_private_targets: true` and list every resolved address in `authorized_ips`. DNS is re-resolved before each request; a changed address set aborts the scan. URL userinfo, unsafe path forms and out-of-scope requests are rejected. Redirects are not followed. Safe HTTP client methods are GET/HEAD/OPTIONS; response sizes and request counts are capped. Do not use this engine against systems without explicit written authorization.


## DNS limitation

DNS is resolved during scope validation and rechecked before each HTTP request; a changed address set aborts the scan. This is not socket-level DNS pinning and does not eliminate the narrow time-of-check/time-of-use window. Production deployments should additionally enforce outbound network restrictions at the network/container layer.
