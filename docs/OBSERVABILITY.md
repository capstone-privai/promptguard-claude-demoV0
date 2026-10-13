# PromptGuard Observability

## Data flow

The dependency-free localhost UI renders two production audit streams through explicit raw-free DTO projections.

```text
Native Mod -> .promptguard/audit/mod-audit.json -> projectAudit() ------+
                                                                        +-> local browser
Final Guard -> .promptguard/audit/guard-audit.jsonl -> projectGuardAudit() -+
```

The Mod stream shows prompt/context/tool scans, findings, placeholder replacements, and failure stages. The Final Guard stream shows provider-bound SAFE/BLOCKED decisions, endpoint, body size, finding count/types, scan latency, reason code, and observed upstream HTTP status.

Guard records are correlated to the selected Mod session only by the existing 64-character `session_hash`. If no matching Final Guard record exists, the UI reports NOT VERIFIED. It does not infer a successful provider transmission from Mod masking alone.

The previous validation-only `src/guard/server.cjs` is no longer production source. Its legacy synthetic scenario implementation is retained only as `tests/observability/mock-guard-provider.cjs`. The active runtime and UI use `src/guard/final-guard.cjs` and its JSONL audit.

## Security boundary

The server never sends the browser whole audit records. `projectAudit()` and `projectGuardAudit()` construct allowlisted DTO fields and reject or normalize arbitrary values.

Neither browser stream contains:

- raw prompt, file content, tool input, or tool output
- request or response body
- credential value or secret snippet
- detector value hash
- Authorization or provider API-key headers
- arbitrary error messages or object paths

The Final Guard projection accepts only known endpoint/type/decision shapes, bounded numeric metadata, fixed-format session hashes, and uppercase reason codes. A malformed explicitly configured Guard audit produces `guardUnavailable: true`; a missing default audit simply means no Guard evidence yet. A partially appended final JSONL line is ignored until complete.

The dashboard listens only on `127.0.0.1`, enforces localhost Host/Origin and GET-only access, uses a restrictive CSP and `no-store`, and serves an exact static asset allowlist. It does not read Claude transcripts and has no third-party telemetry.

## Running

Start PromptGuard Runtime V1, then run the UI in another terminal:

```bash
./promptguard run
node src/observability/server.mjs
# http://127.0.0.1:18880
```

PowerShell uses `promptguard.cmd run`.

Default production inputs:

- `.promptguard/audit/mod-audit.json`
- `.promptguard/audit/guard-audit.jsonl`

Overrides:

- `PG_MOD_AUDIT`: exact Mod audit JSON file
- `PG_GUARD_AUDIT`: exact Final Guard JSONL file
- `PG_OBSERVABILITY_AUDIT_DIR`: directory containing both Runtime V1 audit files
- `PG_AUDIT_PATH`: Runtime V1 audit directory fallback
- `PG_AUDIT_DIR`: legacy Mod-only `.runtime/audit` directory
- `PG_OBSERVABILITY_PORT`: localhost UI port, default `18880`

DEMO mode remains visually labeled and uses only nonfunctional placeholder data. It never invokes a model or writes to the live audit.

## Verification

```bash
npm run lint
npm run typecheck
npm test
npm run build
npm run test:final-guard
```

The integration test starts the real detector ensemble, invokes Native Mod hooks, sends sanitized and raw synthetic requests through the production Final Guard to a synthetic upstream, verifies SAFE/BLOCKED/fail-closed audit projection, and confirms that only the safe request reached upstream.

DOM tests execute the actual UI in jsdom and verify production Guard rendering, every DEMO scenario, filters, sorting, absence of raw sentinels, and zero console output. HTTP tests cover Mod/Guard DTO projection, malformed Guard JSONL isolation, malformed Mod audit failure, localhost Host/Origin enforcement, and GET-only access.

## Limits

- SAFE means the Final Guard completed verification with zero findings. It does not mean every possible secret pattern is detectable.
- An upstream status is displayed only when the Guard observed one. Missing status is not presented as successful cloud delivery.
- Turn IDs, file paths, distinct file counts, request bodies, and full payload previews are intentionally unavailable.
- At most the latest 2,000 Mod and Guard records are projected. Audit files over 16 MiB are rejected.
- Actual Anthropic execution still depends on a valid user account; synthetic test upstream results are not labeled as actual Anthropic results.

Screenshots in this repository contain DEMO placeholders only.
