# Audit contract

Allowed fields: timestamp, hashed session id, source, finding/type/redacted counts, placeholder restore/re-mask counts (`restored_count`, `remasked_count`), blocked flag, reason code, latency, hook/tool identifiers.

Forbidden: raw prompt, raw tool output, full request body, credential value, credential snippet. `tests/e2e/build_results.py` scans generated audit/Guard/detector evidence for the synthetic fixture values.

The placeholder → raw value vault used to restore tool inputs right before execution lives only in Mod process memory and is never written to audit.

Observability additions: event, local numeric operation, scanned_payload_count,
failure_stage, and raw-free finding metadata (detector/type/rule, payload index,
UTF-16 span, MASK action and replacement token). Failure reasons are fixed codes.
No value_hash, raw object key path, arbitrary tool identifier, payload preview,
or freeform exception message is written by the updated Mod audit.

`blocked` on a Mod failure describes the hook failure only. It is not proof of
provider-bound enforcement. The dashboard displays actual Cloud egress as NOT
VERIFIED and keeps validation Guard records explicitly separate.
