# Audit contract

Allowed fields: timestamp, hashed session id, source, finding/type/redacted counts, placeholder restore/re-mask counts (`restored_count`, `remasked_count`), blocked flag, reason code, latency, hook/tool identifiers.

Forbidden: raw prompt, raw tool output, full request body, credential value, credential snippet. `tests/e2e/build_results.py` scans generated audit/Guard/detector evidence for the synthetic fixture values.

The placeholder → raw value vault used to restore tool inputs right before execution lives only in Mod process memory and is never written to audit.
