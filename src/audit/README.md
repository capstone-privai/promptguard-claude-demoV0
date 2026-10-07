# Audit contract

Allowed fields: timestamp, hashed session id, source, finding/type/redacted counts, blocked flag, reason code, latency, hook/tool identifiers.

Forbidden: raw prompt, raw tool output, full request body, credential value, credential snippet. `tests/e2e/build_results.py` scans generated audit/Guard/detector evidence for the synthetic fixture values.
