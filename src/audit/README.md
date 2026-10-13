# Audit contract

Runtime V1 writes two raw-free audit streams under `.promptguard/audit/` (`auditPath` in `promptguard.config.json`). The legacy Mod-only launcher writes the Mod stream to `.runtime/audit/mod-audit-*.json`.

## Native Mod audit (`mod-audit.json`, JSON array)

Written by `src/native-mod/hooks/register.mjs`.

Allowed fields: timestamp, hashed session id (`session_id_hash`, 64 hex), source, hook and tool identifiers, event, local numeric operation, `scanned_payload_count`, finding/type/redacted counts, placeholder restore/re-mask counts (`restored_count`, `remasked_count`), blocked flag, fixed reason code, `failure_stage`, latency, and raw-free finding metadata (detector/type/rule, payload index, UTF-16 span, MASK action and replacement token).

Sources: `user_prompt`, `user_command` (`!` shell-mode rows from the `session.append` hook), `history`, `claude_md`, `automatic_context`, `subagent`, `read_result`, `grep`, `bash_stdout`, `bash_error`, `mcp`, `tool_result`.

`blocked` on a Mod failure describes the hook failure only. It is not proof of provider-bound enforcement: Claude Code skips a hook that throws.

## Final Guard audit (`guard-audit.jsonl`, one JSON object per line)

Written by `src/audit/writer.cjs`, which drops any field outside: `timestamp`, `request_id`, `session_hash`, `endpoint`, `body_size`, `finding_count`, `finding_types`, `decision` (`allow`/`block`), `reason`, `scan_latency_ms`, `upstream_status`.

## Never written

Raw prompt, raw tool output, request or response body, credential value or snippet, detector value hash, raw object key path, arbitrary tool identifier, payload preview, authorization header, or freeform exception message.

The placeholder → raw value vault used to restore tool inputs right before execution lives only in Mod process memory and is never written to audit. The Final Guard clean-scan cache holds only per-process HMACs in memory and is never written.

## Dashboard

`src/observability/server.mjs` projects both streams into allowlisted DTOs and correlates Guard records to a Mod session by session hash. The final cloud-egress state shows SAFE/BLOCKED only when a matching Final Guard record exists; otherwise it shows NOT VERIFIED.
