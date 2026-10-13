// The only projection from local audit files into browser state. Never spread input objects.
const types = new Set(['PASSWORD', 'API_KEY', 'TOKEN', 'PRIVATE_KEY', 'AWS_KEY', 'GITHUB_TOKEN', 'SLACK_TOKEN', 'JWT', 'SECRET', 'CREDENTIAL'])
const sources = { user_prompt: 'USER_PROMPT', user_command: 'USER_PROMPT', read_result: 'FILE_READ', grep: 'TOOL_OUTPUT', bash_error: 'TOOL_OUTPUT', bash_stdout: 'TOOL_OUTPUT', mcp: 'TOOL_OUTPUT', tool_result: 'TOOL_OUTPUT', history: 'HISTORY', claude_md: 'AGENTS_CONTEXT', outbound: 'FINAL_REQUEST' }
const hooks = new Set(['prompt.submit', 'prompt.context', 'prompt.section', 'prompt.compose', 'prompt.attachment', 'skill.prompt', 'agent.spawn', 'tool.call', 'tool.call.text', 'tool.call.context', 'session.compact', 'session.append', 'turn.step', 'turn.step.agent-input'])
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null
const timestamp = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)) ? value : null
const rule = value => typeof value === 'string' && /^[A-Za-z][A-Za-z ()+_.-]{0,119}$/.test(value) ? value : null

export function projectAudit(rows) {
  if (!Array.isArray(rows)) throw new Error('AUDIT_UNAVAILABLE')
  return rows.slice(-2000).filter(row => row && typeof row === 'object').map((row, index) => ({
    id: index, timestamp: timestamp(row.timestamp),
    session: typeof row.session_id_hash === 'string' && /^[a-f0-9]{64}$/.test(row.session_id_hash) ? row.session_id_hash : 'unavailable',
    event: ['scan_completed', 'scan_failed', 'tool_started', 'tool_failed', 'tool_denied'].includes(row.event) ? row.event : 'audit_record',
    operation: count(row.operation),
    source: sources[row.source] || 'UNKNOWN', hook: hooks.has(row.hook) ? row.hook : null,
    tool: ['Read', 'Grep', 'Bash', 'Agent', 'MCP tool', 'Other tool'].includes(row.tool) ? row.tool : typeof row.tool === 'string' && row.tool.startsWith('mcp__') ? 'MCP tool' : row.tool ? 'Other tool' : null,
    toolError: row.is_error === true,
    scanned: count(row.scanned_payload_count), detected: count(row.finding_count), masked: count(row.redacted_count),
    failed: row.blocked === true,
    // A failed Mod hook does not prove a provider request was blocked.
    failureStage: row.failure_stage === 'sanitizer' ? 'sanitizer' : row.failure_stage === 'detector' ? 'detector' : null,
    findings: Array.isArray(row.findings) ? row.findings.slice(0, 1000).map(f => ({
      detector: f?.detector === 'CredSweeper' ? 'CredSweeper' : null,
      type: types.has(f?.secret_type) ? f.secret_type : 'UNKNOWN', rule: rule(f?.rule_id),
      payload: count(f?.payload_index), start: count(f?.start), end: count(f?.end),
      unit: f?.offset_unit === 'utf16_code_units' ? 'UTF-16 code units' : null,
      action: f?.action === 'MASK' ? 'MASK' : null,
      placeholder: typeof f?.placeholder === 'string' && /^\[(PASSWORD|API_KEY|TOKEN|PRIVATE_KEY|AWS_KEY|GITHUB_TOKEN|SLACK_TOKEN|JWT|SECRET|CREDENTIAL)_\d{1,9}\]$/.test(f.placeholder) ? f.placeholder : null,
    })) : [],
  }))
}

const guardEndpoints = new Set(['/v1/messages', '/v1/messages/count_tokens', 'UNKNOWN'])
const guardReason = value => typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(value) ? value : null
const latency = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.round(value * 1000) / 1000 : null

export function projectGuardAudit(rows) {
  if (!Array.isArray(rows)) throw new Error('GUARD_AUDIT_UNAVAILABLE')
  return rows.slice(-2000).filter(record => record && typeof record === 'object' && !Array.isArray(record)).map((record, index) => {
    const findingCount = count(record.finding_count)
    const auditDecision = record.decision === 'allow' || record.decision === 'block' ? record.decision : null
    const decision = auditDecision === 'block'
      ? 'BLOCKED'
      : auditDecision === 'allow' && findingCount === 0
        ? 'SAFE'
        : 'NOT VERIFIED'
    return {
      id: index,
      scope: 'FINAL GUARD — provider-bound verification',
      session: typeof record.session_hash === 'string' && /^[a-f0-9]{64}$/.test(record.session_hash) ? record.session_hash : 'unavailable',
      timestamp: timestamp(record.timestamp),
      endpoint: guardEndpoints.has(record.endpoint) ? record.endpoint : 'UNKNOWN',
      bodySize: count(record.body_size),
      findingCount,
      findingTypes: Array.isArray(record.finding_types) ? [...new Set(record.finding_types.filter(value => types.has(value)))].sort() : [],
      decision,
      reason: guardReason(record.reason),
      scanLatencyMs: latency(record.scan_latency_ms),
      upstreamStatus: Number.isInteger(record.upstream_status) && record.upstream_status >= 100 && record.upstream_status <= 599 ? record.upstream_status : null,
    }
  })
}
