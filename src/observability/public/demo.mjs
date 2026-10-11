// UI-only, non-credential placeholders. Never merged with audit events.
export function demo(scenario = 'multiple') {
  const base = { session: 'DEMO SESSION', event: 'scan_completed', hook: 'prompt.submit', tool: null, toolError: false, scanned: 1, detected: 0, masked: 0, failed: false, failureStage: null, findings: [] }
  const finding = { detector: 'CredSweeper', type: 'PASSWORD', rule: 'Password', payload: 0, start: 31, end: 48, unit: 'UTF-16 code units', action: 'MASK', placeholder: '[PASSWORD_1]' }
  const rows = [{ ...base, source: 'USER_PROMPT' }]
  if (['prompt', 'multiple', 'missing'].includes(scenario)) Object.assign(rows[0], { detected: 1, masked: 1, findings: [{ ...finding, type: 'API_KEY', placeholder: '[API_KEY_1]', rule: scenario === 'missing' ? null : 'API Key', detector: scenario === 'missing' ? null : 'CredSweeper', unit: scenario === 'missing' ? null : finding.unit }] })
  if (['file', 'tool', 'multiple'].includes(scenario)) rows.push({ ...base, source: scenario === 'tool' ? 'TOOL_OUTPUT' : 'FILE_READ', hook: 'tool.call', tool: scenario === 'tool' ? 'Bash' : 'Read', detected: 1, masked: 1, findings: [finding] })
  if (scenario === 'multiple') rows.push({ ...base, source: 'FILE_READ', hook: 'tool.call', tool: 'Read', detected: 1, masked: 1, findings: [{ ...finding, placeholder: '[PASSWORD_2]' }] })
  if (['detector-error', 'sanitizer-error'].includes(scenario)) rows.push({ ...base, source: 'TOOL_OUTPUT', hook: 'tool.call', tool: 'Bash', event: 'scan_failed', failed: true, scanned: null, detected: null, masked: null, failureStage: scenario === 'detector-error' ? 'detector' : 'sanitizer' })
  const blocked = ['blocked', 'detector-error', 'sanitizer-error'].includes(scenario)
  return { mode: 'DEMO', events: rows.map((e, id) => ({ ...e, id, timestamp: `2026-10-11T00:00:0${id}.000Z` })), guard: { scope: 'DEMO — synthetic UI scenario', decision: blocked ? 'BLOCKED' : 'SAFE', remaining: blocked ? null : 0, scanned: blocked ? null : rows.reduce((n, e) => n + e.scanned, 0), placeholders: rows.reduce((n, e) => n + (e.masked || 0), 0), reason: blocked ? 'Synthetic failure scenario' : null } }
}
