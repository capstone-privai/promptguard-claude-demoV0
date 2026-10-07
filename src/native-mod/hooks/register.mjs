const ledger = new Map()
const counters = new Map()
const auditRows = []
let detectorQueue = Promise.resolve()
let auditQueue = Promise.resolve()

function collectStrings(value, source, entries = []) {
  if (typeof value === 'string') entries.push({ id: entries.length, text: value, source })
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, source, entries)
  else if (value && typeof value === 'object') for (const item of Object.values(value)) collectStrings(item, source, entries)
  return entries
}

function typeName(value) {
  return String(value || 'CREDENTIAL').toUpperCase().replace(/[^A-Z0-9_]/g, '_') || 'CREDENTIAL'
}

function placeholder(finding) {
  const kind = typeName(finding.type)
  const key = `${kind}:${finding.value_hash}`
  if (ledger.has(key)) return ledger.get(key)
  const next = (counters.get(kind) || 0) + 1
  counters.set(kind, next)
  const value = `[${kind}_${next}]`
  ledger.set(key, value)
  return value
}

function redactText(text, findings) {
  const ordered = [...findings].sort((a, b) => b.start - a.start || b.end - a.end)
  let out = text
  let previousStart = text.length + 1
  for (const finding of ordered) {
    if (finding.offset_unit !== 'utf16_code_units') throw new Error('PromptGuard detector offset unit mismatch')
    if (!Number.isInteger(finding.start) || !Number.isInteger(finding.end) || finding.start < 0 || finding.end > text.length || finding.start >= finding.end) throw new Error('PromptGuard detector invalid span')
    if (finding.end > previousStart) throw new Error('PromptGuard detector overlapping normalized spans')
    out = out.slice(0, finding.start) + placeholder(finding) + out.slice(finding.end)
    previousStart = finding.start
  }
  return out
}

async function scanBatch($, entries) {
  if (!entries.length) return { items: [], latencyMs: 0 }
  const started = Date.now()
  const operation = detectorQueue.then(() => $.mcp.call('pgdetector', 'scan_batch', { items: entries }))
  detectorQueue = operation.catch(() => {})
  const response = await operation
  if (!response || response.isError === true || !Array.isArray(response.content)) throw new Error('PromptGuard detector bridge failure')
  const text = response.content.find(block => block?.type === 'text')?.text
  let value
  try { value = JSON.parse(text) } catch { throw new Error('PromptGuard detector malformed response') }
  if (!value || value.ok !== true || !Array.isArray(value.items) || value.items.length !== entries.length) throw new Error('PromptGuard detector malformed response')
  for (const item of value.items) {
    if (item.ok !== true || !Array.isArray(item.findings) || (Array.isArray(item.errors) && item.errors.length)) throw new Error('PromptGuard detector unsafe result')
  }
  return { items: value.items, latencyMs: Date.now() - started }
}

async function appendFailureAudit($, source, error) {
  const path = await $.env.get('PG_MOD_AUDIT')
  if (!path) return
  const row = {
    timestamp: new Date().toISOString(),
    session_id_hash: await $.env.get('PG_SESSION_HASH') || 'unavailable',
    source,
    finding_count: 0,
    type_counts: {},
    redacted_count: 0,
    blocked: true,
    reason: String(error?.message || 'MOD_FAILURE').slice(0, 160),
    latency_ms: 0,
  }
  auditQueue = auditQueue.then(() => $.fs.write(path, JSON.stringify([...auditRows, row], null, 2))).catch(() => {})
  await auditQueue
}

function rebuild(value, byId, cursor = { value: 0 }) {
  if (typeof value === 'string') return redactText(value, byId.get(cursor.value++) || [])
  if (Array.isArray(value)) return value.map(item => rebuild(item, byId, cursor))
  if (value && typeof value === 'object') {
    const out = {}
    for (const [key, item] of Object.entries(value)) out[key] = rebuild(item, byId, cursor)
    return out
  }
  return value
}

async function sanitize($, value, source) {
  const entries = collectStrings(value, source)
  const scanned = await scanBatch($, entries)
  const byId = new Map(scanned.items.map(item => [item.id, item.findings]))
  const findings = scanned.items.flatMap(item => item.findings)
  const types = {}
  for (const finding of findings) types[finding.type] = (types[finding.type] || 0) + 1
  return { value: rebuild(value, byId), findingCount: findings.length, types, latencyMs: scanned.latencyMs }
}

async function appendAudit($, source, result, extra = {}) {
  const path = await $.env.get('PG_MOD_AUDIT')
  if (!path) return
  auditRows.push({
    timestamp: new Date().toISOString(),
    session_id_hash: await $.env.get('PG_SESSION_HASH') || 'unavailable',
    source,
    finding_count: result.findingCount,
    type_counts: result.types,
    redacted_count: result.findingCount,
    blocked: false,
    reason: null,
    latency_ms: result.latencyMs,
    ...extra,
  })
  auditQueue = auditQueue.then(() => $.fs.write(path, JSON.stringify(auditRows, null, 2))).catch(() => {})
  await auditQueue
}

async function sanitizeAndAudit($, value, source, extra = {}) {
  try {
    const result = await sanitize($, value, source)
    await appendAudit($, source, result, extra)
    return result.value
  } catch (error) {
    await appendFailureAudit($, source, error)
    throw error
  }
}

function toolSource(e, isError) {
  if (e.tool === 'Read') return 'read_result'
  if (e.tool === 'Grep') return 'grep'
  if (e.tool === 'Bash') return isError ? 'bash_error' : 'bash_stdout'
  if (e.tool === 'Agent') return 'subagent'
  if (String(e.tool).startsWith('mcp__')) return 'mcp'
  return 'tool_result'
}

export function register(on) {
  on('prompt.submit', async ($, e, next) => {
    if (await $.env.get('PG_MOD_FAILURE_MODE') === 'throw') throw new Error('synthetic Mod failure')
    const text = await sanitizeAndAudit($, e.text, 'user_prompt', { hook: 'prompt.submit' })
    const context = (await sanitize($, e.context, 'history')).value
    return next({ ...e, text, context })
  })

  on('prompt.context', async ($, e, next) => {
    const blocks = []
    for (const block of e.blocks) blocks.push({ ...block, text: await sanitizeAndAudit($, block.text, 'claude_md', { hook: 'prompt.context' }) })
    return next({ ...e, blocks, instructionFiles: (await sanitize($, e.instructionFiles, 'claude_md')).value })
  })

  on('prompt.section', async ($, e, next) => e.text === null ? next(e) : next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { hook: 'prompt.section', name: e.name }) }))

  on('prompt.compose', async ($, e, next) => {
    const result = await next(e)
    const sections = []
    for (const section of result.sections) sections.push({ ...section, text: await sanitizeAndAudit($, section.text, 'automatic_context', { hook: 'prompt.compose' }) })
    return { ...result, sections }
  })

  on('prompt.attachment', async ($, e, next) => next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { hook: 'prompt.attachment', type: e.type }) }))
  on('skill.prompt', async ($, e, next) => next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { hook: 'skill.prompt', skill: e.skill }) }))
  on('agent.spawn', async ($, e, next) => next({ ...e, prompt: await sanitizeAndAudit($, e.prompt, 'subagent', { hook: 'agent.spawn' }), description: (await sanitize($, e.description, 'subagent')).value }))

  on('tool.call', async ($, e, next) => {
    if (e.tool === 'mcp__pgdetector__scan_batch') return next(e)
    const result = await next(e)
    if (result.deny !== undefined) return result
    const source = toolSource(e, result.isError === true)
    const sanitizedResult = await sanitize($, result.result, source)
    const sanitizedText = result.text === undefined ? undefined : (await sanitize($, result.text, source)).value
    const sanitizedContext = (await sanitize($, result.context, source)).value
    await appendAudit($, source, sanitizedResult, { hook: 'tool.call', tool: e.tool, tool_use_id: e.tool_use_id, is_error: result.isError === true })
    if (result.isError === true) return { deny: String(sanitizedText ?? sanitizedResult.value ?? 'Tool call failed') }
    return { ...result, result: sanitizedResult.value, text: sanitizedText, context: sanitizedContext }
  })

  on('session.compact', async ($, e, next) => {
    const messages = (await sanitize($, e.messages, 'history')).value.map(message => { const { handle, ...built } = message; return built })
    const instructions = e.instructions === undefined ? undefined : await sanitizeAndAudit($, e.instructions, 'history', { hook: 'session.compact', trigger: e.trigger })
    const result = await next({ ...e, messages, instructions })
    if (result.skip !== undefined) return result
    const sanitized = (await sanitize($, result.messages, 'history')).value.map(message => { const { handle, ...built } = message; return built })
    return { ...result, messages: sanitized }
  })

  on('turn.step', async function* ($, e, next) {
    const agentInputs = new Set()
    for await (const chunk of next(e)) {
      if (chunk.kind === 'text') yield { ...chunk, text: await sanitizeAndAudit($, chunk.text, 'history', { hook: 'turn.step', agent_id: e.agentId }) }
      else if (chunk.kind === 'tool') { if (chunk.name === 'Agent') agentInputs.add(chunk.index); yield chunk }
      else if (chunk.kind === 'input' && agentInputs.has(chunk.index)) yield { ...chunk, json: await sanitizeAndAudit($, chunk.json, 'subagent', { hook: 'turn.step.agent-input', agent_id: e.agentId }) }
      else yield chunk
    }
  })
}
