const ledger = new Map()
const counters = new Map()
// placeholder -> raw value. Memory only: never audited, persisted, or sent to the model.
const vault = new Map()
// raw value -> placeholder, for re-masking raw values that come back from restored tool runs.
const reverseVault = new Map()
const PLACEHOLDER_PATTERN = /\[[A-Z0-9_]+_\d+\]/g
// Tools that execute locally. Model-bound tools (Agent, WebFetch, ...) never get raw values.
const RESTORE_TOOLS = new Set(['Bash', 'PowerShell', 'Edit', 'MultiEdit', 'Write', 'NotebookEdit', 'Grep'])
const TOOL_META_KEYS = new Set(['tool', 'tool_use_id'])
const auditRows = []
let detectorQueue = Promise.resolve()
let auditQueue = Promise.resolve()
let toolOperation = 0

function collectStrings(value, source, entries = []) {
  if (typeof value === 'string') entries.push({ id: entries.length, text: value, source })
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, source, entries)
  else if (value && typeof value === 'object') for (const item of Object.values(value)) collectStrings(item, source, entries)
  return entries
}

function typeName(value) {
  return String(value || 'CREDENTIAL').toUpperCase().replace(/[^A-Z0-9_]/g, '_') || 'CREDENTIAL'
}

function placeholder(finding, raw) {
  const kind = typeName(finding.type)
  const key = `${kind}:${finding.value_hash}`
  if (ledger.has(key)) return ledger.get(key)
  const next = (counters.get(kind) || 0) + 1
  counters.set(kind, next)
  const value = `[${kind}_${next}]`
  ledger.set(key, value)
  vault.set(value, raw)
  if (!reverseVault.has(raw)) reverseVault.set(raw, value)
  return value
}

function mapStrings(value, fn) {
  if (typeof value === 'string') return fn(value)
  if (Array.isArray(value)) return value.map(item => mapStrings(item, fn))
  if (value && typeof value === 'object') {
    const out = {}
    for (const [key, item] of Object.entries(value)) out[key] = mapStrings(item, fn)
    return out
  }
  return value
}

// Swaps placeholders the model wrote back to their raw values. Unknown placeholders stay as is.
function restoreText(text, counter) {
  return text.replace(PLACEHOLDER_PATTERN, match => {
    if (!vault.has(match)) return match
    counter.count++
    return vault.get(match)
  })
}

function restoreToolInput(e) {
  const counter = { count: 0 }
  const input = {}
  for (const [key, item] of Object.entries(e)) input[key] = TOOL_META_KEYS.has(key) ? item : mapStrings(item, text => restoreText(text, counter))
  return { input, restoredCount: counter.count }
}

// Replaces known raw values with their placeholders, even where the detector would miss them
// (e.g. a restored password echoed alone on a line). Longest first so substrings never win.
function remaskText(text, counter) {
  if (!reverseVault.size) return text
  let out = text
  for (const raw of [...reverseVault.keys()].sort((a, b) => b.length - a.length)) {
    if (!out.includes(raw)) continue
    const parts = out.split(raw)
    counter.count += parts.length - 1
    out = parts.join(reverseVault.get(raw))
  }
  return out
}

function redactText(text, findings) {
  const ordered = [...findings].sort((a, b) => b.start - a.start || b.end - a.end)
  let out = text
  let previousStart = text.length + 1
  for (const finding of ordered) {
    if (finding.offset_unit !== 'utf16_code_units') throw new Error('PromptGuard detector offset unit mismatch')
    if (!Number.isInteger(finding.start) || !Number.isInteger(finding.end) || finding.start < 0 || finding.end > text.length || finding.start >= finding.end) throw new Error('PromptGuard detector invalid span')
    if (finding.end > previousStart) throw new Error('PromptGuard detector overlapping normalized spans')
    out = out.slice(0, finding.start) + placeholder(finding, text.slice(finding.start, finding.end)) + out.slice(finding.end)
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

async function appendFailureAudit($, source, error, extra = {}) {
  const path = await $.env.get('PG_MOD_AUDIT')
  if (!path) return
  const row = {
    timestamp: new Date().toISOString(),
    session_id_hash: await $.env.get('PG_SESSION_HASH') || 'unavailable',
    source,
    finding_count: null,
    type_counts: {},
    redacted_count: null,
    blocked: true,
    reason: error?.pgStage === 'sanitizer' ? 'SANITIZER_FAILURE' : 'DETECTOR_FAILURE',
    event: 'scan_failed',
    hook: extra.hook, tool: auditTool(extra.tool), operation: extra.operation,
    failure_stage: error?.pgStage === 'sanitizer' ? 'sanitizer' : 'detector',
    latency_ms: 0,
  }
  auditRows.push(row)
  auditQueue = auditQueue.then(() => $.fs.write(path, JSON.stringify(auditRows, null, 2))).catch(() => {})
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
  let sanitized
  try { sanitized = rebuild(value, byId) }
  catch (error) { error.pgStage = 'sanitizer'; throw error }
  // After the detector pass, so remasked_count counts only raw values the detector missed.
  const remasked = { count: 0 }
  sanitized = mapStrings(sanitized, text => remaskText(text, remasked))
  // Never retain text, hashes, object keys, or caller-provided error messages in audit.
  const details = scanned.items.flatMap(item => item.findings.map(finding => ({
    detector: item.detector === 'CredSweeper' ? 'CredSweeper' : undefined,
    secret_type: typeName(finding.type), rule_id: finding.rule_id,
    payload_index: item.id, start: finding.start, end: finding.end,
    offset_unit: finding.offset_unit, action: 'MASK', placeholder: placeholder(finding),
  })))
  return { value: sanitized, findingCount: findings.length, types, latencyMs: scanned.latencyMs,
    scannedPayloadCount: entries.length, findings: details, remaskedCount: remasked.count }
}

async function appendAudit($, source, result, extra = {}) {
  const path = await $.env.get('PG_MOD_AUDIT')
  if (!path) return
  auditRows.push({
    timestamp: new Date().toISOString(),
    session_id_hash: await $.env.get('PG_SESSION_HASH') || 'unavailable',
    source,
    event: extra.event || 'scan_completed',
    operation: extra.operation,
    scanned_payload_count: result.scannedPayloadCount,
    findings: result.findings,
    finding_count: result.findingCount,
    type_counts: result.types,
    redacted_count: result.findingCount === null ? null : result.findingCount + (result.remaskedCount || 0),
    remasked_count: result.remaskedCount || 0,
    restored_count: extra.restored_count,
    blocked: false,
    reason: null,
    latency_ms: result.latencyMs,
    hook: extra.hook,
    tool: auditTool(extra.tool),
    is_error: extra.is_error,
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
    await appendFailureAudit($, source, error, extra)
    throw new Error(error?.pgStage === 'sanitizer' ? 'PromptGuard sanitizer failure' : 'PromptGuard detector failure')
  }
}

function auditTool(tool) {
  if (['Read', 'Grep', 'Bash', 'Agent'].includes(tool)) return tool
  if (typeof tool === 'string' && tool.startsWith('mcp__')) return 'MCP tool'
  return tool ? 'Other tool' : undefined
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
    const context = await sanitizeAndAudit($, e.context, 'history', { hook: 'prompt.submit' })
    return next({ ...e, text, context })
  })

  on('prompt.context', async ($, e, next) => {
    const blocks = []
    for (const block of e.blocks) blocks.push({ ...block, text: await sanitizeAndAudit($, block.text, 'claude_md', { hook: 'prompt.context' }) })
    return next({ ...e, blocks, instructionFiles: (await sanitizeAndAudit($, e.instructionFiles, 'claude_md', { hook: 'prompt.context' })) })
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
  on('agent.spawn', async ($, e, next) => next({ ...e, prompt: await sanitizeAndAudit($, e.prompt, 'subagent', { hook: 'agent.spawn' }), description: (await sanitizeAndAudit($, e.description, 'subagent', { hook: 'agent.spawn' })) }))

  on('tool.call', async ($, e, next) => {
    if (e.tool === 'mcp__pgdetector__scan_batch') return next(e)
    const operation = ++toolOperation
    const restoreEnabled = RESTORE_TOOLS.has(e.tool) && await $.env.get('PG_RESTORE_PLACEHOLDERS') !== 'off'
    const { input, restoredCount } = restoreEnabled ? restoreToolInput(e) : { input: e, restoredCount: 0 }
    const lifecycle = { findingCount: null, types: {}, latencyMs: 0, findings: [] }
    const extra = { hook: 'tool.call', tool: e.tool, operation, restored_count: restoredCount }
    await appendAudit($, toolSource(e, false), lifecycle, { ...extra, event: 'tool_started' })
    let result
    try { result = await next(input) }
    catch {
      await appendAudit($, toolSource(e, false), lifecycle, { ...extra, event: 'tool_failed' })
      throw new Error('PromptGuard tool execution failure')
    }
    if (result.deny !== undefined) {
      await appendAudit($, toolSource(e, false), lifecycle, { ...extra, event: 'tool_denied' })
      const deny = typeof result.deny === 'string' ? remaskText(result.deny, { count: 0 }) : result.deny
      return deny === result.deny ? result : { ...result, deny }
    }
    const source = toolSource(e, result.isError === true)
    extra.is_error = result.isError === true
    const sanitizedResult = { value: await sanitizeAndAudit($, result.result, source, extra) }
    const sanitizedText = result.text === undefined ? undefined : await sanitizeAndAudit($, result.text, source, { ...extra, hook: 'tool.call.text' })
    const sanitizedContext = await sanitizeAndAudit($, result.context, source, { ...extra, hook: 'tool.call.context' })
    if (result.isError === true) return { deny: String(sanitizedText ?? sanitizedResult.value ?? 'Tool call failed') }
    return { ...result, result: sanitizedResult.value, text: sanitizedText, context: sanitizedContext }
  })

  on('session.compact', async ($, e, next) => {
    const messages = (await sanitizeAndAudit($, e.messages, 'history', { hook: 'session.compact' })).map(message => { const { handle, ...built } = message; return built })
    const instructions = e.instructions === undefined ? undefined : await sanitizeAndAudit($, e.instructions, 'history', { hook: 'session.compact', trigger: e.trigger })
    const result = await next({ ...e, messages, instructions })
    if (result.skip !== undefined) return result
    const sanitized = (await sanitizeAndAudit($, result.messages, 'history', { hook: 'session.compact' })).map(message => { const { handle, ...built } = message; return built })
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
