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
// session.append doors whose content no earlier hook sanitized. `command` is `!` shell mode:
// its <bash-input>/<bash-stdout> rows skip prompt.submit and tool.call entirely.
const UNSANITIZED_DOORS = new Set(['command', 'tool-message', 'delivery', 'hook-context', 'note', 'notice'])
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

// One placeholder per value: keyed by value_hash alone, so a value keeps the placeholder (and the
// type) it got first even when a later finding names another type. The ensemble names a value by
// its context: one key is SECRET after `"secret": ` and API_KEY after `API_KEY=`, and two numbers
// for one key hid from the model that the files share it (metric-task t15).
function placeholder(finding, raw) {
  const key = finding.value_hash
  if (ledger.has(key)) return ledger.get(key)
  const kind = typeName(finding.type)
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
  return remaskPartial(out, counter)
}

// Partial re-mask. A restored command can print part of a secret (`sed 's/(=.{12}).*/…/'`,
// `cut -c1-12`, `head -c 20`), and the full-value pass above misses it: in the metric-task t09 run,
// 12 of a 16-character password went out. So a run of at least partMinLength(raw) consecutive
// characters of a known raw value is masked too, as [TYPE_N_PART].
//
// The minimum is max(8, half the value's length), rounded up:
// - 8: shorter runs are shared by ordinary words and identifiers (`deploy-`, `report`), and give
//   little of a value away. A value shorter than 8 characters is masked only whole.
// - half: long values (JWTs, keys) have long common prefixes and fixed headers (a JWT header such as
//   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` is 36 characters), and less than half of a long random
//   value leaves the rest out of reach.
// The marker ends in `_PART]`, outside PLACEHOLDER_PATTERN, so tool.call never restores a part to
// the full value.
const PART_MIN = 8
const partMinLength = raw => Math.max(PART_MIN, Math.ceil(raw.length / 2))
const partMarker = placeholder => `${placeholder.slice(0, -1)}_PART]`

// Every PART_MIN-character window of every raw value long enough to have parts, so one pass over a
// text finds them all, however many values there are. The vault only grows: rebuilt on a new value.
let partIndex = { size: -1, windows: new Map() }

function partWindows() {
  if (partIndex.size === reverseVault.size) return partIndex.windows
  const windows = new Map()
  for (const raw of reverseVault.keys()) {
    if (raw.length < PART_MIN) continue
    for (let offset = 0; offset + PART_MIN <= raw.length; offset++) {
      const window = raw.slice(offset, offset + PART_MIN)
      const hits = windows.get(window)
      if (hits) hits.push({ raw, offset })
      else windows.set(window, [{ raw, offset }])
    }
  }
  partIndex = { size: reverseVault.size, windows }
  return windows
}

function remaskPartial(text, counter) {
  if (text.length < PART_MIN || !reverseVault.size) return text
  const windows = partWindows()
  if (!windows.size) return text
  const spans = []
  for (let start = 0; start + PART_MIN <= text.length; start++) {
    const hits = windows.get(text.slice(start, start + PART_MIN))
    if (!hits) continue
    // A run starting here, extended as far as it keeps matching; the longest one that is long
    // enough for its value wins. Scanning left to right, the first hit of a run is its start.
    let best = null
    for (const { raw, offset } of hits) {
      let end = start + PART_MIN
      let at = offset + PART_MIN
      while (end < text.length && at < raw.length && text[end] === raw[at]) { end++; at++ }
      if (end - start >= partMinLength(raw) && (!best || end > best.end)) best = { start, end, raw }
    }
    if (!best) continue
    spans.push(best)
    start = best.end - 1
  }
  if (!spans.length) return text
  counter.count += spans.length
  let out = text
  for (const { start, end, raw } of spans.reverse()) out = out.slice(0, start) + partMarker(reverseVault.get(raw)) + out.slice(end)
  return out
}

// Checks every span first, then numbers top to bottom (so the first value in a .env is _1), then
// replaces from the end so earlier offsets stay valid.
function redactText(text, findings) {
  const ordered = [...findings].sort((a, b) => b.start - a.start || b.end - a.end)
  let previousStart = text.length + 1
  for (const finding of ordered) {
    if (finding.offset_unit !== 'utf16_code_units') throw new Error('PromptGuard detector offset unit mismatch')
    if (!Number.isInteger(finding.start) || !Number.isInteger(finding.end) || finding.start < 0 || finding.end > text.length || finding.start >= finding.end) throw new Error('PromptGuard detector invalid span')
    if (finding.end > previousStart) throw new Error('PromptGuard detector overlapping normalized spans')
    previousStart = finding.start
  }
  const placeholders = new Map()
  for (const finding of [...ordered].reverse()) placeholders.set(finding, placeholder(finding, text.slice(finding.start, finding.end)))
  let out = text
  for (const finding of ordered) out = out.slice(0, finding.start) + placeholders.get(finding) + out.slice(finding.end)
  return out
}

// The pgdetector MCP server connects in the background after the session starts, and until then
// $.mcp.call throws. Failing then would block the first prompt for no reason, so wait for the first
// connection (bounded); after that, a throw fails at once. Either way a failure blocks (BLOCKED_TEXT).
//
// The wait is one window for the whole session, from the first call, not one per hook: a denied
// permission also throws, and per-hook windows queued behind one another (detectorQueue) outran
// the hook budget (HookBudget.ms, 10s, which counts these timers). Claude Code 2.1.291 then unloaded
// the whole Mod as "a runaway plugin" for ignoring next.signal, and later text went out unscanned.
// So every wait also stops on the hook's signal; the hook's .catch then blocks in its place. A
// PG_MOD_CONNECT_WAIT_MS past the budget is cut there.
const CONNECT_RETRY_MS = 250
let detectorConnected = false
let connectDeadline = null

class DetectorAbandoned extends Error {}

function pause(ms, signal) {
  return new Promise(resolve => {
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
  })
}

// Settles with `promise`, or rejects as soon as `signal` aborts.
function untilAborted(promise, signal) {
  if (!signal) return promise
  if (signal.aborted) return Promise.reject(new DetectorAbandoned('PromptGuard detector call abandoned'))
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new DetectorAbandoned('PromptGuard detector call abandoned'))
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort))
  })
}

async function callDetector($, entries, signal) {
  if (connectDeadline === null) {
    const wait = Number(await $.env.get('PG_MOD_CONNECT_WAIT_MS') ?? 15000)
    connectDeadline = Date.now() + (Number.isFinite(wait) && wait >= 0 ? wait : 15000)
  }
  for (;;) {
    if (signal?.aborted) throw new DetectorAbandoned('PromptGuard detector call abandoned')
    try {
      const response = await $.mcp.call('pgdetector', 'scan_batch', { items: entries })
      detectorConnected = true
      return response
    } catch (error) {
      if (detectorConnected || Date.now() >= connectDeadline) throw error
      await pause(CONNECT_RETRY_MS, signal)
    }
  }
}

async function scanBatch($, entries, signal) {
  if (!entries.length) return { items: [], latencyMs: 0 }
  const started = Date.now()
  const operation = detectorQueue.then(() => callDetector($, entries, signal))
  detectorQueue = operation.catch(() => {})
  const response = await untilAborted(operation, signal)
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

async function sanitize($, value, source, signal) {
  const entries = collectStrings(value, source)
  const scanned = await scanBatch($, entries, signal)
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

// Fail closed. The engine skips a hook that throws, fails its budget or answers a wrong shape, and
// runs what is beneath it with the ORIGINAL input, so a throw here would send raw text to the model
// (Claude Code 2.1.291 types: EngineEventOf, "a guard fails open unless its registration carries a
// `.catch`"). So a failed scan never throws: each text it could not check becomes BLOCKED_TEXT and
// the hook answers normally. BLOCKED_TEXT is not placeholder-shaped, so tool.call never restores it.
const BLOCKED_TEXT = '[PROMPTGUARD_BLOCKED: detector failure]'
const blockStrings = value => mapStrings(value, () => BLOCKED_TEXT)

// { ok: true, value } with the sanitized value, or { ok: false } after a raw-free failure audit row.
// `signal` is the hook's next.signal; it never reaches the audit row.
async function trySanitize($, value, source, { signal, ...extra } = {}) {
  try {
    const result = await sanitize($, value, source, signal)
    await appendAudit($, source, result, extra)
    return { ok: true, value: result.value }
  } catch (error) {
    try { await appendFailureAudit($, source, error, extra) } catch { /* audit is best effort; blocking is not */ }
    return { ok: false }
  }
}

// For values that hold only model-bound text (a string, or strings in arrays): every string of a
// value that failed to scan becomes BLOCKED_TEXT. Pass `block` for values with non-text fields.
async function sanitizeAndAudit($, value, source, extra = {}, block = blockStrings) {
  const scanned = await trySanitize($, value, source, extra)
  return scanned.ok ? scanned.value : block(value)
}

const blockInstructionFiles = files => files?.map(file => ({ ...file, content: BLOCKED_TEXT }))

function blockRow(e) {
  const content = e.message?.content
  if (!UNSANITIZED_DOORS.has(e.door) || !Array.isArray(content)) return e
  return { ...e, message: { ...e.message, content: rebuildRow(content, blockStrings(rowTexts(content))) } }
}

// Backstops for a hook that fails anyway (a bug, an overrun HookBudget): the engine runs the
// registration's `.catch` in its place, and its answer stands. Each refuses what the hook guards.
// `next` there replays a call the hook already made; it never runs beneath twice. The engine reads
// `.catch(...)` statically too: its handler must be a function literal or a function's name.
function catchPromptSubmit($, e, next) { return next.called ? next(e) : next({ ...e, text: BLOCKED_TEXT, context: blockStrings(e.context) }) }
function catchPromptContext($, e, next) { return next.called ? next(e) : next({ ...e, blocks: e.blocks.map(block => ({ ...block, text: BLOCKED_TEXT })), instructionFiles: blockInstructionFiles(e.instructionFiles) }) }
function catchPromptSection($, e, next) { return next.called || e.text === null ? next(e) : next({ ...e, text: BLOCKED_TEXT }) }
// Sanitizes on the way up, so the replayed result is still raw: block every section's text.
async function catchPromptCompose($, e, next) {
  const result = await next(e)
  return { ...result, sections: result.sections.map(section => ({ ...section, text: BLOCKED_TEXT })) }
}
function catchPromptAttachment($, e, next) { return next.called ? next(e) : next({ ...e, text: BLOCKED_TEXT }) }
function catchSkillPrompt($, e, next) { return next.called ? next(e) : next({ ...e, text: BLOCKED_TEXT }) }
function catchAgentSpawn($, e, next) { return next.called ? next(e) : next({ ...e, prompt: BLOCKED_TEXT, description: BLOCKED_TEXT }) }
// Unscanned output never goes back, and a call the hook did not get to start never runs.
function catchToolCall($, e, next) { return e.tool === 'mcp__pgdetector__scan_batch' ? next(e) : { deny: BLOCKED_TEXT } }
function catchSessionCompact() { return { skip: BLOCKED_TEXT } }
function catchSessionAppend($, e, next) { return next.called ? next(e) : next(blockRow(e)) }
// Ends the response here: the rest of the stream is unscanned.
async function* catchTurnStep() {}

function auditTool(tool) {
  if (['Read', 'Grep', 'Bash', 'Agent'].includes(tool)) return tool
  if (typeof tool === 'string' && tool.startsWith('mcp__')) return 'MCP tool'
  return tool ? 'Other tool' : undefined
}

// Only text blocks and a tool_result's text are rewritable; every other block passes through.
function rowTexts(content) {
  return content.map(block => {
    if (block?.type === 'text' && typeof block.text === 'string') return block.text
    if (block?.type === 'tool_result' && typeof block.content === 'string') return block.content
    if (block?.type === 'tool_result' && Array.isArray(block.content)) return block.content.map(item => item?.type === 'text' && typeof item.text === 'string' ? item.text : null)
    return null
  })
}

function rebuildRow(content, texts) {
  return content.map((block, index) => {
    if (block?.type === 'text' && typeof block.text === 'string') return { ...block, text: texts[index] }
    if (block?.type === 'tool_result' && typeof block.content === 'string') return { ...block, content: texts[index] }
    if (block?.type === 'tool_result' && Array.isArray(block.content)) return { ...block, content: block.content.map((item, i) => texts[index][i] === null ? item : { ...item, text: texts[index][i] }) }
    return block
  })
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
  // Each registration carries its `.catch` backstop (catch* above). The engine reads `on("<event>", hook)`
  // statically, so every call keeps a literal event name.
  on('prompt.submit', async ($, e, next) => {
    if (await $.env.get('PG_MOD_FAILURE_MODE') === 'throw') throw new Error('synthetic Mod failure')
    const text = await sanitizeAndAudit($, e.text, 'user_prompt', { signal: next.signal, hook: 'prompt.submit' })
    const context = await sanitizeAndAudit($, e.context, 'history', { signal: next.signal, hook: 'prompt.submit' })
    return next({ ...e, text, context })
  }).catch(catchPromptSubmit)

  on('prompt.context', async ($, e, next) => {
    const blocks = []
    for (const block of e.blocks) blocks.push({ ...block, text: await sanitizeAndAudit($, block.text, 'claude_md', { signal: next.signal, hook: 'prompt.context' }) })
    // path and kind are scanned too, but on a failure only content is blocked: kind is an enum.
    return next({ ...e, blocks, instructionFiles: (await sanitizeAndAudit($, e.instructionFiles, 'claude_md', { signal: next.signal, hook: 'prompt.context' }, blockInstructionFiles)) })
  }).catch(catchPromptContext)

  on('prompt.section', async ($, e, next) => e.text === null ? next(e) : next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { signal: next.signal, hook: 'prompt.section', name: e.name }) })).catch(catchPromptSection)

  on('prompt.compose', async ($, e, next) => {
    const result = await next(e)
    const sections = []
    for (const section of result.sections) sections.push({ ...section, text: await sanitizeAndAudit($, section.text, 'automatic_context', { signal: next.signal, hook: 'prompt.compose' }) })
    return { ...result, sections }
  }).catch(catchPromptCompose)

  on('prompt.attachment', async ($, e, next) => next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { signal: next.signal, hook: 'prompt.attachment', type: e.type }) })).catch(catchPromptAttachment)
  on('skill.prompt', async ($, e, next) => next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { signal: next.signal, hook: 'skill.prompt', skill: e.skill }) })).catch(catchSkillPrompt)
  on('agent.spawn', async ($, e, next) => next({ ...e, prompt: await sanitizeAndAudit($, e.prompt, 'subagent', { signal: next.signal, hook: 'agent.spawn' }), description: (await sanitizeAndAudit($, e.description, 'subagent', { signal: next.signal, hook: 'agent.spawn' })) })).catch(catchAgentSpawn)

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
    // A tool result is structured per tool, so a failed scan denies it whole: the model gets
    // BLOCKED_TEXT as the tool's answer. The tool already ran; only its output is withheld.
    const sanitizedResult = await trySanitize($, result.result, source, { ...extra, signal: next.signal })
    const sanitizedText = result.text === undefined ? { ok: true, value: undefined } : await trySanitize($, result.text, source, { ...extra, signal: next.signal, hook: 'tool.call.text' })
    const sanitizedContext = await trySanitize($, result.context, source, { ...extra, signal: next.signal, hook: 'tool.call.context' })
    if (!sanitizedResult.ok || !sanitizedText.ok || !sanitizedContext.ok) return { deny: BLOCKED_TEXT }
    if (result.isError === true) return { deny: String(sanitizedText.value ?? sanitizedResult.value ?? 'Tool call failed') }
    return { ...result, result: sanitizedResult.value, text: sanitizedText.value, context: sanitizedContext.value }
  }).catch(catchToolCall)

  // A failed scan skips the compaction: the conversation stays as it is (its rows were sanitized as
  // they were appended), and neither the compacting model nor the new history gets unscanned text.
  on('session.compact', async ($, e, next) => {
    const strip = messages => messages.map(message => { const { handle, ...built } = message; return built })
    const messages = await trySanitize($, e.messages, 'history', { signal: next.signal, hook: 'session.compact' })
    const instructions = e.instructions === undefined ? { ok: true, value: undefined } : await trySanitize($, e.instructions, 'history', { signal: next.signal, hook: 'session.compact', trigger: e.trigger })
    if (!messages.ok || !instructions.ok) return { skip: BLOCKED_TEXT }
    const result = await next({ ...e, messages: strip(messages.value), instructions: instructions.value })
    if (result.skip !== undefined) return result
    const sanitized = await trySanitize($, result.messages, 'history', { signal: next.signal, hook: 'session.compact' })
    if (!sanitized.ok) return { skip: BLOCKED_TEXT }
    return { ...result, messages: strip(sanitized.value) }
  }).catch(catchSessionCompact)

  // Rewrites the row before it is stored, so neither the model nor the transcript file sees raw values.
  on('session.append', async ($, e, next) => {
    const content = e.message?.content
    if (!UNSANITIZED_DOORS.has(e.door) || !Array.isArray(content)) return next(e)
    const texts = rowTexts(content)
    if (!texts.some(text => text !== null)) return next(e)
    const source = e.door === 'command' ? 'user_command' : 'history'
    const sanitized = await sanitizeAndAudit($, texts, source, { signal: next.signal, hook: 'session.append' })
    return next({ ...e, message: { ...e.message, content: rebuildRow(content, sanitized) } })
  }).catch(catchSessionAppend)

  on('turn.step', async function* ($, e, next) {
    const agentInputs = new Set()
    for await (const chunk of next(e)) {
      if (chunk.kind === 'text') yield { ...chunk, text: await sanitizeAndAudit($, chunk.text, 'history', { signal: next.signal, hook: 'turn.step', agent_id: e.agentId }) }
      else if (chunk.kind === 'tool') { if (chunk.name === 'Agent') agentInputs.add(chunk.index); yield chunk }
      // A blocked fragment may leave the Agent input unparsable; the call then fails, raw-free.
      else if (chunk.kind === 'input' && agentInputs.has(chunk.index)) yield { ...chunk, json: await sanitizeAndAudit($, chunk.json, 'subagent', { signal: next.signal, hook: 'turn.step.agent-input', agent_id: e.agentId }) }
      else yield chunk
    }
  }).catch(catchTurnStep)
}
