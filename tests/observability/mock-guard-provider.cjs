// Legacy validation fixture for synthetic observability scenarios. Production
// provider traffic uses src/guard/final-guard.cjs.
const http = require('http')
const fs = require('fs')
const path = require('path')

const port = Number(process.env.PG_GUARD_PORT || 18191)
const scenario = process.env.PG_SCENARIO || 'simple'
const mode = process.env.PG_GUARD_MODE || 'normal'
const evidenceDir = process.env.PG_EVIDENCE_DIR || path.join(process.cwd(), 'evidence')
const workspace = process.env.PG_WORKSPACE || process.cwd()
const maxBody = Number(process.env.PG_GUARD_MAX_BODY || 8 * 1024 * 1024)
const detectorUrl = process.env.PG_DETECTOR_URL || 'http://127.0.0.1:18771'
fs.mkdirSync(evidenceDir, { recursive: true })

let requestIndex = 0
let upstreamRequests = 0

function collectStrings(value, current = '$', items = []) {
  if (typeof value === 'string') items.push({ id: items.length, text: value, source: 'outbound', json_path: current })
  else if (Array.isArray(value)) value.forEach((item, index) => collectStrings(item, `${current}[${index}]`, items))
  else if (value && typeof value === 'object') Object.entries(value).forEach(([key, item]) => collectStrings(item, `${current}.${key}`, items))
  return items
}

function placeholderCount(value) {
  if (typeof value === 'string') return (value.match(/\[(?:PASSWORD|API_KEY|TOKEN|PRIVATE_KEY|AWS_KEY|GITHUB_TOKEN|SLACK_TOKEN|JWT|SECRET|CREDENTIAL)_\d+\]/g) || []).length
  if (Array.isArray(value)) return value.reduce((n, item) => n + placeholderCount(item), 0)
  if (value && typeof value === 'object') return Object.values(value).reduce((n, item) => n + placeholderCount(item), 0)
  return 0
}

async function inspect(value) {
  if (mode === 'detector_exception') throw new Error('synthetic detector exception')
  if (mode === 'malformed_detector') return null
  const items = collectStrings(value)
  const started = Date.now()
  const response = await fetch(`${detectorUrl}/scan-batch`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ items }),
    signal: AbortSignal.timeout(5000),
  })
  if (!response.ok) throw Object.assign(new Error('detector HTTP failure'), { code: 'DETECTOR_FAILURE' })
  const scanned = await response.json()
  if (!scanned || scanned.ok !== true || !Array.isArray(scanned.items) || scanned.items.length !== items.length) return null
  const byId = new Map(items.map(item => [item.id, item]))
  let findingCount = 0
  const paths = []
  const types = {}
  for (const item of scanned.items) {
    if (item.ok !== true || !Array.isArray(item.findings) || (Array.isArray(item.errors) && item.errors.length)) return null
    if (item.findings.length) paths.push(byId.get(item.id)?.json_path || '$')
    findingCount += item.findings.length
    for (const finding of item.findings) types[finding.type] = (types[finding.type] || 0) + 1
  }
  return { rawCount: findingCount, placeholderCount: placeholderCount(value), rawPaths: paths, typeCounts: types, latencyMs: Date.now() - started, payloadCount: items.length }
}

function writeJson(name, value) {
  fs.writeFileSync(path.join(evidenceDir, name), JSON.stringify(value, null, 2))
}

function saveState() {
  writeJson('guard-state.json', { scenario, mode, requestIndex, upstreamRequests })
}

function sseText(text, stopReason = 'end_turn') {
  return [
    ['message_start', { type: 'message_start', message: { id: `msg_pg_${requestIndex}`, type: 'message', role: 'assistant', content: [], model: 'claude-sonnet-4-5-20250929', stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } }],
    ['content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }],
    ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } }],
    ['content_block_stop', { type: 'content_block_stop', index: 0 }],
    ['message_delta', { type: 'message_delta', delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 5 } }],
    ['message_stop', { type: 'message_stop' }],
  ]
}

function sseTools(calls) {
  const events = [[
    'message_start',
    { type: 'message_start', message: { id: `msg_pg_${requestIndex}`, type: 'message', role: 'assistant', content: [], model: 'claude-sonnet-4-5-20250929', stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } }, },
  ]]
  calls.forEach((call, index) => {
    events.push(['content_block_start', { type: 'content_block_start', index, content_block: { type: 'tool_use', id: call.id, name: call.name, input: {} } }])
    events.push(['content_block_delta', { type: 'content_block_delta', index, delta: { type: 'input_json_delta', partial_json: JSON.stringify(call.input) } }])
    events.push(['content_block_stop', { type: 'content_block_stop', index }])
  })
  events.push(['message_delta', { type: 'message_delta', delta: { stop_reason: 'tool_use', stop_sequence: null }, usage: { output_tokens: 10 } }])
  events.push(['message_stop', { type: 'message_stop' }])
  return events
}

function firstResponse() {
  switch (scenario) {
    case 'read':
      return sseTools([{ id: 'toolu_read_001', name: 'Read', input: { file_path: path.join(workspace, '.env') } }])
    case 'semantics':
      return sseTools([{ id: 'toolu_semantics_001', name: 'Read', input: { file_path: path.join(workspace, 'semantics.env') } }])
    case 'bash-success':
      return sseTools([{ id: 'toolu_bash_ok', name: 'Bash', input: { command: `node -e "console.log(require('fs').readFileSync('.env','utf8'))"`, description: 'emit synthetic success' } }])
    case 'bash-failure':
      return sseTools([{ id: 'toolu_bash_fail', name: 'Bash', input: { command: `node -e "console.error(require('fs').readFileSync('error-source.txt','utf8')); process.exit(7)"`, description: 'emit synthetic failure' } }])
    case 'grep':
      return sseTools([{ id: 'toolu_grep_001', name: 'Grep', input: { pattern: 'PASSWORD|TOKEN|API_KEY', path: workspace, output_mode: 'content', '-n': true } }])
    case 'parallel':
      return sseTools([
        { id: 'toolu_parallel_a', name: 'Read', input: { file_path: path.join(workspace, '.env') } },
        { id: 'toolu_parallel_b', name: 'Read', input: { file_path: path.join(workspace, 'config.json') } },
      ])
    case 'assistant':
      return sseText('Assistant TOKEN=AssistantToken_7qM2vK8pR4xN5sL9 is protected.')
    case 'mcp-success':
      return sseTools([{ id: 'toolu_mcp_ok', name: 'mcp__pgsynthetic__read_secret', input: {} }])
    case 'mcp-failure':
      return sseTools([{ id: 'toolu_mcp_fail', name: 'mcp__pgsynthetic__fail_secret', input: {} }])
    case 'subagent':
      return sseTools([{ id: 'toolu_agent_001', name: 'Agent', input: { prompt: 'Use Read on .env and track TOKEN=SubagentToken_5qM8vK2pR7xN4sL9.', description: 'Synthetic subagent', subagent_type: 'general-purpose', run_in_background: false } }])
    case 'demo':
      return sseTools([{ id: 'toolu_demo_read', name: 'Read', input: { file_path: path.join(workspace, '.env') } }])
    default:
      return sseText('Mock completed')
  }
}

function respondSse(res, events) {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' })
  for (const [event, data] of events) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  res.end()
}

function providerResponse(body, res) {
  if (scenario === 'retry-reset' && requestIndex === 1) {
    res.socket.destroy()
    return
  }
  if (scenario === 'http-429' || (scenario === 'retry-429' && requestIndex === 1)) {
    res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '0' })
    res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'synthetic 429' } }))
    return
  }
  if (scenario === 'http-500' || (scenario === 'retry-500' && requestIndex === 1)) {
    res.writeHead(500, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ type: 'error', error: { type: 'api_error', message: 'synthetic 500' } }))
    return
  }
  if (scenario === 'malformed-sse') {
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.end('event: message_start\ndata: {broken\n\n')
    return
  }
  if (scenario === 'slow-sse') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
    res.write(`event: message_start\ndata: ${JSON.stringify({ type: 'message_start', message: { id: `msg_pg_${requestIndex}`, type: 'message', role: 'assistant', content: [], model: 'claude-sonnet-4-5-20250929', stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 0 } } })}\n\n`)
    setTimeout(() => res.end(), 120000)
    return
  }
  if (scenario === 'high-usage' && requestIndex === 1) {
    const events = sseText('High-usage synthetic response.')
    events[0][1].message.usage.input_tokens = 150000
    events[4][1].usage.output_tokens = 100
    return respondSse(res, events)
  }
  const hasToolResult = (body.messages || []).some(message => Array.isArray(message.content) && message.content.some(block => block?.type === 'tool_result'))
  if (scenario === 'subagent') {
    if (requestIndex === 1) return respondSse(res, firstResponse())
    if (requestIndex === 2) return respondSse(res, sseTools([{ id: 'toolu_sub_read', name: 'Read', input: { file_path: path.join(workspace, '.env') } }]))
    if (requestIndex === 3) return respondSse(res, sseTools([{ id: 'toolu_sub_bash_fail', name: 'Bash', input: { command: `node -e "console.error(require('fs').readFileSync('error-source.txt','utf8')); process.exit(7)"`, description: 'subagent synthetic failure' } }]))
    return respondSse(res, sseText('Subagent report complete'))
  }
  if (scenario === 'demo') {
    if (requestIndex === 1) return respondSse(res, firstResponse())
    if (requestIndex === 2) return respondSse(res, sseTools([{ id: 'toolu_demo_grep', name: 'Grep', input: { pattern: 'DB_CONNECT_FAILED|error_code|token', path: path.join(workspace, 'app.log'), output_mode: 'content', '-n': true } }]))
    if (requestIndex === 3) return respondSse(res, sseTools([{ id: 'toolu_demo_bash', name: 'Bash', input: { command: `node -e "console.error(require('fs').readFileSync('error-source.txt','utf8')); process.exit(7)"`, description: 'run database diagnostic' } }]))
    if (requestIndex === 4) return respondSse(res, sseTools([{ id: 'toolu_demo_mcp', name: 'mcp__pgsynthetic__read_secret', input: {} }]))
    return respondSse(res, sseText('Diagnosis: db.internal and payments are correct, but configured port 5433 differs from expected port 5432. Error E_PORT_MISMATCH confirms a port configuration issue. Credentials remained placeholders.'))
  }
  respondSse(res, hasToolResult ? sseText('Mock observed a structurally valid tool result and completed.') : firstResponse())
}

const server = http.createServer((req, res) => {
  const chunks = []
  let size = 0
  let tooLarge = false
  req.on('data', chunk => {
    size += chunk.length
    if (size > maxBody) tooLarge = true
    else chunks.push(chunk)
  })
  req.on('end', async () => {
    requestIndex += 1
    const url = req.url || ''
    const isMessages = /^\/v1\/messages(?:\?|$)/.test(url) && !url.includes('/count_tokens')
    const isCountTokens = /^\/v1\/messages\/count_tokens(?:\?|$)/.test(url)
    const known = isMessages || isCountTokens
    const record = {
      request_index: requestIndex,
      method: req.method,
      endpoint: isMessages ? '/v1/messages' : isCountTokens ? '/v1/messages/count_tokens' : 'UNKNOWN',
      timestamp: new Date().toISOString(),
      scenario,
      guard_mode: mode,
      body_bytes: size,
      known_endpoint: known,
      guard_inspected: false,
      guard_allowed: false,
      upstream_forwarded: false,
    }
    try {
      if (tooLarge) throw Object.assign(new Error('body too large'), { code: 'BODY_TOO_LARGE' })
      const contentType = String(req.headers['content-type'] || '')
      if (!contentType.toLowerCase().startsWith('application/json')) throw Object.assign(new Error('unsupported content type'), { code: 'UNSUPPORTED_CONTENT_TYPE' })
      const rawBody = Buffer.concat(chunks).toString('utf8')
      let body = {}
      if (rawBody.length) {
        try { body = JSON.parse(rawBody) }
        catch { throw Object.assign(new Error('malformed JSON'), { code: 'MALFORMED_JSON' }) }
      }
      if (mode === 'bypass') {
        if (!known) throw Object.assign(new Error('unknown endpoint denied'), { code: 'UNKNOWN_ENDPOINT' })
        record.guard_allowed = true
        record.upstream_forwarded = true
        upstreamRequests += 1
        writeJson(`request-${String(requestIndex).padStart(3, '0')}.json`, record)
        saveState()
        if (isCountTokens) {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ input_tokens: 42 }))
          return
        }
        providerResponse(body, res)
        return
      }
      if (mode === 'crash') process.exit(86)
      if (mode === 'detector_timeout') throw Object.assign(new Error('synthetic detector timeout'), { code: 'DETECTOR_TIMEOUT' })
      const inspected = await inspect(body)
      if (!inspected || typeof inspected.rawCount !== 'number') throw Object.assign(new Error('malformed detector output'), { code: 'MALFORMED_DETECTOR' })
      Object.assign(record, {
        guard_inspected: true,
        raw_marker_count: inspected.rawCount,
        placeholder_count: inspected.placeholderCount,
        scanned_payload_count: inspected.payloadCount,
        type_counts: inspected.typeCounts,
        detector_latency_ms: inspected.latencyMs,
      })
      if (!known) throw Object.assign(new Error('unknown endpoint denied'), { code: 'UNKNOWN_ENDPOINT' })
      if (inspected.rawCount > 0 && mode !== 'allow_raw') throw Object.assign(new Error('raw synthetic secret candidate'), { code: 'RAW_FOUND' })
      record.guard_allowed = true
      record.upstream_forwarded = true
      upstreamRequests += 1
      writeJson(`request-${String(requestIndex).padStart(3, '0')}.json`, record)
      saveState()
      if (isCountTokens) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ input_tokens: 42 }))
        return
      }
      providerResponse(body, res)
    } catch (error) {
      record.block_reason = error.code || 'DETECTOR_EXCEPTION'
      writeJson(`request-${String(requestIndex).padStart(3, '0')}.json`, record)
      saveState()
      res.writeHead(error.code === 'BODY_TOO_LARGE' ? 413 : 422, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ type: 'error', error: { type: 'promptguard_block', message: `PromptGuard blocked request: ${record.block_reason}` } }))
    }
  })
})

server.listen(port, '127.0.0.1', () => {
  writeJson('server-ready.json', { port, scenario, mode, pid: process.pid, maxBody })
  saveState()
  process.stdout.write(`READY ${port} ${scenario} ${mode}\n`)
})
