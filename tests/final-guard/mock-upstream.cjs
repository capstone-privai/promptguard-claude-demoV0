#!/usr/bin/env node
'use strict'

const crypto = require('node:crypto')
const http = require('node:http')

const host = process.env.PG_MOCK_HOST || '127.0.0.1'
const port = Number(process.env.PG_MOCK_UPSTREAM_PORT || 0)
const defaultScenario = process.env.PG_MOCK_SCENARIO || 'text'
const marker = process.env.PG_MOCK_SECRET_MARKER || 'PG_TEST_SECRET_Q7m2K9v4N8x5'
const chunkDelayMs = Number(process.env.PG_MOCK_CHUNK_DELAY_MS || 5)
const scenarioCounts = new Map()

const state = {
  requestCount: 0,
  rawMarkerCount: 0,
  cancelledResponses: 0,
  activeResponses: 0,
  maxActiveResponses: 0,
  byEndpoint: Object.create(null),
  byScenario: Object.create(null),
  lastBodyBytes: 0,
  lastBodySha256: null,
  lastAuthPresent: false,
  lastApiKeyPresent: false,
  lastRequestIdPresent: false,
}

function sendJson(response, statusCode, value, headers = {}) {
  if (response.destroyed) return
  const encoded = Buffer.from(JSON.stringify(value), 'utf8')
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(encoded.length),
    ...headers,
  })
  response.end(encoded)
}

function readBody(request, limit = 32 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    request.on('data', chunk => {
      size += chunk.length
      if (size > limit) {
        reject(new Error('BODY_TOO_LARGE'))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => resolve(Buffer.concat(chunks, size)))
    request.on('error', reject)
  })
}

function occurrences(buffer, needle) {
  if (!needle) return 0
  let count = 0
  let cursor = 0
  while (cursor <= buffer.length - Buffer.byteLength(needle)) {
    const index = buffer.indexOf(needle, cursor, 'utf8')
    if (index < 0) break
    count += 1
    cursor = index + Buffer.byteLength(needle)
  }
  return count
}

function messageStart(id, inputTokens = 12) {
  return ['message_start', {
    type: 'message_start',
    message: {
      id,
      type: 'message',
      role: 'assistant',
      content: [],
      model: 'claude-sonnet-4-5-20250929',
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: inputTokens, output_tokens: 1 },
    },
  }]
}

function textEvents(id, text = 'Synthetic provider response.', inputTokens = 12) {
  return [
    messageStart(id, inputTokens),
    ['content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }],
    ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } }],
    ['content_block_stop', { type: 'content_block_stop', index: 0 }],
    ['message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 8 } }],
    ['message_stop', { type: 'message_stop' }],
  ]
}

function toolEvents(id, count = 1) {
  const events = [messageStart(id)]
  for (let index = 0; index < count; index += 1) {
    events.push(['content_block_start', {
      type: 'content_block_start',
      index,
      content_block: { type: 'tool_use', id: `toolu_pg_${id}_${index}`, name: 'Read', input: {} },
    }])
    events.push(['content_block_delta', {
      type: 'content_block_delta',
      index,
      delta: { type: 'input_json_delta', partial_json: JSON.stringify({ file_path: `fixture-${index}.txt` }) },
    }])
    events.push(['content_block_stop', { type: 'content_block_stop', index }])
  }
  events.push(['message_delta', {
    type: 'message_delta',
    delta: { stop_reason: 'tool_use', stop_sequence: null },
    usage: { output_tokens: 16 },
  }])
  events.push(['message_stop', { type: 'message_stop' }])
  return events
}

async function streamEvents(response, events, delayMs = chunkDelayMs) {
  response.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
  })
  for (const [event, data] of events) {
    if (response.destroyed) return
    response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
    if (delayMs > 0) await new Promise(resolve => setTimeout(resolve, delayMs))
  }
  response.end()
}

function publicState() {
  return {
    ok: true,
    request_count: state.requestCount,
    raw_marker_count: state.rawMarkerCount,
    cancelled_responses: state.cancelledResponses,
    active_responses: state.activeResponses,
    max_active_responses: state.maxActiveResponses,
    by_endpoint: { ...state.byEndpoint },
    by_scenario: { ...state.byScenario },
    last_body_bytes: state.lastBodyBytes,
    last_body_sha256: state.lastBodySha256,
    last_auth_present: state.lastAuthPresent,
    last_api_key_present: state.lastApiKeyPresent,
    last_request_id_present: state.lastRequestIdPresent,
  }
}

function resetState() {
  state.requestCount = 0
  state.rawMarkerCount = 0
  state.cancelledResponses = 0
  state.activeResponses = 0
  state.maxActiveResponses = 0
  state.byEndpoint = Object.create(null)
  state.byScenario = Object.create(null)
  state.lastBodyBytes = 0
  state.lastBodySha256 = null
  state.lastAuthPresent = false
  state.lastApiKeyPresent = false
  state.lastRequestIdPresent = false
  scenarioCounts.clear()
}

async function respondScenario(response, scenario, requestNumber) {
  const id = `msg_pg_${requestNumber}`
  const count = (scenarioCounts.get(scenario) || 0) + 1
  scenarioCounts.set(scenario, count)

  if (/^status-(429|500|502)$/.test(scenario)) {
    const status = Number(scenario.slice('status-'.length))
    sendJson(response, status, { type: 'error', error: { type: 'synthetic_error', message: `synthetic ${status}` } })
    return
  }
  if (/^retry-(429|500|502)$/.test(scenario) && count === 1) {
    const status = Number(scenario.slice('retry-'.length))
    sendJson(response, status, { type: 'error', error: { type: 'synthetic_error', message: `synthetic ${status}` } }, { 'retry-after': '0' })
    return
  }
  if (scenario === 'reset' || (scenario === 'retry-reset' && count === 1)) {
    response.socket?.destroy()
    return
  }
  if (scenario === 'timeout') {
    const delay = Number(process.env.PG_MOCK_DELAY_MS || 30_000)
    await new Promise(resolve => setTimeout(resolve, delay))
    if (!response.destroyed) await streamEvents(response, textEvents(id), 0)
    return
  }
  if (scenario === 'delay') {
    const delay = Number(process.env.PG_MOCK_DELAY_MS || 250)
    await new Promise(resolve => setTimeout(resolve, delay))
    if (!response.destroyed) await streamEvents(response, textEvents(id), 0)
    return
  }
  if (scenario === 'malformed-sse') {
    response.writeHead(200, { 'content-type': 'text/event-stream' })
    response.end('event: message_start\ndata: {broken\n\n')
    return
  }
  if (scenario === 'early-close') {
    response.writeHead(200, { 'content-type': 'text/event-stream' })
    response.flushHeaders()
    response.write(`event: message_start\ndata: ${JSON.stringify(messageStart(id)[1])}\n\n`)
    await new Promise(resolve => setTimeout(resolve, 20))
    response.socket?.destroy()
    return
  }
  if (scenario === 'error-event') {
    response.writeHead(200, { 'content-type': 'text/event-stream' })
    response.end(`event: error\ndata: ${JSON.stringify({ type: 'error', error: { type: 'synthetic_error', message: 'synthetic stream error' } })}\n\n`)
    return
  }
  if (scenario === 'tool') {
    await streamEvents(response, toolEvents(id, 1))
    return
  }
  if (scenario === 'multi-tool') {
    await streamEvents(response, toolEvents(id, 3))
    return
  }
  if (scenario === 'tool-cycle' && count === 1) {
    await streamEvents(response, toolEvents(id, 1))
    return
  }
  if (scenario === 'high-usage') {
    const tokens = Number(process.env.PG_MOCK_INPUT_TOKENS || 180_000)
    await streamEvents(response, textEvents(id, 'Synthetic high-usage response.', tokens))
    return
  }
  await streamEvents(response, textEvents(id))
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || '/', 'http://mock.invalid')
  if (request.method === 'GET' && url.pathname === '/__status') {
    sendJson(response, 200, publicState())
    return
  }
  if (request.method === 'POST' && url.pathname === '/__reset') {
    request.resume()
    resetState()
    sendJson(response, 200, { ok: true })
    return
  }
  if (request.method !== 'POST' || !['/v1/messages', '/v1/messages/count_tokens'].includes(url.pathname)) {
    request.resume()
    sendJson(response, 404, { type: 'error', error: { type: 'not_found', message: 'synthetic not found' } })
    return
  }

  let body
  try {
    body = await readBody(request)
  } catch {
    sendJson(response, 400, { type: 'error', error: { type: 'invalid_request', message: 'invalid synthetic body' } })
    return
  }

  const scenarioHeader = request.headers['x-pg-mock-scenario']
  const scenario = typeof scenarioHeader === 'string' && /^[a-z0-9-]{1,32}$/.test(scenarioHeader)
    ? scenarioHeader
    : defaultScenario

  state.requestCount += 1
  state.rawMarkerCount += occurrences(body, marker)
  state.byEndpoint[url.pathname] = (state.byEndpoint[url.pathname] || 0) + 1
  state.byScenario[scenario] = (state.byScenario[scenario] || 0) + 1
  state.lastBodyBytes = body.length
  state.lastBodySha256 = crypto.createHash('sha256').update(body).digest('hex')
  state.lastAuthPresent = typeof request.headers.authorization === 'string'
  state.lastApiKeyPresent = typeof request.headers['x-api-key'] === 'string'
  state.lastRequestIdPresent = typeof request.headers['x-promptguard-request-id'] === 'string'
  state.activeResponses += 1
  state.maxActiveResponses = Math.max(state.maxActiveResponses, state.activeResponses)
  let completed = false
  response.once('finish', () => { completed = true })
  response.once('close', () => {
    state.activeResponses = Math.max(0, state.activeResponses - 1)
    if (!completed) state.cancelledResponses += 1
  })

  if (url.pathname === '/v1/messages/count_tokens') {
    sendJson(response, 200, { input_tokens: 42 })
    return
  }
  await respondScenario(response, scenario, state.requestCount)
})

server.listen(port, host, () => {
  const address = server.address()
  process.stdout.write(`READY ${address.port}\n`)
})

const stop = () => {
  server.close()
  process.exit(0)
}
process.once('SIGTERM', stop)
process.once('SIGINT', stop)
