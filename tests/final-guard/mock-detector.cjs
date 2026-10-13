#!/usr/bin/env node
'use strict'

const crypto = require('node:crypto')
const http = require('node:http')

const host = process.env.PG_MOCK_HOST || '127.0.0.1'
const port = Number(process.env.PG_MOCK_DETECTOR_PORT || 0)
const marker = process.env.PG_MOCK_SECRET_MARKER || 'PG_TEST_SECRET_Q7m2K9v4N8x5'
const maxBody = 16 * 1024 * 1024

const state = {
  mode: process.env.PG_MOCK_DETECTOR_MODE || 'normal',
  delayMs: Number(process.env.PG_MOCK_DETECTOR_DELAY_MS || 0),
  healthCount: 0,
  scanCount: 0,
  itemCount: 0,
  maxBatchItems: 0,
  activeScans: 0,
  maxActiveScans: 0,
}

function sendJson(response, statusCode, value) {
  if (response.destroyed) return
  const encoded = Buffer.from(JSON.stringify(value), 'utf8')
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(encoded.length),
    'cache-control': 'no-store',
  })
  response.end(encoded)
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    request.on('data', chunk => {
      size += chunk.length
      if (size > maxBody) {
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

function finding(text) {
  const start = text.indexOf(marker)
  if (start < 0) return []
  return [{
    type: 'TOKEN',
    start,
    end: start + marker.length,
    value_hash: crypto.createHash('sha256').update(marker, 'utf8').digest('hex'),
    confidence: 'strong',
    rule_id: 'synthetic-test-marker',
    source: 'outbound',
    offset_unit: 'utf16_code_units',
  }]
}

async function handleScan(request, response) {
  state.scanCount += 1
  state.activeScans += 1
  state.maxActiveScans = Math.max(state.maxActiveScans, state.activeScans)
  response.once('close', () => {
    state.activeScans = Math.max(0, state.activeScans - 1)
  })

  let payload
  try {
    payload = JSON.parse((await readBody(request)).toString('utf8'))
  } catch {
    sendJson(response, 400, { ok: false, error: 'INVALID_BODY' })
    return
  }

  if (Array.isArray(payload?.items)) {
    state.itemCount += payload.items.length
    state.maxBatchItems = Math.max(state.maxBatchItems, payload.items.length)
  }
  if (state.delayMs > 0 || state.mode === 'timeout') {
    const delay = state.mode === 'timeout' ? 30_000 : state.delayMs
    await new Promise(resolve => setTimeout(resolve, delay))
  }
  if (state.mode === 'http-error') {
    sendJson(response, 500, { ok: false, error: 'SYNTHETIC' })
    return
  }
  if (state.mode === 'malformed-json') {
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end('{broken')
    return
  }
  if (state.mode === 'close') {
    response.socket?.destroy()
    return
  }
  if (!payload || !Array.isArray(payload.items)) {
    sendJson(response, 400, { ok: false, error: 'INVALID_BATCH' })
    return
  }
  if (state.mode === 'malformed-result') {
    sendJson(response, 200, { ok: true, items: 'not-an-array' })
    return
  }

  const items = payload.items.map((item, index) => {
    const text = typeof item.text === 'string' ? item.text : ''
    const findings = state.mode === 'always-finding'
      ? [{
          type: 'TOKEN',
          start: 0,
          end: Math.max(1, Math.min(text.length, 1)),
          value_hash: '0'.repeat(64),
          confidence: 'strong',
          rule_id: 'synthetic-always',
          source: 'outbound',
          offset_unit: 'utf16_code_units',
        }]
      : finding(text)
    if (state.mode === 'invalid-span' && findings.length > 0) findings[0].end = text.length + 10
    return {
      id: state.mode === 'id-mismatch'
        ? index + 100_000
        : state.mode === 'duplicate-ids'
          ? payload.items[0]?.id
          : item.id,
      ok: true,
      findings,
      errors: [],
      finding_count: findings.length,
      latency_ms: 0.1,
      detector: 'MockDetector',
      detector_version: '1.0.0',
      ml: false,
    }
  })
  sendJson(response, 200, {
    ok: true,
    request_id: state.mode === 'request-id-mismatch' ? '00000000-0000-4000-8000-000000000000' : payload.request_id,
    items,
  })
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || '/', 'http://mock.invalid')
  if (request.method === 'GET' && ['/health', '/ready'].includes(url.pathname)) {
    state.healthCount += 1
    if (state.mode === 'unhealthy') {
      sendJson(response, 503, { ok: false, ready: false })
      return
    }
    sendJson(response, 200, { ok: true, ready: true, detector: 'MockDetector' })
    return
  }
  if (request.method === 'GET' && url.pathname === '/__status') {
    sendJson(response, 200, {
      ok: true,
      mode: state.mode,
      delay_ms: state.delayMs,
      health_count: state.healthCount,
      scan_count: state.scanCount,
      item_count: state.itemCount,
      max_batch_items: state.maxBatchItems,
      active_scans: state.activeScans,
      max_active_scans: state.maxActiveScans,
    })
    return
  }
  if (request.method === 'POST' && url.pathname === '/__control') {
    try {
      const value = JSON.parse((await readBody(request)).toString('utf8'))
      const allowed = new Set([
        'normal', 'always-finding', 'http-error', 'malformed-json', 'malformed-result',
        'timeout', 'close', 'unhealthy', 'id-mismatch', 'duplicate-ids',
        'request-id-mismatch', 'invalid-span',
      ])
      if (value.mode !== undefined && !allowed.has(value.mode)) throw new Error('INVALID_MODE')
      if (value.mode !== undefined) state.mode = value.mode
      if (value.delay_ms !== undefined) {
        if (!Number.isInteger(value.delay_ms) || value.delay_ms < 0 || value.delay_ms > 30_000) throw new Error('INVALID_DELAY')
        state.delayMs = value.delay_ms
      }
      sendJson(response, 200, { ok: true, mode: state.mode, delay_ms: state.delayMs })
    } catch {
      sendJson(response, 400, { ok: false, error: 'INVALID_CONTROL' })
    }
    return
  }
  if (request.method === 'POST' && url.pathname === '/scan-batch') {
    await handleScan(request, response)
    return
  }
  sendJson(response, 404, { ok: false, error: 'NOT_FOUND' })
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
