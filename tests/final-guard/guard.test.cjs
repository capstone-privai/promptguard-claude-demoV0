'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs')
const http = require('node:http')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const { spawn } = require('node:child_process')
const { after, before, beforeEach, describe, test } = require('node:test')

const ROOT = path.resolve(__dirname, '..', '..')
const MARKER = 'PG_TEST_SECRET_Q7m2K9v4N8x5'
const SESSION_HASH = 'ab'.repeat(16)
const SAFE_BODY = Buffer.from(JSON.stringify({
  model: 'claude-test',
  max_tokens: 32,
  messages: [{ role: 'user', content: 'Use [TOKEN_1] and keep db.internal:5432.' }],
}), 'utf8')

const children = []
let detector
let upstream
let guard
let tempDirectory
let auditPath

function startProcess(script, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], {
      cwd: ROOT,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })
    children.push(child)
    let stdout = ''
    let stderr = ''
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      reject(new Error(`Timed out starting ${script}; stdout=${stdout}; stderr=${stderr}`))
    }, 15_000)
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', chunk => {
      stdout += chunk
      const match = stdout.match(/READY\s+(\d+)/)
      if (!match || settled) return
      settled = true
      clearTimeout(timer)
      resolve({ child, port: Number(match[1]), stderr: () => stderr })
    })
    child.stderr.on('data', chunk => { stderr += chunk })
    child.once('exit', code => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(new Error(`${script} exited during startup (${code}); stderr=${stderr}`))
    })
  })
}

async function availablePort(start = 28191) {
  for (let candidate = start; candidate < start + 200; candidate += 1) {
    const available = await new Promise(resolve => {
      const probe = net.createServer()
      probe.once('error', () => resolve(false))
      probe.listen(candidate, '127.0.0.1', () => probe.close(() => resolve(true)))
    })
    if (available) return candidate
  }
  throw new Error('no provider-test port available')
}

function stopProcess(child) {
  if (!child || child.exitCode !== null) return Promise.resolve()
  return new Promise(resolve => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      resolve()
    }, 3_000)
    child.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
    child.kill('SIGTERM')
  })
}

function request(port, pathname, options = {}) {
  return new Promise((resolve, reject) => {
    const body = options.body === undefined ? null : Buffer.from(options.body)
    const headers = { ...(options.headers || {}) }
    if (body && headers['content-length'] === undefined) headers['content-length'] = String(body.length)
    const chunks = []
    const times = []
    const outgoing = http.request({
      host: '127.0.0.1',
      port,
      path: pathname,
      method: options.method || 'GET',
      headers,
      agent: false,
    }, response => {
      response.on('data', chunk => {
        chunks.push(chunk)
        times.push(Date.now())
        if (options.cancelOnFirstChunk) {
          response.destroy()
          outgoing.destroy()
          resolve({ cancelled: true, statusCode: response.statusCode, headers: response.headers, chunks, times })
        }
      })
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8'),
        chunks,
        times,
      }))
      response.on('aborted', () => {
        if (options.expectEarlyClose) {
          resolve({ statusCode: response.statusCode, headers: response.headers, earlyClose: true, chunks, times })
        } else if (!options.cancelOnFirstChunk) {
          reject(new Error('response aborted'))
        }
      })
      response.on('error', error => {
        if (options.expectEarlyClose) resolve({ statusCode: response.statusCode, earlyClose: true, chunks, times })
        else if (!options.cancelOnFirstChunk) reject(error)
      })
    })
    outgoing.on('error', error => {
      if (options.expectEarlyClose) resolve({ earlyClose: true, error })
      else if (!options.cancelOnFirstChunk) reject(error)
    })
    if (body) outgoing.end(body)
    else outgoing.end()
  })
}

async function jsonRequest(port, pathname, options = {}) {
  const result = await request(port, pathname, options)
  return { ...result, json: result.body ? JSON.parse(result.body) : null }
}

async function setDetector(mode = 'normal', delayMs = 0) {
  return jsonRequest(detector.port, '/__control', {
    method: 'POST',
    body: JSON.stringify({ mode, delay_ms: delayMs }),
    headers: { 'content-type': 'application/json' },
  })
}

async function resetUpstream() {
  await jsonRequest(upstream.port, '/__reset', { method: 'POST', body: '' })
}

async function upstreamStatus() {
  return (await jsonRequest(upstream.port, '/__status')).json
}

async function detectorStatus() {
  return (await jsonRequest(detector.port, '/__status')).json
}

function providerRequest(body = SAFE_BODY, extra = {}) {
  return request(guard.port, extra.pathname || '/v1/messages', {
    method: extra.method || 'POST',
    body,
    headers: {
      'content-type': 'application/json',
      ...(extra.headers || {}),
    },
    cancelOnFirstChunk: extra.cancelOnFirstChunk,
    expectEarlyClose: extra.expectEarlyClose,
  })
}

async function waitFor(predicate, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  throw new Error('condition timeout')
}

describe('production-style Final Guard', { concurrency: 1 }, () => {
  before(async () => {
    tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'promptguard-guard-'))
    auditPath = path.join(tempDirectory, 'guard.jsonl')
    const detectorPort = await availablePort(27191)
    detector = await startProcess(path.join(ROOT, 'tests', 'final-guard', 'mock-detector.cjs'), {
      PG_MOCK_DETECTOR_PORT: String(detectorPort),
      PG_MOCK_SECRET_MARKER: MARKER,
    })
    const upstreamPort = await availablePort(detectorPort + 1)
    upstream = await startProcess(path.join(ROOT, 'tests', 'final-guard', 'mock-upstream.cjs'), {
      PG_MOCK_UPSTREAM_PORT: String(upstreamPort),
      PG_MOCK_SECRET_MARKER: MARKER,
      PG_MOCK_CHUNK_DELAY_MS: '20',
      PG_MOCK_DELAY_MS: '500',
    })
    const guardPort = await availablePort(upstreamPort + 1)
    guard = await startProcess(path.join(ROOT, 'src', 'guard', 'final-guard.cjs'), {
      PG_GUARD_PORT: String(guardPort),
      PG_UPSTREAM_BASE_URL: `http://127.0.0.1:${upstream.port}`,
      PG_GUARD_DETECTOR_URL: `http://127.0.0.1:${detector.port}`,
      PG_DETECTOR_TIMEOUT_MS: '100',
      PG_UPSTREAM_TIMEOUT_MS: '250',
      PG_GUARD_MAX_BODY: String(64 * 1024),
      PG_AUDIT_PATH: auditPath,
      PG_SESSION_HASH: SESSION_HASH,
    })
  })

  beforeEach(async () => {
    await setDetector('normal', 0)
    await resetUpstream()
  })

  after(async () => {
    await Promise.all(children.reverse().map(stopProcess))
  })

  test('health is local and readiness is detector-gated', async () => {
    const health = await jsonRequest(guard.port, '/health')
    assert.equal(health.statusCode, 200)
    assert.equal(health.json.status, 'alive')

    const ready = await jsonRequest(guard.port, '/ready')
    assert.equal(ready.statusCode, 200)
    assert.equal(ready.json.ready, true)

    await setDetector('unhealthy')
    const unavailable = await jsonRequest(guard.port, '/ready')
    assert.equal(unavailable.statusCode, 503)
    assert.equal(unavailable.json.ready, false)
  })

  test('safe JSON is forwarded byte-for-byte with auth headers and query', async () => {
    const result = await providerRequest(SAFE_BODY, {
      pathname: '/v1/messages?beta=true',
      headers: {
        authorization: 'Bearer synthetic-transport-auth',
        'x-api-key': 'synthetic-transport-key',
        'x-session-id': 'synthetic-session-a',
        'x-pg-mock-scenario': 'text',
      },
    })
    assert.equal(result.statusCode, 200)
    assert.match(result.body, /event: message_start/)
    assert.match(result.body, /event: message_stop/)
    assert.ok(result.headers['x-promptguard-request-id'])

    const status = await upstreamStatus()
    assert.equal(status.request_count, 1)
    assert.equal(status.last_body_bytes, SAFE_BODY.length)
    assert.equal(status.last_body_sha256, crypto.createHash('sha256').update(SAFE_BODY).digest('hex'))
    assert.equal(status.last_auth_present, true)
    assert.equal(status.last_api_key_present, true)
    assert.equal(status.last_request_id_present, true)
  })

  test('count_tokens is scanned and proxied as JSON', async () => {
    const result = await providerRequest(SAFE_BODY, { pathname: '/v1/messages/count_tokens?beta=true' })
    assert.equal(result.statusCode, 200)
    assert.deepEqual(JSON.parse(result.body), { input_tokens: 42 })
    const status = await upstreamStatus()
    assert.equal(status.by_endpoint['/v1/messages/count_tokens'], 1)
    assert.equal((await detectorStatus()).scan_count > 0, true)
  })

  test('a finding blocks upstream and raw data never reaches audit', async () => {
    const rawBody = Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: `token=${MARKER}` }] }), 'utf8')
    const result = await providerRequest(rawBody)
    assert.equal(result.statusCode, 422)
    const error = JSON.parse(result.body)
    assert.equal(error.error.code, 'DETECTOR_FINDINGS')
    assert.equal((await upstreamStatus()).request_count, 0)

    const audit = fs.readFileSync(auditPath, 'utf8')
    assert.equal(audit.includes(MARKER), false)
    const last = JSON.parse(audit.trim().split(/\r?\n/).at(-1))
    assert.equal(last.decision, 'block')
    assert.equal(last.finding_count, 1)
    assert.deepEqual(last.finding_types, ['TOKEN'])
  })

  test('detector timeout, HTTP error, malformed output, and response mixing all fail closed', async () => {
    for (const [mode, expected] of [
      ['timeout', 'DETECTOR_TIMEOUT'],
      ['http-error', 'DETECTOR_HTTP_ERROR'],
      ['malformed-json', 'DETECTOR_MALFORMED_RESULT'],
      ['malformed-result', 'DETECTOR_MALFORMED_RESULT'],
      ['id-mismatch', 'DETECTOR_MALFORMED_RESULT'],
      ['duplicate-ids', 'DETECTOR_MALFORMED_RESULT'],
      ['request-id-mismatch', 'DETECTOR_MALFORMED_RESULT'],
    ]) {
      await resetUpstream()
      await setDetector(mode, 0)
      const result = await providerRequest()
      assert.equal(result.statusCode, 503, mode)
      assert.equal(JSON.parse(result.body).error.code, expected, mode)
      assert.equal((await upstreamStatus()).request_count, 0, mode)
    }

    await setDetector('normal', 0)
    const recovered = await providerRequest()
    assert.equal(recovered.statusCode, 200)
  })

  test('malformed, unsupported, oversized, unknown, and non-POST requests never reach upstream', async () => {
    const cases = [
      () => providerRequest(Buffer.from('{broken', 'utf8')),
      () => providerRequest(SAFE_BODY, { headers: { 'content-type': 'text/plain' } }),
      () => providerRequest(SAFE_BODY, { headers: { 'content-encoding': 'gzip' } }),
      () => providerRequest(Buffer.from(JSON.stringify({ value: 'x'.repeat(70 * 1024) }), 'utf8')),
      () => providerRequest(SAFE_BODY, { pathname: '/v1/future_endpoint' }),
      () => request(guard.port, '/v1/messages', { method: 'GET' }),
    ]
    const expected = [400, 415, 415, 413, 404, 405]
    for (let index = 0; index < cases.length; index += 1) {
      await resetUpstream()
      const result = await cases[index]()
      assert.equal(result.statusCode, expected[index])
      assert.equal((await upstreamStatus()).request_count, 0)
    }
  })

  test('each retry is rescanned and provider statuses are propagated', async () => {
    const beforeScans = (await detectorStatus()).scan_count
    const first = await providerRequest(SAFE_BODY, { headers: { 'x-pg-mock-scenario': 'retry-429' } })
    const second = await providerRequest(SAFE_BODY, { headers: { 'x-pg-mock-scenario': 'retry-429' } })
    assert.equal(first.statusCode, 429)
    assert.equal(second.statusCode, 200)
    assert.equal((await upstreamStatus()).request_count, 2)
    assert.equal((await detectorStatus()).scan_count - beforeScans, 2)
  })

  test('SSE text, tool, malformed, error, and early-close responses pass through without buffering or rewrite', async () => {
    for (const scenario of ['text', 'tool', 'multi-tool', 'malformed-sse', 'error-event']) {
      const result = await providerRequest(SAFE_BODY, { headers: { 'x-pg-mock-scenario': scenario } })
      assert.equal(result.statusCode, 200, scenario)
      if (scenario === 'malformed-sse') assert.match(result.body, /\{broken/)
      if (scenario === 'tool') assert.match(result.body, /input_json_delta/)
      if (scenario === 'multi-tool') assert.match(result.body, /toolu_pg_/)
      if (scenario === 'error-event') assert.match(result.body, /event: error/)
    }
    const early = await providerRequest(SAFE_BODY, {
      headers: { 'x-pg-mock-scenario': 'early-close' },
      expectEarlyClose: true,
    })
    assert.equal(early.earlyClose, true)
  })

  test('client cancellation tears down the upstream stream', async () => {
    await providerRequest(SAFE_BODY, {
      headers: { 'x-pg-mock-scenario': 'text' },
      cancelOnFirstChunk: true,
    })
    await waitFor(async () => (await upstreamStatus()).cancelled_responses >= 1)
    assert.equal((await upstreamStatus()).active_responses, 0)
  })

  test('concurrent requests have unique correlation IDs and no cross-talk', async () => {
    const results = await Promise.all(Array.from({ length: 10 }, (_, index) => providerRequest(
      Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: `safe request ${index}` }] }), 'utf8'),
    )))
    assert.ok(results.every(result => result.statusCode === 200))
    const ids = new Set(results.map(result => result.headers['x-promptguard-request-id']))
    assert.equal(ids.size, 10)
    const status = await upstreamStatus()
    assert.equal(status.request_count, 10)
    assert.equal(status.raw_marker_count, 0)
  })

  test('status and the complete JSONL audit remain raw-free and schema-limited', async () => {
    const status = await jsonRequest(guard.port, '/status')
    assert.equal(status.statusCode, 200)
    assert.equal(typeof status.json.blocked, 'number')
    assert.equal(typeof status.json.allowed, 'number')

    const allowedKeys = new Set([
      'timestamp', 'request_id', 'session_hash', 'endpoint', 'body_size', 'finding_count',
      'finding_types', 'decision', 'reason', 'scan_latency_ms', 'upstream_status',
    ])
    const text = fs.readFileSync(auditPath, 'utf8')
    assert.equal(text.includes(MARKER), false)
    assert.equal(text.includes('synthetic-transport-auth'), false)
    assert.equal(text.includes('synthetic-transport-key'), false)
    for (const line of text.trim().split(/\r?\n/)) {
      const record = JSON.parse(line)
      assert.ok(Object.keys(record).every(key => allowedKeys.has(key)))
      assert.match(record.request_id, /^[0-9a-f-]{36}$/)
      assert.equal(record.session_hash, SESSION_HASH)
    }
  })
})
