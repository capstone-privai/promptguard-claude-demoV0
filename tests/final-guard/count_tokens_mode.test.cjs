'use strict'

// PG_GUARD_COUNT_TOKENS=block|mask and the block message for a flagged system prompt.
// Synthetic marker only; nothing here prints it.
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
const children = []

function startProcess(script, env, { expectExit = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], { cwd: ROOT, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
    children.push(child)
    let stdout = ''
    let stderr = ''
    let settled = false
    const timer = setTimeout(() => { if (!settled) { settled = true; reject(new Error(`timeout starting ${script}`)) } }, 15_000)
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', chunk => {
      stdout += chunk
      const match = stdout.match(/READY\s+(\d+)/)
      if (!match || settled) return
      settled = true
      clearTimeout(timer)
      if (expectExit) reject(new Error(`${script} started but should have refused`))
      else resolve({ child, port: Number(match[1]) })
    })
    child.stderr.on('data', chunk => { stderr += chunk })
    child.once('exit', code => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (expectExit) resolve({ code, stderr })
      else reject(new Error(`${script} exited (${code}): ${stderr}`))
    })
  })
}

async function availablePort(start) {
  for (let candidate = start; candidate < start + 200; candidate += 1) {
    const free = await new Promise(resolve => {
      const probe = net.createServer()
      probe.once('error', () => resolve(false))
      probe.listen(candidate, '127.0.0.1', () => probe.close(() => resolve(true)))
    })
    if (free) return candidate
  }
  throw new Error('no port')
}

function request(port, pathname, { method = 'GET', body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(body)
    const headers = payload ? { 'content-type': 'application/json', 'content-length': String(payload.length) } : {}
    const outgoing = http.request({ host: '127.0.0.1', port, path: pathname, method, headers, agent: false }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8')
        resolve({ statusCode: response.statusCode, body: text, json: text ? JSON.parse(text) : null })
      })
    })
    outgoing.on('error', reject)
    outgoing.end(payload || undefined)
  })
}

const post = (guard, pathname, value) => request(guard.port, pathname, { method: 'POST', body: JSON.stringify(value) })
const sha = value => crypto.createHash('sha256').update(Buffer.from(JSON.stringify(value), 'utf8')).digest('hex')

describe('count_tokens mode', { concurrency: 1 }, () => {
  let detector
  let upstream
  const guards = {}
  const audits = {}
  const status = async () => (await request(upstream.port, '/__status')).json

  before(async () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'promptguard-count-'))
    detector = await startProcess(path.join(ROOT, 'tests/final-guard/mock-detector.cjs'), { PG_MOCK_DETECTOR_PORT: String(await availablePort(29191)), PG_MOCK_SECRET_MARKER: MARKER })
    upstream = await startProcess(path.join(ROOT, 'tests/final-guard/mock-upstream.cjs'), { PG_MOCK_UPSTREAM_PORT: String(await availablePort(29291)), PG_MOCK_SECRET_MARKER: MARKER })
    const base = { PG_UPSTREAM_BASE_URL: `http://127.0.0.1:${upstream.port}`, PG_GUARD_DETECTOR_URL: `http://127.0.0.1:${detector.port}`, PG_DETECTOR_TIMEOUT_MS: '2000', PG_SESSION_HASH: 'ab'.repeat(16) }
    let port = 29391
    for (const mode of ['default', 'block', 'mask']) {
      audits[mode] = path.join(temp, `${mode}.jsonl`)
      port = await availablePort(port + 1)
      const env = { ...base, PG_GUARD_PORT: String(port), PG_AUDIT_PATH: audits[mode] }
      if (mode !== 'default') env.PG_GUARD_COUNT_TOKENS = mode
      guards[mode] = await startProcess(path.join(ROOT, 'src/guard/final-guard.cjs'), env)
    }
  })

  beforeEach(async () => { await request(upstream.port, '/__reset', { method: 'POST', body: '' }) })

  after(async () => { for (const child of children) child.kill() })

  const flagged = () => ({
    model: 'claude-test',
    system: [{ type: 'text', text: 'You are a helper.' }],
    messages: [
      { role: 'user', content: [{ type: 'text', text: `log line API_TOKEN=${MARKER} end ${crypto.randomUUID()}` }] },
      { role: 'user', content: `again ${MARKER} and ${MARKER}` },
    ],
  })

  test('an unknown mode refuses to start', async () => {
    const result = await startProcess(path.join(ROOT, 'src/guard/final-guard.cjs'), {
      PG_GUARD_PORT: String(await availablePort(29591)), PG_UPSTREAM_BASE_URL: 'http://127.0.0.1:1', PG_GUARD_DETECTOR_URL: 'http://127.0.0.1:1', PG_GUARD_COUNT_TOKENS: 'allow',
    }, { expectExit: true })
    assert.notEqual(result.code, 0)
    assert.match(result.stderr, /PG_GUARD_COUNT_TOKENS/)
  })

  for (const mode of ['default', 'block']) {
    test(`${mode}: a flagged count_tokens request is refused`, async () => {
      const result = await post(guards[mode], '/v1/messages/count_tokens', flagged())
      assert.equal(result.statusCode, 422)
      assert.equal(result.json.error.code, 'DETECTOR_FINDINGS')
      assert.equal((await status()).request_count, 0)
    })
  }

  test('mask: flagged values become placeholders and the count is returned', async () => {
    const value = flagged()
    const result = await post(guards.mask, '/v1/messages/count_tokens?beta=true', value)
    assert.equal(result.statusCode, 200)
    assert.deepEqual(result.json, { input_tokens: 42 })
    const seen = await status()
    assert.equal(seen.by_endpoint['/v1/messages/count_tokens'], 1)
    assert.equal(seen.raw_marker_count, 0)
    // Same value, same placeholder; other text and the JSON shape unchanged.
    const expected = JSON.parse(JSON.stringify(value).split(MARKER).join('[TOKEN_1]'))
    assert.equal(seen.last_body_sha256, sha(expected))
    const row = JSON.parse(fs.readFileSync(audits.mask, 'utf8').trim().split(/\r?\n/).at(-1))
    assert.equal(row.decision, 'allow')
    assert.equal(row.reason, 'COUNT_TOKENS_MASKED')
    assert.equal(row.finding_count, 3)
    assert.equal(fs.readFileSync(audits.mask, 'utf8').includes(MARKER), false)
  })

  test('mask: a clean count_tokens request is forwarded byte for byte', async () => {
    const value = { model: 'claude-test', messages: [{ role: 'user', content: `clean ${crypto.randomUUID()}` }] }
    const result = await post(guards.mask, '/v1/messages/count_tokens', value)
    assert.equal(result.statusCode, 200)
    assert.equal((await status()).last_body_sha256, sha(value))
  })

  test('mask: /v1/messages with a finding is still refused', async () => {
    const result = await post(guards.mask, '/v1/messages', flagged())
    assert.equal(result.statusCode, 422)
    assert.equal((await status()).request_count, 0)
  })

  test('mask: a value the detector still flags after masking is refused', async () => {
    // always-finding flags every text, placeholders included, so the masked body never passes.
    await request(detector.port, '/__control', { method: 'POST', body: JSON.stringify({ mode: 'always-finding', delay_ms: 0 }) })
    try {
      const result = await post(guards.mask, '/v1/messages/count_tokens', { messages: [{ role: 'user', content: `abc ${crypto.randomUUID()}` }] })
      assert.equal(result.statusCode, 422)
      assert.equal((await status()).request_count, 0)
    } finally {
      await request(detector.port, '/__control', { method: 'POST', body: JSON.stringify({ mode: 'normal', delay_ms: 0 }) })
    }
  })

  test('a flagged system prompt is refused with a pointer to promptguard run', async () => {
    for (const mode of ['default', 'mask']) {
      const value = { model: 'claude-test', system: [{ type: 'text', text: `deploy key ${MARKER} ${crypto.randomUUID()}` }], messages: [{ role: 'user', content: 'hi' }] }
      const result = await post(guards[mode], '/v1/messages', value)
      assert.equal(result.statusCode, 422)
      assert.equal(result.json.error.code, 'DETECTOR_FINDINGS')
      assert.match(result.json.error.message, /promptguard run/)
      assert.match(result.json.error.message, /--append-system-prompt/)
      assert.equal(result.body.includes(MARKER), false)
    }
  })

  test('a finding only in messages keeps the plain message', async () => {
    const result = await post(guards.default, '/v1/messages', { system: 'plain', messages: [{ role: 'user', content: `x ${MARKER}` }] })
    assert.equal(result.statusCode, 422)
    assert.doesNotMatch(result.json.error.message, /promptguard run/)
  })
})
