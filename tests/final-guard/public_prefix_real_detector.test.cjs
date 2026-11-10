'use strict'

// Final Guard with the real detector worker: the mock detector cannot show that the real rules leave
// `API_KEY=sk_live_[STRIPE_SECRET_KEY_1]` alone. Skipped when the project's Python is not installed.
const assert = require('node:assert/strict')
const fs = require('node:fs')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const { spawn } = require('node:child_process')
const { after, before, describe, test } = require('node:test')

const ROOT = path.resolve(__dirname, '..', '..')
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
// Synthetic only, joined at run time so no complete provider-shaped value sits in the repository.
const PREFIX = ['sk', 'live', ''].join('_')
const WHOLE = `${PREFIX}SYNTHxFAKExVALUExONLYx0001`
const children = []

const freePort = () => new Promise((resolve, reject) => {
  const probe = net.createServer()
  probe.once('error', reject)
  probe.listen(0, '127.0.0.1', () => {
    const { port } = probe.address()
    probe.close(() => resolve(port))
  })
})

function start(command, args, env) {
  const child = spawn(command, args, { cwd: ROOT, env: { ...process.env, ...env }, stdio: 'ignore', windowsHide: true })
  children.push(child)
}

async function waitOk(url) {
  for (let attempt = 0; attempt < 600; attempt++) {
    try { if ((await fetch(url)).ok) return } catch { /* not up yet */ }
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error(`not ready: ${url}`)
}

describe('Final Guard with the real detector and public prefix on', { skip: !fs.existsSync(PYTHON) }, () => {
  let guardUrl
  let upstreamUrl
  const send = text => fetch(`${guardUrl}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ messages: [{ role: 'user', content: text }] }),
  })
  const forwarded = async () => (await (await fetch(`${upstreamUrl}/__status`)).json()).request_count

  before(async () => {
    const [detector, upstream, guard] = [await freePort(), await freePort(), await freePort()]
    const shared = { PG_PLACEHOLDER_PUBLIC_PREFIX: 'on', PG_DETECTOR_DISABLE: 'gitleaks' }
    start(PYTHON, [path.join(ROOT, 'src', 'detector', 'worker.py')], { ...shared, PG_DETECTOR_PORT: String(detector), PYTHONIOENCODING: 'utf-8' })
    await waitOk(`http://127.0.0.1:${detector}/ready`)
    start(process.execPath, [path.join(ROOT, 'tests', 'final-guard', 'mock-upstream.cjs')], { PG_MOCK_UPSTREAM_PORT: String(upstream) })
    upstreamUrl = `http://127.0.0.1:${upstream}`
    await waitOk(`${upstreamUrl}/__status`)
    start(process.execPath, [path.join(ROOT, 'src', 'guard', 'final-guard.cjs')], {
      ...shared,
      PG_GUARD_PORT: String(guard),
      PG_UPSTREAM_BASE_URL: upstreamUrl,
      PG_GUARD_DETECTOR_URL: `http://127.0.0.1:${detector}`,
      PG_DETECTOR_TIMEOUT_MS: '20000',
      PG_AUDIT_PATH: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pg-prefix-')), 'audit.jsonl'),
      PG_SESSION_HASH: 'ab'.repeat(16),
    })
    guardUrl = `http://127.0.0.1:${guard}`
    await waitOk(`${guardUrl}/health`)
  }, { timeout: 120_000 })

  after(() => { for (const child of children) child.kill() })

  for (const form of ['{v}', 'API_KEY={v}', 'export STRIPE_SECRET_KEY={v}', 'password: {v}']) {
    test(`masked text passes: ${form}`, async () => {
      const before = await forwarded()
      const response = await send(form.replace('{v}', `${PREFIX}[STRIPE_SECRET_KEY_1]`))
      assert.equal(response.status, 200)
      assert.equal(await forwarded(), before + 1)
    })
  }

  test('the whole value is still blocked', async () => {
    const before = await forwarded()
    const response = await send(`API_KEY=${WHOLE}`)
    assert.equal(response.status, 422)
    assert.equal(await forwarded(), before)
  })

  test('text around a placeholder does not hide a secret', async () => {
    const response = await send(`API_KEY=${PREFIX}[STRIPE_SECRET_KEY_1]SYNTHxFAKExVALUExONLY`)
    assert.equal(response.status, 422)
  })
})
