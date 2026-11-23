'use strict'

// When the supervisor found that the Mod's and the Guard's detector filter settings differ, a Guard block says
// so (PG_DETECTOR_FILTER_MISMATCH names the settings). Mock detector and upstream; synthetic marker only.
const assert = require('node:assert/strict')
const fs = require('node:fs')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const { spawn } = require('node:child_process')
const { after, before, describe, test } = require('node:test')

const ROOT = path.resolve(__dirname, '..', '..')
const MARKER = 'PG_TEST_SECRET_Q7m2K9v4N8x5'
const children = []

const freePort = () => new Promise((resolve, reject) => {
  const probe = net.createServer()
  probe.once('error', reject)
  probe.listen(0, '127.0.0.1', () => {
    const { port } = probe.address()
    probe.close(() => resolve(port))
  })
})

function start(script, env) {
  const child = spawn(process.execPath, [script], { cwd: ROOT, env: { ...process.env, ...env }, stdio: 'ignore', windowsHide: true })
  children.push(child)
}

async function waitOk(url) {
  for (let attempt = 0; attempt < 300; attempt++) {
    try { if ((await fetch(url)).ok) return } catch { /* not up yet */ }
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  throw new Error(`not ready: ${url}`)
}

describe('Final Guard block reason with a filter settings mismatch', () => {
  const guards = {}
  before(async () => {
    const [detector, upstream] = [await freePort(), await freePort()]
    start(path.join(ROOT, 'tests', 'final-guard', 'mock-detector.cjs'), { PG_MOCK_DETECTOR_PORT: String(detector), PG_MOCK_SECRET_MARKER: MARKER })
    start(path.join(ROOT, 'tests', 'final-guard', 'mock-upstream.cjs'), { PG_MOCK_UPSTREAM_PORT: String(upstream), PG_MOCK_SECRET_MARKER: MARKER })
    await waitOk(`http://127.0.0.1:${detector}/health`)
    await waitOk(`http://127.0.0.1:${upstream}/__status`)
    for (const [name, mismatch] of [['mismatch', 'PG_DETECTOR_FILTERS'], ['same', ''], ['model', 'PG_ML_CHECKPOINT,PG_DETECTOR_CANDIDATE_POLICY'], ['both', 'PG_DETECTOR_FILTERS,PG_VERIFIER_BUNDLE']]) {
      const port = await freePort()
      start(path.join(ROOT, 'src', 'guard', 'final-guard.cjs'), {
        PG_GUARD_PORT: String(port),
        PG_UPSTREAM_BASE_URL: `http://127.0.0.1:${upstream}`,
        PG_GUARD_DETECTOR_URL: `http://127.0.0.1:${detector}`,
        PG_DETECTOR_TIMEOUT_MS: '2000',
        PG_AUDIT_PATH: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pg-mismatch-')), 'audit.jsonl'),
        PG_SESSION_HASH: 'ab'.repeat(16),
        PG_DETECTOR_FILTER_MISMATCH: mismatch,
      })
      guards[name] = `http://127.0.0.1:${port}`
      await waitOk(`${guards[name]}/health`)
    }
  })
  after(() => { for (const child of children) child.kill() })

  const send = url => fetch(`${url}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ messages: [{ role: 'user', content: `token=${MARKER}` }] }) })

  test('a block names the mismatched settings, without values', async () => {
    const response = await send(guards.mismatch)
    assert.equal(response.status, 422)
    const { error } = await response.json()
    assert.equal(error.code, 'DETECTOR_FINDINGS')
    assert.match(error.message, /필터 설정 불일치/)
    assert.deepEqual(error.filter_settings_mismatch, ['PG_DETECTOR_FILTERS'])
    assert.ok(!JSON.stringify(error).includes(MARKER))
  })

  test('model settings: the block names them under their own heading, without values', async () => {
    const { error } = await (await send(guards.model)).json()
    assert.match(error.message, /모델 설정 불일치: PG_ML_CHECKPOINT, PG_DETECTOR_CANDIDATE_POLICY/)
    assert.doesNotMatch(error.message, /필터 설정 불일치/)
    assert.deepEqual(error.model_settings_mismatch, ['PG_ML_CHECKPOINT', 'PG_DETECTOR_CANDIDATE_POLICY'])
    assert.equal(error.filter_settings_mismatch, undefined)
  })

  test('filter and model settings together', async () => {
    const { error } = await (await send(guards.both)).json()
    assert.match(error.message, /필터 설정 불일치: PG_DETECTOR_FILTERS/)
    assert.match(error.message, /모델 설정 불일치: PG_VERIFIER_BUNDLE/)
    assert.deepEqual(error.filter_settings_mismatch, ['PG_DETECTOR_FILTERS'])
    assert.deepEqual(error.model_settings_mismatch, ['PG_VERIFIER_BUNDLE'])
  })

  test('with the same settings the block is as before', async () => {
    const response = await send(guards.same)
    assert.equal(response.status, 422)
    const { error } = await response.json()
    assert.doesNotMatch(error.message, /필터 설정 불일치/)
    assert.equal(error.filter_settings_mismatch, undefined)
  })
})
