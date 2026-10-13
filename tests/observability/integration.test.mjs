import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import net from 'node:net'
import { projectAudit, projectGuardAudit } from '../../src/observability/model.mjs'
const python = process.env.PROMPTGUARD_PYTHON || (process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python')
async function freePort() {
  const server = net.createServer()
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  await new Promise(resolve => server.close(resolve))
  return port
}
async function launch(command, args, env, ready) {
  const child = spawn(command, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' })
  let output = ''
  let diagnostics = ''
  child.stderr.on('data', chunk => { diagnostics += chunk })
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error('SERVICE_START_TIMEOUT')) }, 20000)
    child.once('error', () => { clearTimeout(timer); reject(new Error('SERVICE_START_FAILED')) })
    child.once('exit', () => { clearTimeout(timer); reject(new Error('SERVICE_EXITED')) })
    child.stdout.on('data', chunk => { output += chunk; if (output.includes(ready)) { clearTimeout(timer); resolve() } })
  })
  return { child, diagnostics: () => output + diagnostics }
}
async function stop(child) {
  if (child.exitCode === null && child.signalCode === null) {
    await new Promise(resolve => {
      child.once('exit', resolve)
      if (process.platform === 'win32') child.kill()
      else process.kill(-child.pid, 'SIGTERM')
    })
  }
  child.stdout.destroy()
  child.stderr.destroy()
}

async function waitForGuardRows(file, minimum) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const text = await readFile(file, 'utf8')
    const rows = text.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line))
    if (rows.length >= minimum) return rows
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  throw new Error('GUARD_AUDIT_TIMEOUT')
}

test('real CredSweeper -> Native Mod -> production Final Guard SAFE/BLOCKED and detector failure', { skip: !existsSync(python), timeout: 60000 }, async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pg-observability-integration-'))
  const detectorPort = await freePort()
  const guardPort = await freePort()
  const upstreamPort = await freePort()
  const detectorUrl = `http://127.0.0.1:${detectorPort}`
  const guardAudit = path.join(directory, 'guard-audit.jsonl')
  const worker = await launch(python, ['src/detector/worker.py'], { PG_DETECTOR_PORT: String(detectorPort), PG_DETECTOR_MODE: 'normal' }, '"ready": true')
  const upstream = await launch(process.execPath, ['tests/final-guard/mock-upstream.cjs'], { PG_MOCK_UPSTREAM_PORT: String(upstreamPort) }, 'READY')
  let guard
  try {
    guard = await launch(process.execPath, ['src/guard/final-guard.cjs'], { PG_GUARD_PORT: String(guardPort), PG_GUARD_DETECTOR_URL: detectorUrl, PG_UPSTREAM_BASE_URL: `http://127.0.0.1:${upstreamPort}`, PG_AUDIT_PATH: guardAudit, PG_SESSION_HASH: 'b'.repeat(64) }, 'READY')
    const callbacks = new Map()
    const { register } = await import(`../../src/native-mod/hooks/register.mjs?integration=${Date.now()}`)
    register((name, fn) => callbacks.set(name, fn))
    let audit = []
    const $ = {
      env: { get: async key => ({ PG_MOD_AUDIT: 'memory', PG_SESSION_HASH: 'b'.repeat(64) }[key]) },
      fs: { write: async (_name, value) => { audit = JSON.parse(value) } },
      mcp: { call: async (_server, _tool, { items }) => {
        const response = await fetch(`${detectorUrl}/scan-batch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ items }) })
        return { content: [{ type: 'text', text: JSON.stringify(await response.json()) }] }
      } },
    }
    const fixture = await readFile('fixtures/positive/.env', 'utf8')
    const expectedValues = fixture.split('\n').filter(line => /PASSWORD|API_KEY|TOKEN/.test(line)).map(line => line.slice(line.indexOf('=') + 1)).filter(Boolean)
    const prompt = await callbacks.get('prompt.submit')($, { text: fixture, context: [] }, async e => e)
    const read = await callbacks.get('tool.call')($, { tool: 'Read' }, async () => ({ result: fixture, context: [] }))
    const shell = await callbacks.get('tool.call')($, { tool: 'Bash' }, async () => ({ result: fixture, context: [] }))
    assert.equal(audit.filter(row => row.event === 'scan_completed').reduce((n, row) => n + row.finding_count, 0), 9)
    assert.equal(projectAudit(audit).flatMap(e => e.findings).length, 9)
    const send = async text => {
      const response = await fetch(`http://127.0.0.1:${guardPort}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ messages: [{ role: 'user', content: text }] }) })
      await response.arrayBuffer()
      return response
    }
    assert.equal((await send(prompt.text)).status, 200)
    let guardRows = await waitForGuardRows(guardAudit, 1)
    const safe = projectGuardAudit(guardRows)[0]
    assert.equal(safe.decision, 'SAFE')
    assert.equal(safe.findingCount, 0)
    assert.equal(safe.upstreamStatus, 200)
    assert.equal((await send(fixture)).status, 422)
    guardRows = await waitForGuardRows(guardAudit, 2)
    const blocked = projectGuardAudit(guardRows)[1]
    assert.equal(blocked.decision, 'BLOCKED')
    await stop(worker.child)
    assert.equal((await send('No secret')).status, 503)
    guardRows = await waitForGuardRows(guardAudit, 3)
    const failure = projectGuardAudit(guardRows)[2]
    assert.equal(failure.decision, 'BLOCKED')
    assert.equal(failure.reason, 'DETECTOR_UNAVAILABLE')
    const upstreamState = await (await fetch(`http://127.0.0.1:${upstreamPort}/__status`)).json()
    assert.equal(upstreamState.request_count, 1)
    const exported = JSON.stringify({ audit, prompt, read, shell, safe, blocked, failure, upstreamState }) + worker.diagnostics() + guard.diagnostics() + upstream.diagnostics()
    for (const value of expectedValues) assert.equal(exported.includes(value), false, 'Synthetic fixture value must not escape safe outputs')
  } finally {
    await stop(worker.child)
    if (guard) await stop(guard.child)
    await stop(upstream.child)
    await rm(directory, { recursive: true })
  }
})
