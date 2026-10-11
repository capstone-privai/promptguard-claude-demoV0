import test from 'node:test'
import http from 'node:http'
import assert from 'node:assert/strict'
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { JSDOM } from 'jsdom'
import { projectAudit, projectGuard } from '../../src/observability/model.mjs'
import { summarize, pipeline } from '../../src/observability/public/view.mjs'
import { demo } from '../../src/observability/public/demo.mjs'

const synthetic = '[SYNTHETIC_INPUT_ONLY]'
const session = 'a'.repeat(64)
const row = (extra = {}) => ({ timestamp: '2026-10-11T00:00:00.000Z', session_id_hash: session, source: 'user_prompt', event: 'scan_completed', finding_count: 0, redacted_count: 0, scanned_payload_count: 1, ...extra })

test('empty, prompt, tool, multiple files and missing metadata summaries', () => {
  assert.equal(summarize([]).scanned, null)
  assert.equal(summarize(projectAudit([row()])).detected, 0)
  assert.equal(summarize(demo('prompt').events).detected, 1)
  assert.equal(summarize(demo('tool').events).tools, 1)
  assert.equal(summarize(demo('multiple').events).detected, 3)
  assert.equal(summarize(demo('multiple').events).reads, 2)
  assert.equal(demo('missing').events[0].findings[0].rule, null)
  const legacy = projectAudit([row({ scanned_payload_count: undefined, findings: undefined })])
  assert.equal(summarize(legacy).scanned, null)
  assert.deepEqual(legacy[0].findings, [])
})

test('source categories derive from actual hook sources, unknown stays unknown', () => {
  const sources = ['user_prompt', 'read_result', 'bash_stdout', 'history', 'claude_md', 'automatic_context']
  assert.deepEqual(projectAudit(sources.map(source => row({ source }))).map(e => e.source), ['USER_PROMPT', 'FILE_READ', 'TOOL_OUTPUT', 'HISTORY', 'AGENTS_CONTEXT', 'UNKNOWN'])
})

test('failure stages are distinct and no Mod event claims provider egress success', () => {
  for (const stage of ['detector', 'sanitizer']) {
    const events = projectAudit([row({ event: 'scan_failed', blocked: true, failure_stage: stage })])
    assert.equal(events[0].failureStage, stage)
    const stages = pipeline(events)
    assert.equal(stages[stage === 'detector' ? 2 : 3].status, 'error')
    assert.equal(stages[4].status, 'pending')
    assert.equal(stages[5].status, 'pending')
  }
})

test('SAFE requires normal inspected zero findings; bypass and allow_raw are not verified', () => {
  const record = { guard_mode: 'normal', guard_inspected: true, raw_marker_count: 0, guard_allowed: true }
  assert.equal(projectGuard(record).decision, 'SAFE')
  for (const change of [{ guard_mode: 'bypass' }, { guard_mode: 'allow_raw' }, { guard_inspected: false }, { raw_marker_count: 1 }, { raw_marker_count: undefined }]) assert.equal(projectGuard({ ...record, ...change }).decision, 'NOT VERIFIED')
  assert.equal(projectGuard({ guard_allowed: false, block_reason: 'DETECTOR_EXCEPTION' }).decision, 'BLOCKED')
  assert.equal(projectGuard(null), null)
})

test('DTO removes payloads, errors, keys, hashes, paths and arbitrary tool identifiers', () => {
  const projected = projectAudit([row({ raw_secret: synthetic, full_raw_line: synthetic, full_raw_prompt: synthetic, reason: synthetic, tool: synthetic, name: synthetic, session_id_hash: synthetic, source: synthetic, findings: [{ raw_secret: synthetic, value_hash: synthetic, json_path: synthetic, secret_type: 'PASSWORD', detector: 'CredSweeper', rule_id: 'Password', action: 'MASK', start: 1, end: 10, offset_unit: 'utf16_code_units', placeholder: '[PASSWORD_1]' }] })])
  assert.equal(JSON.stringify(projected).includes(synthetic), false)
  assert.equal(projected[0].findings[0].rule, 'Password')
  assert.equal(projected[0].source, 'UNKNOWN')
})

async function hookHarness(failure = null) {
  const callbacks = new Map()
  const mod = await import(`../../src/native-mod/hooks/register.mjs?test=${Math.random()}`)
  mod.register((name, handler) => callbacks.set(name, handler))
  let output = []
  const $ = {
    env: { get: async key => ({ PG_MOD_AUDIT: 'memory-only', PG_SESSION_HASH: session }[key]) },
    fs: { write: async (_file, value) => { output = JSON.parse(value) } },
    mcp: { call: async (_server, _tool, { items }) => {
      if (failure === 'detector') throw new Error(synthetic)
      const rows = items.map(item => {
        const start = item.text.indexOf(synthetic)
        return { id: item.id, ok: true, detector: 'CredSweeper', findings: start < 0 ? [] : [{ type: 'PASSWORD', rule_id: 'Password', start: failure === 'sanitizer' ? -1 : start, end: start + synthetic.length, value_hash: '0'.repeat(64), offset_unit: 'utf16_code_units' }] }
      })
      return { content: [{ type: 'text', text: JSON.stringify({ ok: true, items: rows }) }] }
    } },
  }
  return { $, callbacks, rows: () => output, recover: () => { failure = null } }
}

test('real prompt hook preserves structure and replacement consistency without persisting input', async () => {
  const h = await hookHarness()
  const result = await h.callbacks.get('prompt.submit')(h.$, { text: `HOST=localhost PASSWORD=${synthetic} PORT=5432`, context: [synthetic] }, async e => e)
  assert.equal(result.text.includes(synthetic), false)
  assert.equal(result.text, 'HOST=localhost PASSWORD=[PASSWORD_1] PORT=5432')
  assert.deepEqual(result.context, ['[PASSWORD_1]'])
  assert.equal(h.rows().length, 2)
  assert.equal(JSON.stringify(h.rows()).includes(synthetic), false)
  assert.equal(h.rows()[0].findings[0].rule_id, 'Password')
  assert.equal(h.rows()[0].scanned_payload_count, 1)
})

test('tool result, text and context all audited; no raw values returned', async () => {
  const h = await hookHarness()
  const result = await h.callbacks.get('tool.call')(h.$, { tool: 'Read', tool_use_id: synthetic }, async () => ({ result: { content: synthetic }, text: synthetic, context: [synthetic] }))
  assert.equal(JSON.stringify(result).includes(synthetic), false)
  assert.equal(h.rows().length, 4)
  assert.equal(summarize(projectAudit(h.rows())).tools, 1)
  assert.equal(summarize(projectAudit(h.rows())).reads, 1)
  assert.equal(JSON.stringify(h.rows()).includes(synthetic), false)
})

for (const stage of ['detector', 'sanitizer']) test(`${stage} error is raw-free and retained after recovery`, async () => {
  const h = await hookHarness(stage)
  let thrown
  try { await h.callbacks.get('prompt.submit')(h.$, { text: synthetic, context: [] }, async e => e) } catch (error) { thrown = error }
  assert.ok(thrown)
  assert.equal(thrown.message.includes(synthetic), false)
  assert.equal(h.rows()[0].failure_stage, stage)
  assert.equal(JSON.stringify(h.rows()).includes(synthetic), false)
  h.recover()
  await h.callbacks.get('prompt.submit')(h.$, { text: 'hello', context: [] }, async e => e)
  assert.equal(h.rows()[0].event, 'scan_failed')
  assert.equal(h.rows().length, 3)
})

test('existing denied tools and detector transport bypass are unchanged', async () => {
  const h = await hookHarness()
  const denied = { deny: 'Denied by existing policy' }
  assert.equal(await h.callbacks.get('tool.call')(h.$, { tool: 'Bash' }, async () => denied), denied)
  const response = { result: 'internal detector result' }
  assert.equal(await h.callbacks.get('tool.call')(h.$, { tool: 'mcp__pgdetector__scan_batch' }, async () => response), response)
  assert.equal(h.rows().length, 2)
  assert.equal(h.rows()[1].event, 'tool_denied')
})

test('actual app renders safe DOM, supports demo selection, and never logs payloads', async () => {
  const html = await readFile(new URL('../../src/observability/public/index.html', import.meta.url), 'utf8')
  const dom = new JSDOM(html, { url: 'http://127.0.0.1:18880' })
  const old = { document: globalThis.document, fetch: globalThis.fetch, setInterval: globalThis.setInterval }
  const logs = []
  const methods = ['log', 'error', 'warn', 'debug', 'info']
  const original = Object.fromEntries(methods.map(method => [method, console[method]]))
  try {
    globalThis.document = dom.window.document
    globalThis.setInterval = () => 0
    const events = projectAudit([row({ raw_secret: synthetic, full_raw_prompt: synthetic, findings: [{ secret_type: 'PASSWORD', rule_id: 'Password', detector: 'CredSweeper', action: 'MASK', placeholder: '[PASSWORD_1]' }] })])
    globalThis.fetch = async () => ({ ok: true, json: async () => ({ mode: 'LIVE', events }) })
    for (const method of methods) console[method] = (...args) => logs.push(args)
    await import(`../../src/observability/public/app.mjs?test=${Math.random()}`)
    const text = dom.window.document.body.textContent
    assert.equal(text.includes(synthetic), false)
    assert.equal(text.includes('undefined'), false)
    assert.equal(text.includes('null'), false)
    assert.ok(text.includes('NOT VERIFIED'))
    const mode = dom.window.document.getElementById('mode')
    mode.value = 'DEMO'; mode.dispatchEvent(new dom.window.Event('change'))
    assert.ok(dom.window.document.getElementById('notice').textContent.includes('DEMO / MOCK'))
    for (const scenario of ['empty', 'prompt', 'file', 'tool', 'multiple', 'missing', 'detector-error', 'sanitizer-error', 'blocked']) {
      const select = dom.window.document.getElementById('scenario')
      select.value = scenario; select.dispatchEvent(new dom.window.Event('change'))
      assert.equal(dom.window.document.body.textContent.includes(synthetic), false)
      assert.equal(dom.window.document.body.textContent.includes('undefined'), false)
    }
    assert.equal(logs.length, 0)
  } finally {
    for (const method of methods) console[method] = original[method]
    Object.assign(globalThis, old)
    dom.window.close()
  }
})

test('HTTP endpoint enforces localhost Host, hides raw audit and handles malformed files', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pg-observe-test-'))
  const file = path.join(directory, 'audit.json')
  const old = process.env.PG_MOD_AUDIT
  process.env.PG_MOD_AUDIT = file
  const { createServer } = await import(`../../src/observability/server.mjs?test=${Math.random()}`)
  const server = createServer()
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const url = `http://127.0.0.1:${server.address().port}`
  try {
    await writeFile(file, JSON.stringify([row({ raw_secret: synthetic })]))
    const response = await fetch(`${url}/api/events`)
    assert.equal(response.status, 200)
    assert.equal((await response.text()).includes(synthetic), false)
    assert.equal((await fetch(`${url}/api/events`, { headers: { origin: 'https://example.com' } })).status, 403)
    assert.equal(await new Promise(resolve => http.get(`${url}/api/events`, { headers: { host: 'example.com' } }, response => { response.resume(); resolve(response.statusCode) })), 403)
    assert.equal((await fetch(`${url}/api/events`, { method: 'POST' })).status, 403)
    await writeFile(file, synthetic)
    const failed = await fetch(`${url}/api/events`)
    assert.equal(failed.status, 503)
    assert.equal((await failed.text()).includes(synthetic), false)
  } finally {
    await new Promise(resolve => server.close(resolve))
    if (old === undefined) delete process.env.PG_MOD_AUDIT; else process.env.PG_MOD_AUDIT = old
    await rm(directory, { recursive: true })
  }
})

test('real tool start produces running state; execution failure is observed without error text', async () => {
  const h = await hookHarness()
  let release
  const result = h.callbacks.get('tool.call')(h.$, { tool: 'Bash' }, () => new Promise(resolve => { release = resolve }))
  while (!release) await new Promise(resolve => setImmediate(resolve))
  assert.equal(pipeline(projectAudit(h.rows()))[1].status, 'running')
  release({ result: 'safe output', context: [] })
  await result
  assert.equal(pipeline(projectAudit(h.rows()))[1].status, 'success')
  let failed = false
  try { await h.callbacks.get('tool.call')(h.$, { tool: `mcp__${synthetic}` }, async () => { throw new Error(synthetic) }) } catch (error) { failed = true; assert.equal(error.message.includes(synthetic), false) }
  assert.ok(failed)
  assert.equal(pipeline(projectAudit(h.rows()))[1].status, 'error')
  assert.equal(JSON.stringify(h.rows()).includes(synthetic), false)
})
