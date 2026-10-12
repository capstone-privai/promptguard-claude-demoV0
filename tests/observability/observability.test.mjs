import test from 'node:test'
import http from 'node:http'
import assert from 'node:assert/strict'
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { JSDOM } from 'jsdom'
import { projectAudit, projectGuardAudit } from '../../src/observability/model.mjs'
import { summarize, pipeline, sortRows } from '../../src/observability/public/view.mjs'
import { demo } from '../../src/observability/public/demo.mjs'

const synthetic = '[SYNTHETIC_INPUT_ONLY]'
const session = 'a'.repeat(64)
const row = (extra = {}) => ({ timestamp: '2026-10-11T00:00:00.000Z', session_id_hash: session, source: 'user_prompt', event: 'scan_completed', finding_count: 0, redacted_count: 0, scanned_payload_count: 1, ...extra })
const guardRow = (extra = {}) => ({ timestamp: '2026-10-11T00:00:01.000Z', session_hash: session, endpoint: '/v1/messages', body_size: 128, finding_count: 0, finding_types: [], decision: 'allow', reason: 'FORWARDED', scan_latency_ms: 1.25, upstream_status: 200, ...extra })

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

test('timestamp sorting is derived, stable, and leaves undated events at the end', () => {
  const rows = [{ timestamp: '2026-10-11T00:00:02.000Z' }, { timestamp: null }, { timestamp: '2026-10-11T00:00:01.000Z' }, { timestamp: undefined }]
  assert.deepEqual(sortRows(rows, 'newest').map(row => row.timestamp), ['2026-10-11T00:00:02.000Z', '2026-10-11T00:00:01.000Z', null, undefined])
  assert.deepEqual(sortRows(rows, 'oldest').map(row => row.timestamp), ['2026-10-11T00:00:01.000Z', '2026-10-11T00:00:02.000Z', null, undefined])
  assert.equal(rows[0].timestamp, '2026-10-11T00:00:02.000Z')
})

test('Final Guard audit projects provider-bound SAFE/BLOCKED decisions without raw fields', () => {
  const [safe, blocked, invalid] = projectGuardAudit([
    guardRow({ raw_secret: synthetic, authorization: synthetic }),
    guardRow({ decision: 'block', reason: 'DETECTOR_FINDINGS', finding_count: 2, finding_types: ['PASSWORD', 'TOKEN'], upstream_status: null }),
    guardRow({ decision: 'allow', finding_count: 1, finding_types: ['NOT_ALLOWED'], endpoint: synthetic, reason: synthetic, session_hash: synthetic }),
  ])
  assert.equal(safe.decision, 'SAFE')
  assert.equal(safe.upstreamStatus, 200)
  assert.equal(blocked.decision, 'BLOCKED')
  assert.deepEqual(blocked.findingTypes, ['PASSWORD', 'TOKEN'])
  assert.equal(invalid.decision, 'NOT VERIFIED')
  assert.equal(invalid.endpoint, 'UNKNOWN')
  assert.equal(invalid.reason, null)
  assert.equal(invalid.session, 'unavailable')
  assert.equal(JSON.stringify([safe, blocked, invalid]).includes(synthetic), false)
  assert.throws(() => projectGuardAudit(null), /GUARD_AUDIT_UNAVAILABLE/)
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
    const guards = projectGuardAudit([guardRow()])
    globalThis.fetch = async () => ({ ok: true, json: async () => ({ mode: 'LIVE', events, guards }) })
    for (const method of methods) console[method] = (...args) => logs.push(args)
    await import(`../../src/observability/public/app.mjs?test=${Math.random()}`)
    const text = dom.window.document.body.textContent
    assert.equal(text.includes(synthetic), false)
    assert.equal(text.includes('undefined'), false)
    assert.equal(text.includes('null'), false)
    assert.equal(dom.window.localStorage.length, 0)
    assert.equal(dom.window.sessionStorage.length, 0)
    assert.ok(text.includes('Final Guard'))
    assert.ok(text.includes('200'))
    const mode = dom.window.document.getElementById('mode')
    mode.value = 'DEMO'; mode.dispatchEvent(new dom.window.Event('change'))
    assert.ok(dom.window.document.getElementById('notice').textContent.includes('DEMO / MOCK'))
    const findings = dom.window.document.getElementById('findings')
    const change = (id, value) => { const control = dom.window.document.getElementById(id); control.value = value; control.dispatchEvent(new dom.window.Event('change')) }
    change('scenario', 'multiple')
    assert.equal(findings.querySelectorAll('.finding').length, 3)
    assert.ok(dom.window.document.getElementById('preview').textContent.includes('[API_KEY_1]'))
    assert.ok(dom.window.document.getElementById('preview').textContent.includes('[PASSWORD_1]'))
    assert.equal(dom.window.document.getElementById('preview').querySelectorAll('.preview-row:not(.preview-heading)').length, 3)
    change('filter-type', 'PASSWORD')
    assert.equal(findings.querySelectorAll('.finding').length, 2)
    change('filter-source', 'FILE_READ')
    change('filter-detector', 'CredSweeper')
    change('filter-action', 'MASK')
    assert.equal(findings.querySelectorAll('.finding').length, 2)
    change('filter-type', 'API_KEY')
    assert.equal(findings.querySelectorAll('.finding').length, 0)
    assert.ok(findings.textContent.includes('조건에 맞는 탐지 결과가 없습니다'))
    change('filter-source', '*')
    dom.window.document.getElementById('clear-filters').click()
    assert.equal(findings.querySelectorAll('.finding').length, 3)
    change('finding-sort', 'oldest')
    assert.equal(findings.querySelector('.finding strong').textContent, 'API 키 (API_KEY)')
    change('timeline-sort', 'newest')
    assert.match(dom.window.document.querySelector('#timeline .event').dataset.event, /2/)
    change('timeline-sort', 'oldest')
    assert.match(dom.window.document.querySelector('#timeline .event').dataset.event, /0/)
    change('scenario', 'empty')
    assert.ok(findings.textContent.includes('기록된 상세 탐지 결과가 없습니다'))
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
  const guardFile = path.join(directory, 'guard-audit.jsonl')
  const old = process.env.PG_MOD_AUDIT
  const oldGuard = process.env.PG_GUARD_AUDIT
  process.env.PG_MOD_AUDIT = file
  process.env.PG_GUARD_AUDIT = guardFile
  const { createServer } = await import(`../../src/observability/server.mjs?test=${Math.random()}`)
  const server = createServer()
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const url = `http://127.0.0.1:${server.address().port}`
  try {
    await writeFile(file, JSON.stringify([row({ raw_secret: synthetic })]))
    await writeFile(guardFile, `${JSON.stringify(guardRow({ raw_secret: synthetic }))}\n`)
    const response = await fetch(`${url}/api/events`)
    assert.equal(response.status, 200)
    const responseText = await response.text()
    assert.equal(responseText.includes(synthetic), false)
    const responseValue = JSON.parse(responseText)
    assert.equal(responseValue.guards[0].decision, 'SAFE')
    assert.equal(responseValue.guards[0].upstreamStatus, 200)
    assert.equal((await fetch(`${url}/api/events`, { headers: { origin: 'https://example.com' } })).status, 403)
    assert.equal(await new Promise(resolve => http.get(`${url}/api/events`, { headers: { host: 'example.com' } }, response => { response.resume(); resolve(response.statusCode) })), 403)
    assert.equal((await fetch(`${url}/api/events`, { method: 'POST' })).status, 403)
    await writeFile(guardFile, `${synthetic}\n`)
    const missingGuard = await fetch(`${url}/api/events`)
    assert.equal(missingGuard.status, 200)
    assert.equal((await missingGuard.json()).guardUnavailable, true)
    await writeFile(file, synthetic)
    const failed = await fetch(`${url}/api/events`)
    assert.equal(failed.status, 503)
    assert.equal((await failed.text()).includes(synthetic), false)
  } finally {
    await new Promise(resolve => server.close(resolve))
    if (old === undefined) delete process.env.PG_MOD_AUDIT; else process.env.PG_MOD_AUDIT = old
    if (oldGuard === undefined) delete process.env.PG_GUARD_AUDIT; else process.env.PG_GUARD_AUDIT = oldGuard
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
