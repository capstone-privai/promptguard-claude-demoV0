'use strict'

// PG_DETECTOR_FILTERS with the real detector: the Native Mod's worker and the Final Guard's worker run the same
// pgdetector, so with the same setting they judge the same text the same way. A value the Mod's filters let
// through must not be blocked by the Guard (422), and a real secret is still masked by the Mod and blocked
// by the Guard when it arrives raw. Skipped when the project's Python is not installed. Synthetic values only.
const assert = require('node:assert/strict')
const fs = require('node:fs')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const { spawn } = require('node:child_process')
const { pathToFileURL } = require('node:url')
const { after, before, describe, test } = require('node:test')

const ROOT = path.resolve(__dirname, '..', '..')
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const SECRET = 'SYNTHx7Qk2mR9vL4wPz!q'
// Lines whose value is a false positive by structure, each one shape of the stage-0 fp_types.
const NOISE = [
  'password = self.password',
  'token = get_token()',
  'password = &lt;/p&gt;',
  'api_key = attributes[',
  'secret = {{ secrets.DEPLOY_KEY }}',
  'password: <pre><code>',
]
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

async function scanBatch(url, items) {
  const response = await fetch(`${url}/scan-batch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request_id: 'r', items }) })
  return response.json()
}

describe('detector filters on: Native Mod and Final Guard agree', { skip: !fs.existsSync(PYTHON) }, () => {
  let modUrl
  let guardDetectorUrl
  let guardUrl
  let upstreamUrl
  const shared = { PG_DETECTOR_FILTERS: 'on', PG_DETECTOR_FILTER_DUMMY: 'on', PG_DETECTOR_DISABLE: 'gitleaks', PYTHONIOENCODING: 'utf-8' }

  before(async () => {
    const [mod, guardDetector, upstream, guard] = [await freePort(), await freePort(), await freePort(), await freePort()]
    start(PYTHON, [path.join(ROOT, 'src', 'detector', 'worker.py')], { ...shared, PG_DETECTOR_PORT: String(mod) })
    start(PYTHON, [path.join(ROOT, 'src', 'detector', 'worker.py')], { ...shared, PG_DETECTOR_PORT: String(guardDetector) })
    modUrl = `http://127.0.0.1:${mod}`
    guardDetectorUrl = `http://127.0.0.1:${guardDetector}`
    await Promise.all([waitOk(`${modUrl}/ready`), waitOk(`${guardDetectorUrl}/ready`)])
    start(process.execPath, [path.join(ROOT, 'tests', 'final-guard', 'mock-upstream.cjs')], { PG_MOCK_UPSTREAM_PORT: String(upstream) })
    upstreamUrl = `http://127.0.0.1:${upstream}`
    await waitOk(`${upstreamUrl}/__status`)
    start(process.execPath, [path.join(ROOT, 'src', 'guard', 'final-guard.cjs')], {
      ...shared,
      PG_GUARD_PORT: String(guard),
      PG_UPSTREAM_BASE_URL: upstreamUrl,
      PG_GUARD_DETECTOR_URL: guardDetectorUrl,
      PG_DETECTOR_TIMEOUT_MS: '20000',
      PG_AUDIT_PATH: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pg-filters-')), 'audit.jsonl'),
      PG_SESSION_HASH: 'ab'.repeat(16),
    })
    guardUrl = `http://127.0.0.1:${guard}`
    await waitOk(`${guardUrl}/health`)
  }, { timeout: 120_000 })

  after(() => { for (const child of children) child.kill() })

  test('both workers give the same findings and filter counts for the same text', async () => {
    const texts = [...NOISE, `password = ${SECRET}`, NOISE.join('\n')]
    const modSide = await scanBatch(modUrl, texts.map((text, id) => ({ id, text, source: 'tool_result' })))
    const guardSide = await scanBatch(guardDetectorUrl, texts.map((text, id) => ({ id, text, source: 'outbound' })))
    const shape = result => result.items.map(item => ({ findings: item.findings.map(f => [f.start, f.end, f.type]), filtered: item.filtered }))
    assert.deepEqual(shape(modSide), shape(guardSide))
    assert.equal(modSide.items.at(-2).finding_count, 1, 'the real secret is still found')
    assert.ok(Object.keys(modSide.items.at(-1).filtered).length > 0, 'the noise was filtered, by name')
  })

  test('what the Mod lets through, the Guard forwards; a raw secret is still blocked', async () => {
    const { register } = await import(`${pathToFileURL(path.join(ROOT, 'src', 'native-mod', 'hooks', 'register.mjs')).href}?case=${Math.random()}`)
    const hooks = {}
    register((name, handler) => { hooks[name] = handler; return { catch() {} } })
    const $ = {
      env: { get: async () => null },
      fs: { write: async () => {}, read: async file => fs.readFileSync(file, 'utf8') },
      plugin: { root: path.join(ROOT, 'src', 'native-mod') },
      mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(await scanBatch(modUrl, args.items)) }] }) },
    }
    let sent
    const prompt = [...NOISE, `password = ${SECRET}`].join('\n')
    await hooks['prompt.submit']($, { text: prompt, context: [] }, e => { sent = e; return e })
    assert.ok(!sent.text.includes(SECRET), 'the Mod masked the real secret')
    assert.ok(sent.text.includes('self.password') && sent.text.includes('get_token()'), 'the Mod left the noise alone')

    const send = text => fetch(`${guardUrl}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ messages: [{ role: 'user', content: text }] }) })
    assert.equal((await send(sent.text)).status, 200)
    assert.equal((await send(prompt)).status, 422)
  })
})
