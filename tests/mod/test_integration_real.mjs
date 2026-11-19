// Where the Mod-side PRs meet (eval/integration-1118), with the real detector worker:
// - #23 filters x re-mask list: a value the filters remove never enters the Native Mod's re-mask list.
// - #24 PG_REMASK_SHORT=boundary x #26 sql-password: a 3-character SQL password is re-masked only as a word.
// - #25 guide and launcher placeholders x detector, filters and re-mask: none of them is a candidate or re-masked.
// Run: node --test tests/mod/test_integration_real.mjs. Skipped when the project's Python is not installed.
// Synthetic values only; nothing here prints them.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, before, describe, test } from 'node:test'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const { maskSystemPromptArgs, detectorScan } = createRequire(import.meta.url)('../../src/launcher/system-prompt.cjs')
const ALL_ON = { PG_DETECTOR_FILTERS: 'on', PG_DETECTOR_FILTER_DUMMY: 'on', PG_RULE_HEX_KEY: 'on', PG_SHELL_POSITIONAL_MIN: '4' }
const ALL_OFF = { PG_DETECTOR_FILTERS: 'off', PG_DETECTOR_FILTER_DUMMY: 'off', PG_RULE_HEX_KEY: 'off', PG_SHELL_POSITIONAL_MIN: '1' }
const SQL_SHORT = 'q7Z'
const APPENDED = 'SYNTHintegAppend_4qM8vK2pR7xN5sL9'
const children = []
const workers = {}

const freePort = () => new Promise((resolve, reject) => {
  const probe = net.createServer()
  probe.once('error', reject)
  probe.listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close(() => resolve(port)) })
})

async function startWorker(env) {
  const port = await freePort()
  children.push(spawn(PYTHON, [path.join(ROOT, 'src/detector/worker.py')], {
    cwd: ROOT, env: { ...process.env, ...env, PG_DETECTOR_PORT: String(port), PG_DETECTOR_DISABLE: 'gitleaks', PYTHONIOENCODING: 'utf-8' }, stdio: 'ignore', windowsHide: true,
  }))
  const url = `http://127.0.0.1:${port}`
  for (let attempt = 0; attempt < 900; attempt++) {
    try { if ((await fetch(`${url}/ready`)).ok) return url } catch { /* not up yet */ }
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error('detector worker not ready')
}

async function scanBatch(url, items) {
  const response = await fetch(`${url}/scan-batch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request_id: 'r', items }) })
  return response.json()
}

// The Native Mod with its MCP detector call wired to a real worker, as the MCP bridge does.
async function load(url, env = {}, files = {}) {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const $ = {
    env: { get: async key => env[key] ?? null },
    fs: { read: async file => { if (!(file in files)) throw new Error('ENOENT'); return files[file] }, write: async (file, text) => { files[file] = text } },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(await scanBatch(url, args.items)) }] }) },
  }
  return { hooks, $ }
}

async function read(hooks, $, content) {
  const result = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 't', file_path: 'x' }, () => ({ result: { type: 'text', file: { content } } }))
  return result.result.file.content
}

const findingsAndFiltered = item => [item.findings.length, Object.values(item.filtered || {}).reduce((a, b) => a + b, 0)]

describe('integration: Mod, detector filters, re-mask floor and the gaps fixes', { skip: !fs.existsSync(PYTHON) }, () => {
  before(async () => {
    [workers.on, workers.off] = await Promise.all([startWorker(ALL_ON), startWorker(ALL_OFF)])
  })
  after(() => { for (const child of children) child.kill() })

  test('#23 x re-mask: a value the filters remove is never re-masked later', async () => {
    for (const [line, later] of [['password = self.password', 'print(self.password)'], ['token = get_token()', 'x = get_token()  # retry']]) {
      const on = await load(workers.on)
      assert.equal(await read(on.hooks, on.$, line), line, 'filters on: not a finding')
      assert.equal(await read(on.hooks, on.$, later), later, 'filters on: not in the re-mask list')
      const off = await load(workers.off)
      assert.notEqual(await read(off.hooks, off.$, line), line, 'filters off: the rule finds it (so on is what keeps it out)')
      assert.notEqual(await read(off.hooks, off.$, later), later, 'filters off: re-masked at the later use')
    }
  })

  test('#24 boundary x #26 sql-password: a 3-character value is re-masked only as a word', async () => {
    const statement = `ALTER USER app_rw WITH PASSWORD '${SQL_SHORT}';`
    const later = `use ${SQL_SHORT} now; x${SQL_SHORT}y; ${SQL_SHORT}_tmp`
    const boundary = await load(workers.on, { PG_REMASK_SHORT: 'boundary' })
    const masked = await read(boundary.hooks, boundary.$, statement)
    const placeholder = masked.match(/\[PASSWORD_\d+\]/)?.[0]
    assert.ok(placeholder && !masked.includes(SQL_SHORT), 'sql-password found the 3-character value')
    assert.equal(await read(boundary.hooks, boundary.$, later), `use ${placeholder} now; x${SQL_SHORT}y; ${SQL_SHORT}_tmp`)
    const substring = await load(workers.on, { PG_REMASK_SHORT: 'substring' })
    await read(substring.hooks, substring.$, statement)
    assert.equal(await read(substring.hooks, substring.$, later), `use ${placeholder} now; x${placeholder}y; ${placeholder}_tmp`, 'substring: today, inside words too')
  })

  test('#25 guide: not a candidate, not filtered, not re-masked', async () => {
    const { hooks, $ } = await load(workers.on, { PG_PLACEHOLDER_GUIDE: 'on', PG_RESTORE_ESCAPED: 'on', PG_REMASK_SHORT: 'boundary' })
    await read(hooks, $, `DB_PASSWORD=SynthGuide.Pass9q\nALTER USER a WITH PASSWORD '${SQL_SHORT}';`) // some values in the re-mask list
    const composed = await hooks['prompt.compose']($, { model: 'm', tools: [], traits: [] }, async () => ({ sections: [{ id: 'intro', text: 'You are Claude.', scope: 'shared' }] }))
    const guide = composed.sections.find(section => section.id === 'promptguard:placeholder-guide').text
    for (const url of [workers.on, workers.off]) {
      const [item] = (await scanBatch(url, [{ id: 0, text: guide, source: 'outbound' }])).items
      assert.deepEqual(findingsAndFiltered(item), [0, 0])
    }
    assert.equal(await read(hooks, $, guide), guide)
  })

  test('#25 launcher placeholders: the masked system prompt is not a candidate, not filtered, not re-masked', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-integ-'))
    const seedFile = path.join(dir, 'seed.json')
    const { args } = await maskSystemPromptArgs(['--append-system-prompt', `Deploy with API_KEY=${APPENDED} when asked.`], { scan: detectorScan(workers.on), seedFile, workDir: dir })
    const prompt = args[1]
    assert.ok(/\[[A-Z_]+_\d+\]/.test(prompt) && !prompt.includes(APPENDED))
    for (const url of [workers.on, workers.off]) {
      const [item] = (await scanBatch(url, [{ id: 0, text: prompt, source: 'outbound' }])).items
      assert.deepEqual(findingsAndFiltered(item), [0, 0])
    }
    const files = { 'seed.json': fs.readFileSync(seedFile, 'utf8') }
    const { hooks, $ } = await load(workers.on, { PG_MOD_SEED_FILE: 'seed.json', PG_REMASK_SHORT: 'boundary' }, files)
    assert.equal(await read(hooks, $, prompt), prompt, 'the placeholder text is left as it is')
    assert.equal(await read(hooks, $, `again ${APPENDED}`), `again ${prompt.match(/\[[A-Z_]+_\d+\]/)[0]}`, 'the seeded value keeps its placeholder')
  })
})
