// E2E on the real Claude Code CLI: context the engine assembles itself (CLAUDE.md, @imports, output styles, skills,
// slash commands, MCP server instructions). One synthetic secret per source, three runs each:
//   probe  - a probe Mod records which hooks carry the value (hook names only)
//   mod    - the PromptGuard Mod alone: does the raw value reach the API, and in which request field
//   guard  - Mod + Final Guard (promptguard run): does the session go on, and does anything raw get through
//   guard_only - Final Guard without the Mod: what the session does when the Guard has to refuse the value
// Run from the repository root after install:  node tests/e2e/contexts.mjs
// Synthetic values only; nothing here prints them.
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const OUT = path.join(ROOT, '.runtime', 'e2e-contexts')
const MODEL = 'claude-sonnet-4-5-20250929'
const SUFFIX = 'q7Lm2Xv9Kp4Rz8Nw'
const ONLY = process.env.PG_E2E_CONTEXTS ? process.env.PG_E2E_CONTEXTS.split(',') : null

const freePort = () => new Promise((resolve, reject) => {
  const probe = net.createServer()
  probe.once('error', reject)
  probe.listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close(() => resolve(port)) })
})

function run(command, args, options) {
  return new Promise(resolve => {
    const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    child.stdout.on('data', d => { stdout += d })
    child.stderr.on('data', () => {})
    child.on('close', code => resolve({ code, stdout }))
  })
}

async function waitOk(url) {
  for (let i = 0; i < 600; i++) {
    try { if ((await fetch(url)).ok) return } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 100))
  }
  throw new Error(`not ready: ${url}`)
}

function sse(res, blocks, stop) {
  res.writeHead(200, { 'content-type': 'text/event-stream' })
  const w = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  w('message_start', { type: 'message_start', message: { id: 'm', type: 'message', role: 'assistant', content: [], model: MODEL, stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } })
  blocks.forEach((b, index) => {
    if (b.type === 'text') {
      w('content_block_start', { type: 'content_block_start', index, content_block: { type: 'text', text: '' } })
      w('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'text_delta', text: b.text } })
    } else {
      w('content_block_start', { type: 'content_block_start', index, content_block: { type: 'tool_use', id: b.id, name: b.name, input: {} } })
      w('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'input_json_delta', partial_json: JSON.stringify(b.input) } })
    }
    w('content_block_stop', { type: 'content_block_stop', index })
  })
  w('message_delta', { type: 'message_delta', delta: { stop_reason: stop, stop_sequence: null }, usage: { output_tokens: 5 } })
  w('message_stop', { type: 'message_stop' })
  res.end()
}

function startProvider(plan) {
  const requests = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      const body = raw ? JSON.parse(raw) : null
      requests.push({ url: req.url, raw, body })
      if (!req.url.startsWith('/v1/messages') || req.url.includes('count_tokens')) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ input_tokens: 10, data: [] }))
      }
      const step = (body.tools || []).length ? plan(body) : null
      if (!body.stream) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ id: 'm', type: 'message', role: 'assistant', model: body.model, content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } }))
      }
      return step ? sse(res, ...step) : sse(res, [{ type: 'text', text: 'Finished.' }], 'end_turn')
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, requests, url: `http://127.0.0.1:${server.address().port}` })))
}

async function startWorker() {
  const port = await freePort()
  const child = spawn(PYTHON, [path.join(ROOT, 'src/detector/worker.py')], { cwd: ROOT, env: { ...process.env, PG_DETECTOR_PORT: String(port), PYTHONIOENCODING: 'utf-8' }, stdio: 'ignore' })
  const url = `http://127.0.0.1:${port}`
  await waitOk(`${url}/ready`)
  return { child, url }
}

async function startGuard(detectorUrl, upstreamUrl, dir) {
  const port = await freePort()
  const child = spawn(process.execPath, [path.join(ROOT, 'src/guard/final-guard.cjs')], {
    cwd: ROOT,
    env: { ...process.env, PG_GUARD_PORT: String(port), PG_UPSTREAM_BASE_URL: upstreamUrl, PG_GUARD_DETECTOR_URL: detectorUrl, PG_DETECTOR_TIMEOUT_MS: '30000', PG_AUDIT_PATH: path.join(dir, 'guard-audit.jsonl'), PG_SESSION_HASH: 'ab'.repeat(16) },
    stdio: 'ignore',
  })
  const url = `http://127.0.0.1:${port}`
  await waitOk(`${url}/health`)
  return { child, url }
}

const write = (file, text) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text) }

// Calls the Skill tool once, whatever its input field is called in this engine version.
const invokeSkill = name => body => {
  if (JSON.stringify(body.messages).includes('toolu_skill')) return null
  const tool = (body.tools || []).find(t => t.name === 'Skill')
  if (!tool) return null
  const field = tool.input_schema?.required?.[0] || 'skill'
  return [[{ type: 'tool_use', id: 'toolu_skill', name: 'Skill', input: { [field]: name } }], 'tool_use']
}

// Each source writes its files and returns extra CLI arguments, MCP servers and the prompt.
const SOURCES = {
  claude_md_project: { setup: ({ ws }, line) => write(path.join(ws, 'CLAUDE.md'), `# Project\n${line}\n`) },
  claude_md_user: { setup: ({ cfg }, line) => write(path.join(cfg, 'CLAUDE.md'), `# User notes\n${line}\n`) },
  claude_md_local: { setup: ({ ws }, line) => write(path.join(ws, 'CLAUDE.local.md'), `# Local\n${line}\n`) },
  claude_md_import: {
    setup: ({ ws }, line) => {
      write(path.join(ws, 'CLAUDE.md'), '# Project\nDeploy notes: @docs/deploy-notes.md\n')
      write(path.join(ws, 'docs', 'deploy-notes.md'), `${line}\n`)
    },
  },
  output_style: {
    setup: ({ ws }, line) => {
      write(path.join(ws, '.claude', 'output-styles', 'probe-style.md'), `---\nname: Probe Style\ndescription: Terse deploy answers\n---\nAnswer tersely. ${line}\n`)
      write(path.join(ws, '.claude', 'settings.json'), JSON.stringify({ outputStyle: 'Probe Style' }))
    },
  },
  skill_body: {
    setup: ({ ws }, line) => write(path.join(ws, '.claude', 'skills', 'probe-skill', 'SKILL.md'), `---\nname: probe-skill\ndescription: Deploy helper for this project\n---\nDeploy steps. ${line}\n`),
    plan: invokeSkill('probe-skill'),
  },
  skill_description: {
    setup: ({ ws }, line) => write(path.join(ws, '.claude', 'skills', 'probe-skill', 'SKILL.md'), `---\nname: probe-skill\ndescription: Deploy helper, ${line}\n---\nDeploy steps.\n`),
  },
  slash_command: {
    setup: ({ ws }, line) => write(path.join(ws, '.claude', 'commands', 'probe-cmd.md'), `Deploy the service. ${line}\n`),
    prompt: '/probe-cmd',
  },
  mcp_instructions: {
    setup: (_dirs, line) => ({ mcp: { probe: { command: process.execPath, args: [path.join(ROOT, 'tests/e2e/fixtures/mcp-instructions.cjs')], env: { PG_PROBE_MCP_INSTRUCTIONS: `Server notes. ${line}` } } } }),
  },
}

async function session(source, mode, worker) {
  const value = `SYNTHctx${source.replace(/_/g, '')}${SUFFIX}`
  const dir = path.join(OUT, source, mode)
  fs.rmSync(dir, { recursive: true, force: true })
  const ws = path.join(dir, 'ws')
  const cfg = path.join(dir, 'cfg')
  fs.mkdirSync(ws, { recursive: true })
  fs.mkdirSync(cfg, { recursive: true })
  const spec = SOURCES[source]
  const extra = spec.setup({ ws, cfg }, `API_KEY=${value}`) || {}
  const provider = await startProvider(spec.plan || (() => null))
  const front = mode.startsWith('guard') ? await startGuard(worker.url, provider.url, dir) : null
  const mcpConfig = path.join(dir, 'mcp.json')
  const servers = { ...(mode === 'probe' || mode === 'guard_only' ? {} : { pgdetector: { command: 'node', args: [path.join(ROOT, 'src/detector/mcp-bridge.cjs')] } }), ...(extra.mcp || {}) }
  fs.writeFileSync(mcpConfig, JSON.stringify({ mcpServers: servers }))
  const base = { ...process.env }
  for (const key of ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_SESSION_ID']) delete base[key]
  const plugin = mode === 'probe' || mode === 'guard_only' ? path.join(ROOT, 'tests/e2e/probe-mod') : path.join(ROOT, 'src/native-mod')
  const result = await run('claude', ['-p', spec.prompt || 'Do the task', '--plugin-dir', plugin, '--mcp-config', mcpConfig,
    '--allowedTools', 'Read', 'Skill', 'mcp__pgdetector__scan_batch', '--output-format', 'json', '--model', MODEL], {
    cwd: ws,
    env: {
      ...base, CLAUDE_CONFIG_DIR: cfg, ANTHROPIC_BASE_URL: front ? front.url : provider.url, ANTHROPIC_API_KEY: 'sk-ant-e2e-dummy',
      NO_PROXY: '127.0.0.1,localhost', no_proxy: '127.0.0.1,localhost', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '1',
      PG_DETECTOR_URL: worker.url, PG_SESSION_HASH: 'e2e', PG_MOD_AUDIT: path.join(dir, 'audit.json'),
      PG_PROBE_TAGS: value, PG_PROBE_LOG: path.join(dir, 'probe.json'),
    },
  })
  provider.server.close()
  front?.child.kill()
  const answer = (() => { try { return JSON.parse(result.stdout).result } catch { return null } })()
  const messages = provider.requests.filter(q => q.url.startsWith('/v1/messages') && !q.url.includes('count_tokens'))
  const fields = new Set()
  for (const q of provider.requests) {
    if (!q.raw.includes(value) || !q.body) continue
    for (const [key, item] of Object.entries(q.body)) if (JSON.stringify(item).includes(value)) fields.add(`${q.url.includes('count_tokens') ? 'count_tokens.' : ''}${key}`)
  }
  const probe = fs.existsSync(path.join(dir, 'probe.json')) ? JSON.parse(fs.readFileSync(path.join(dir, 'probe.json'), 'utf8')) : []
  const guardAudit = fs.existsSync(path.join(dir, 'guard-audit.jsonl')) ? fs.readFileSync(path.join(dir, 'guard-audit.jsonl'), 'utf8').trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)) : []
  const auditText = fs.existsSync(path.join(dir, 'audit.json')) ? fs.readFileSync(path.join(dir, 'audit.json'), 'utf8') : ''
  return {
    code: result.code,
    continued: result.code === 0 && answer === 'Finished.',
    // In the probe run: hooks whose input carried the value.
    hooks: probe.filter(row => row.endsWith(`|${value}`) && row.includes('|in|')).map(row => row.split('|')[0]),
    rawFields: [...fields].sort(),
    reachedModel: messages.length,
    blocked: guardAudit.filter(row => row.decision === 'block').length,
    rawInAudit: auditText.includes(value) || JSON.stringify(guardAudit).includes(value),
    scanFailed: auditText.includes('scan_failed'),
    message: String(answer ?? '').slice(0, 160).split(value).join('<RAW>'),
  }
}

const rows = {}
const checks = {}
const worker = await startWorker()
try {
  for (const source of Object.keys(SOURCES)) {
    if (ONLY && !ONLY.includes(source)) continue
    const probe = await session(source, 'probe', worker)
    const mod = await session(source, 'mod', worker)
    const guard = await session(source, 'guard', worker)
    const guardOnly = await session(source, 'guard_only', worker)
    rows[source] = { probe, mod, guard, guardOnly }
    checks[`${source}: guard_only_no_raw_reached_the_api`] = guardOnly.rawFields.length === 0
    // A detector failure would also keep the value out (fail closed), so the Mod run must have finished normally.
    checks[`${source}: mod_scans_ok`] = mod.continued && !mod.scanFailed
    checks[`${source}: guard_no_raw_reached_the_api`] = guard.rawFields.length === 0
    checks[`${source}: no_raw_in_audit`] = !mod.rawInAudit && !guard.rawInAudit
    // Whatever a hook carries, the Mod masks: with the Mod alone it must not reach the API.
    if (probe.hooks.length) checks[`${source}: seen_by_hooks_so_masked_with_mod_only`] = mod.rawFields.length === 0
  }
} finally {
  worker.child.kill()
}

const { stdout: version } = await run('claude', ['--version'], {})
console.log(`Claude Code ${version.trim()}`)
const cell = text => text.replace(/\|/g, '/').replace(/\n/g, ' ')
console.log('| source | request field it travels in (no Mod) | (a) hooks that carry it | (b) Mod only: raw reached the API in | Mod + Guard: continued / blocked | (c) Guard without Mod: continued / blocked | what the user saw (Guard without Mod) |')
console.log('|---|---|---|---|---|---|---|')
for (const [source, { probe, mod, guard, guardOnly }] of Object.entries(rows)) {
  console.log(`| ${source} | ${probe.rawFields.join(', ') || 'none'} | ${[...new Set(probe.hooks)].join(', ') || 'none'} | ${mod.rawFields.join(', ') || 'not reached'} | ${guard.continued} / ${guard.blocked} | ${guardOnly.continued} / ${guardOnly.blocked} | ${cell(guardOnly.message)} |`)
}
let failed = 0
for (const [name, ok] of Object.entries(checks)) {
  if (!ok) failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`)
}
console.log(failed ? `${failed} check(s) failed. Evidence: ${OUT}` : `All checks passed. Evidence: ${OUT}`)
process.exitCode = failed ? 1 : 0
