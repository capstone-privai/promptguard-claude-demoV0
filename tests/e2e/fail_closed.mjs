// E2E: when the Mod's detector call fails, does raw text still reach the provider?
// Runs the real Claude Code CLI with the Native Mod against a fake Anthropic API that records every
// request. The prompt and a Read result carry a synthetic secret.
// Run from the repository root after install: node tests/e2e/fail_closed.mjs
// PG_E2E_PLUGIN_DIR points at another copy of src/native-mod (e.g. the code before this fix).
// PG_E2E_DEBUG=1 writes each run's Claude Code debug log beside its evidence.
// PG_E2E_CLAUDE is the Claude Code binary (default `claude`); the Mod targets 2.1.291.
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const CLAUDE = process.env.PG_E2E_CLAUDE || 'claude'
const PLUGIN = process.env.PG_E2E_PLUGIN_DIR || path.join(ROOT, 'src/native-mod')
const RAW = 'SynthE2ePass!2026q' // synthetic fixture value
const BLOCKED = '[PROMPTGUARD_BLOCKED: detector failure]'
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const OUT = path.join(ROOT, '.runtime', 'e2e-fail-closed')
const MODEL = 'claude-sonnet-4-5-20250929'

const SCENARIOS = {
  // The README case: scan_batch is not an allowed tool, so headless mode refuses $.mcp.call.
  permission_denied: { allowScan: false, detector: 'up', blocked: true },
  // The bridge answers isError: the worker is not listening.
  detector_down: { allowScan: true, detector: 'down', blocked: true },
  // Control: a working detector masks, nothing is blocked.
  healthy: { allowScan: true, detector: 'up', blocked: false },
}

function sse(res, id, blocks, stop) {
  res.writeHead(200, { 'content-type': 'text/event-stream' })
  const w = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  w('message_start', { type: 'message_start', message: { id, type: 'message', role: 'assistant', content: [], model: MODEL, stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } })
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

function startProvider(workspace) {
  const requests = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      let body = null
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch {}
      requests.push({ method: req.method, url: req.url, body })
      const id = `msg_${requests.length}`
      if (!req.url.startsWith('/v1/messages') || !body?.messages) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{}') }
      if (!(body.tools || []).some(t => t.name === 'Read')) {
        if (!body.stream) {
          res.writeHead(200, { 'content-type': 'application/json' })
          return res.end(JSON.stringify({ id, type: 'message', role: 'assistant', model: body.model, content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } }))
        }
        return sse(res, id, [{ type: 'text', text: 'ok' }], 'end_turn')
      }
      if (JSON.stringify(body.messages.at(-1).content).includes('toolu_read_env')) return sse(res, id, [{ type: 'text', text: 'Finished.' }], 'end_turn')
      return sse(res, id, [{ type: 'tool_use', id: 'toolu_read_env', name: 'Read', input: { file_path: path.join(workspace, '.env') } }], 'tool_use')
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, requests, port: server.address().port })))
}

function run(command, args, options) {
  return new Promise(resolve => {
    const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'], shell: process.platform === 'win32' })
    let stdout = ''
    child.stdout.on('data', d => { stdout += d })
    child.stderr.on('data', () => {})
    child.on('close', code => resolve({ code, stdout }))
  })
}

async function startDetector() {
  const port = 30001 + Math.floor(Math.random() * 5000)
  const child = spawn(PYTHON, [path.join(ROOT, 'src/detector/worker.py')], { cwd: ROOT, env: { ...process.env, PG_DETECTOR_PORT: String(port), PG_DETECTOR_MODE: 'normal' }, stdio: 'ignore' })
  const url = `http://127.0.0.1:${port}`
  for (let i = 0; i < 300; i++) {
    try { if ((await fetch(`${url}/health`)).ok) return { child, url } } catch {}
    await new Promise(r => setTimeout(r, 100))
  }
  child.kill()
  throw new Error('Detector worker failed to start')
}

async function runScenario(name, scenario, detector) {
  const dir = path.join(OUT, name)
  fs.rmSync(dir, { recursive: true, force: true })
  const workspace = path.join(dir, 'ws')
  fs.mkdirSync(workspace, { recursive: true })
  fs.writeFileSync(path.join(workspace, '.env'), `DB_HOST=demo-db.internal\nDB_PASSWORD=${RAW}\n`)
  const mcpConfig = path.join(dir, 'mcp.json')
  fs.writeFileSync(mcpConfig, JSON.stringify({ mcpServers: { pgdetector: { command: 'node', args: [path.join(ROOT, 'src/detector/mcp-bridge.cjs')] } } }))

  const provider = await startProvider(workspace)
  const env = { ...process.env }
  for (const key of ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_SESSION_ID']) delete env[key]
  Object.assign(env, {
    CLAUDE_CONFIG_DIR: path.join(dir, 'claude-config'),
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${provider.port}`,
    ANTHROPIC_API_KEY: 'sk-ant-e2e-dummy',
    NO_PROXY: '127.0.0.1,localhost',
    no_proxy: '127.0.0.1,localhost',
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
    CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '1',
    PG_DETECTOR_URL: scenario.detector === 'up' ? detector.url : 'http://127.0.0.1:9',
    PG_SESSION_HASH: 'e2e',
    PG_MOD_CONNECT_WAIT_MS: '2000',
    PG_MOD_AUDIT: path.join(dir, 'audit.json'),
  })
  const allowed = scenario.allowScan ? 'Read,mcp__pgdetector__scan_batch' : 'Read'
  const args = ['-p', `"Check .env. My DB_PASSWORD=${RAW}"`, '--plugin-dir', PLUGIN, '--mcp-config', mcpConfig, '--allowedTools', allowed, '--output-format', 'json', '--model', MODEL]
  if (process.env.PG_E2E_DEBUG) args.push('--debug-file', path.join(dir, 'debug.log'))
  const result = await run(CLAUDE, args, { cwd: workspace, env })
  provider.server.close()
  fs.writeFileSync(path.join(dir, 'provider-requests.json'), JSON.stringify(provider.requests, null, 2))

  const bodies = provider.requests.map(r => JSON.stringify(r.body ?? ''))
  const main = provider.requests.filter(r => r.body?.messages && (r.body.tools || []).some(t => t.name === 'Read')).map(r => JSON.stringify(r.body))
  const audit = fs.existsSync(path.join(dir, 'audit.json')) ? fs.readFileSync(path.join(dir, 'audit.json'), 'utf8') : '[]'
  const failedRows = JSON.parse(audit).filter(row => row.event === 'scan_failed').length
  const configDir = path.join(dir, 'claude-config')
  const rows = (fs.existsSync(configDir) ? fs.readdirSync(configDir, { recursive: true }) : [])
    .filter(f => String(f).endsWith('.jsonl'))
    .flatMap(f => fs.readFileSync(path.join(configDir, f), 'utf8').split('\n').filter(Boolean))
  // Claude Code writes the -p prompt to a `queue-operation` row before prompt.submit runs, with or
  // without this fix; no hook sees that row. Reported apart from the checks.
  const queued = rows.filter(row => row.includes('"type":"queue-operation"'))
  if (queued.some(row => row.includes(RAW))) console.log(`NOTE ${name}: raw -p prompt in a queue-operation transcript row (engine-side, no hook sees it)`)
  const checks = {
    claude_exit_0: result.code === 0,
    provider_got_main_requests: main.length > 0,
    no_raw_in_any_provider_request: !bodies.some(b => b.includes(RAW)),
    no_raw_in_transcript_messages: !rows.filter(row => !queued.includes(row)).some(row => row.includes(RAW)),
    no_raw_in_audit: !audit.includes(RAW),
  }
  if (scenario.blocked) {
    checks.block_marker_in_provider_request = main.some(b => b.includes(BLOCKED))
    checks.audit_has_scan_failed = failedRows > 0
  } else {
    checks.no_block_marker = !bodies.some(b => b.includes(BLOCKED))
    checks.prompt_masked_with_placeholder = main.some(b => /\[PASSWORD_\d+\]/.test(b))
  }
  return checks
}

const { stdout: version } = await run(CLAUDE, ['--version'], {})
console.log(`Claude Code ${version.trim()}; plugin ${path.relative(ROOT, PLUGIN) || PLUGIN}`)
const detector = await startDetector()
let failed = 0
try {
  for (const [name, scenario] of Object.entries(SCENARIOS)) {
    const checks = await runScenario(name, scenario, detector)
    for (const [check, ok] of Object.entries(checks)) {
      if (!ok) failed++
      console.log(`${ok ? 'PASS' : 'FAIL'} ${name}: ${check}`)
    }
  }
} finally {
  detector.child.kill()
}
process.exit(failed ? 1 : 0)
