// E2E: does a placeholder restored in tool.call reach later provider requests?
// Runs the real Claude Code CLI with the Native Mod and the detector ensemble worker against a
// fake Anthropic API that records every request and plays the model's part.
// Run from the repository root after install: node tests/e2e/restore_history.mjs
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const RAW = 'MyS3cretPass!2026' // synthetic fixture value
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const OUT = path.join(ROOT, '.runtime', 'e2e-restore')
const MODEL = 'claude-sonnet-4-5-20250929'

const SCENARIOS = {
  // Restored value goes into a file; proves the command really ran with the raw value.
  file: { bash: ph => `printf '%s' '${ph}' > restored-proof.txt && echo written`, restore: 'on' },
  // Restored value is echoed alone, where CredSweeper has no key=value context to detect it.
  echo: { bash: ph => `printf '%s\\n' '${ph}'`, restore: 'on' },
  // Restore disabled: the command runs with the placeholder text itself.
  off: { bash: ph => `printf '%s' '${ph}' > restored-proof.txt && echo written`, restore: 'off' },
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

function startProvider(scenario, workspace) {
  const requests = []
  let placeholder = null
  let turn = 0
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      const body = raw ? JSON.parse(raw) : null
      requests.push({ url: req.url, body })
      const id = `msg_${requests.length}`
      if (!req.url.startsWith('/v1/messages') || req.url.includes('count_tokens')) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ input_tokens: 10, data: [] }))
      }
      if (!(body.tools || []).some(t => t.name === 'Bash')) {
        if (!body.stream) {
          res.writeHead(200, { 'content-type': 'application/json' })
          return res.end(JSON.stringify({ id, type: 'message', role: 'assistant', model: body.model, content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } }))
        }
        return sse(res, id, [{ type: 'text', text: 'ok' }], 'end_turn')
      }
      const last = JSON.stringify(body.messages.at(-1).content)
      if (last.includes('toolu_read_env')) {
        // The "model" reuses the placeholder it saw in the masked Read result.
        placeholder = last.match(/\[PASSWORD_\d+\]/)?.[0] ?? null
        return sse(res, id, [{ type: 'tool_use', id: 'toolu_bash_restore', name: 'Bash', input: { command: scenario.bash(placeholder ?? '[PASSWORD_MISSING]'), description: 'use the password' } }], 'tool_use')
      }
      if (last.includes('toolu_bash_restore')) return sse(res, id, [{ type: 'text', text: 'Finished.' }], 'end_turn')
      if (turn++ === 0) return sse(res, id, [{ type: 'tool_use', id: 'toolu_read_env', name: 'Read', input: { file_path: path.join(workspace, '.env') } }], 'tool_use')
      return sse(res, id, [{ type: 'text', text: 'Second turn reply.' }], 'end_turn')
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, requests, port: server.address().port, placeholder: () => placeholder })))
}

function run(command, args, options) {
  return new Promise(resolve => {
    const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => { stdout += d })
    child.stderr.on('data', d => { stderr += d })
    child.on('close', code => resolve({ code, stdout, stderr }))
  })
}

async function startDetector() {
  const port = 30001 + Math.floor(Math.random() * 5000)
  const env = { ...process.env, PG_DETECTOR_PORT: String(port), PG_DETECTOR_MODE: 'normal' }
  const child = spawn(PYTHON, [path.join(ROOT, 'src/detector/worker.py')], { cwd: ROOT, env, stdio: 'ignore' })
  const url = `http://127.0.0.1:${port}`
  for (let i = 0; i < 200; i++) {
    try { if ((await fetch(`${url}/health`)).ok) return { child, url } } catch {}
    await new Promise(r => setTimeout(r, 100))
  }
  child.kill()
  throw new Error('Detector worker failed to start')
}

function bashBlocks(body) {
  const out = { toolUse: null, toolResult: null }
  for (const message of body.messages) {
    if (!Array.isArray(message.content)) continue
    for (const block of message.content) {
      if (block.type === 'tool_use' && block.id === 'toolu_bash_restore') out.toolUse = block.input.command
      if (block.type === 'tool_result' && block.tool_use_id === 'toolu_bash_restore') out.toolResult = JSON.stringify(block.content)
    }
  }
  return out
}

async function runScenario(name, scenario, detector) {
  const dir = path.join(OUT, name)
  fs.rmSync(dir, { recursive: true, force: true })
  const workspace = path.join(dir, 'ws')
  fs.mkdirSync(workspace, { recursive: true })
  fs.writeFileSync(path.join(workspace, '.env'), `DB_HOST=demo-db.internal\nDB_PASSWORD=${RAW}\n`)
  const mcpConfig = path.join(dir, 'mcp.json')
  fs.writeFileSync(mcpConfig, JSON.stringify({ mcpServers: { pgdetector: { command: 'node', args: [path.join(ROOT, 'src/detector/mcp-bridge.cjs')] } } }))

  const provider = await startProvider(scenario, workspace)
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
    PG_DETECTOR_URL: detector.url,
    PG_SESSION_HASH: 'e2e',
    PG_RESTORE_PLACEHOLDERS: scenario.restore,
  })
  // The detector bridge is an MCP tool; without this grant $.mcp.call is refused.
  const common = ['--plugin-dir', path.join(ROOT, 'src/native-mod'), '--mcp-config', mcpConfig, '--allowedTools', 'Read', 'Bash', 'mcp__pgdetector__scan_batch', '--output-format', 'json', '--model', MODEL]
  const first = await run('claude', ['-p', 'Check .env and use the DB password', ...common], { cwd: workspace, env: { ...env, PG_MOD_AUDIT: path.join(dir, 'audit-turn1.json') } })
  const sessionId = JSON.parse(first.stdout || '{}').session_id
  const second = sessionId ? await run('claude', ['-p', 'Anything else?', '--resume', sessionId, ...common], { cwd: workspace, env: { ...env, PG_MOD_AUDIT: path.join(dir, 'audit-turn2.json') } }) : { code: -1 }
  provider.server.close()
  fs.writeFileSync(path.join(dir, 'provider-requests.json'), JSON.stringify(provider.requests, null, 2))

  const messages = provider.requests.filter(r => r.url.startsWith('/v1/messages') && r.body?.messages)
  const afterBash = messages.filter(r => JSON.stringify(r.body).includes('toolu_bash_restore'))
  const turn2 = messages.filter(r => JSON.stringify(r.body).includes('Anything else?'))
  const transcripts = fs.readdirSync(path.join(dir, 'claude-config'), { recursive: true }).filter(f => String(f).endsWith('.jsonl'))
  const proofPath = path.join(workspace, 'restored-proof.txt')
  const proof = fs.existsSync(proofPath) ? fs.readFileSync(proofPath, 'utf8') : null
  const ph = provider.placeholder()
  const blocks = afterBash.length ? bashBlocks(afterBash.at(-1).body) : {}
  const audit1 = fs.existsSync(path.join(dir, 'audit-turn1.json')) ? JSON.parse(fs.readFileSync(path.join(dir, 'audit-turn1.json'), 'utf8')) : []
  // The tool_started row carries the restore count; the tool result's scan row carries the re-mask count.
  const bashStarted = audit1.find(row => row.tool === 'Bash' && row.event === 'tool_started') || {}
  const bashScan = audit1.find(row => row.tool === 'Bash' && row.hook === 'tool.call' && row.event === 'scan_completed') || {}

  const checks = {
    claude_exit_0: first.code === 0 && second.code === 0,
    read_result_masked: ph !== null,
    provider_requests_after_bash: afterBash.length > 0,
    second_turn_sent: turn2.length > 0,
    no_raw_in_any_provider_request: !provider.requests.some(r => JSON.stringify(r.body ?? '').includes(RAW)),
    history_tool_use_keeps_placeholder: blocks.toolUse?.includes(ph) === true && !blocks.toolUse.includes(RAW),
    no_raw_in_local_transcript: !transcripts.some(f => fs.readFileSync(path.join(dir, 'claude-config', f), 'utf8').includes(RAW)),
    no_raw_in_audit: ![...fs.readdirSync(dir)].filter(f => f.startsWith('audit-')).some(f => fs.readFileSync(path.join(dir, f), 'utf8').includes(RAW)),
  }
  if (name === 'file') {
    checks.command_ran_with_raw_value = proof === RAW
    checks.audit_restored_count_1 = bashStarted.restored_count === 1
  }
  if (name === 'echo') {
    checks.echoed_raw_remasked_in_tool_result = blocks.toolResult?.includes(ph) === true
    checks.audit_remasked_count_1 = bashScan.remasked_count === 1
  }
  if (name === 'off') {
    checks.command_ran_with_placeholder = proof === ph
    checks.audit_restored_count_0 = bashStarted.restored_count === 0
  }
  return checks
}

const { stdout: version } = await run('claude', ['--version'], {})
console.log(`Claude Code ${version.trim()}`)
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
console.log(failed ? `${failed} check(s) failed. Evidence: ${OUT}` : `All checks passed. Evidence: ${OUT}`)
process.exitCode = failed ? 1 : 0
