// E2E on the real Claude Code CLI: the count_tokens path, the system prompt flags, the placeholder guide and escaped
// restore. A fake Anthropic API records every request and plays the model. Run from the repository root after install:
//   node tests/e2e/gaps.mjs
// Synthetic values only; nothing here prints them.
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const OUT = path.join(ROOT, '.runtime', 'e2e-gaps')
const MODEL = 'claude-sonnet-4-5-20250929'
const TOKEN = 'SYNTHgapTok_7xQ9mK2pR5vN8cL4wZ' // in a 36,000-character file
const APPENDED = 'SYNTHappendKey_4qM8vK2pR7xN5sL9' // in --append-system-prompt
const PASSWORD = 'Synth.Pa$s_92qDemo' // regex and shell characters on purpose
const GUIDE_MARK = 'PromptGuard: a bracketed name'
const PLACEHOLDER = /\[[A-Z_]+_\d+\]/

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

// plan(body) answers one /v1/messages request that offers tools: [blocks, stop] or null for "done".
function startProvider(plan) {
  const requests = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      const body = raw ? JSON.parse(raw) : null
      const entry = { url: req.url, raw }
      requests.push(entry)
      if (!req.url.startsWith('/v1/messages') || req.url.includes('count_tokens')) {
        // Not a real tokenizer: a fake count of body characters / 4, so masked and raw bodies differ.
        entry.count = Math.ceil(raw.length / 4)
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ input_tokens: entry.count, data: [] }))
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

const lastContent = body => JSON.stringify(body.messages.at(-1).content)

async function startWorker() {
  const port = await freePort()
  const child = spawn(PYTHON, [path.join(ROOT, 'src/detector/worker.py')], { cwd: ROOT, env: { ...process.env, PG_DETECTOR_PORT: String(port), PYTHONIOENCODING: 'utf-8' }, stdio: 'ignore' })
  const url = `http://127.0.0.1:${port}`
  await waitOk(`${url}/ready`)
  return { child, url }
}

async function startGuard(detectorUrl, upstreamUrl, dir, extra = {}) {
  const port = await freePort()
  const child = spawn(process.execPath, [path.join(ROOT, 'src/guard/final-guard.cjs')], {
    cwd: ROOT,
    env: { ...process.env, PG_GUARD_PORT: String(port), PG_UPSTREAM_BASE_URL: upstreamUrl, PG_GUARD_DETECTOR_URL: detectorUrl, PG_DETECTOR_TIMEOUT_MS: '30000', PG_AUDIT_PATH: path.join(dir, 'guard-audit.jsonl'), PG_SESSION_HASH: 'ab'.repeat(16), ...extra },
    stdio: 'ignore',
  })
  const url = `http://127.0.0.1:${port}`
  await waitOk(`${url}/health`)
  return { child, url }
}

async function claude(name, { prompt = 'Do the task', args = [], env = {}, plan, guard = false, guardEnv = {}, files = {} }, worker) {
  const dir = path.join(OUT, name)
  fs.rmSync(dir, { recursive: true, force: true })
  const ws = path.join(dir, 'ws')
  fs.mkdirSync(ws, { recursive: true })
  for (const [file, text] of Object.entries(files)) fs.writeFileSync(path.join(ws, file), text)
  const provider = await startProvider(body => plan(body, ws))
  const front = guard ? await startGuard(worker.url, provider.url, dir, guardEnv) : null
  const mcpConfig = path.join(dir, 'mcp.json')
  fs.writeFileSync(mcpConfig, JSON.stringify({ mcpServers: { pgdetector: { command: 'node', args: [path.join(ROOT, 'src/detector/mcp-bridge.cjs')] } } }))
  const base = { ...process.env }
  for (const key of ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_SESSION_ID']) delete base[key]
  const result = await run('claude', ['-p', prompt, '--plugin-dir', path.join(ROOT, 'src/native-mod'), '--mcp-config', mcpConfig,
    '--allowedTools', 'Read', 'Bash', 'Grep', 'mcp__pgdetector__scan_batch', '--output-format', 'json', '--model', MODEL, ...args], {
    cwd: ws,
    env: {
      ...base, CLAUDE_CONFIG_DIR: path.join(dir, 'cfg'), ANTHROPIC_BASE_URL: front ? front.url : provider.url, ANTHROPIC_API_KEY: 'sk-ant-e2e-dummy',
      NO_PROXY: '127.0.0.1,localhost', no_proxy: '127.0.0.1,localhost', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '1',
      PG_DETECTOR_URL: worker.url, PG_SESSION_HASH: 'e2e', PG_MOD_AUDIT: path.join(dir, 'audit.json'), ...env,
    },
  })
  provider.server.close()
  front?.child.kill()
  const answer = (() => { try { return JSON.parse(result.stdout).result } catch { return null } })()
  const guardAudit = fs.existsSync(path.join(dir, 'guard-audit.jsonl')) ? fs.readFileSync(path.join(dir, 'guard-audit.jsonl'), 'utf8').trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)) : []
  const audit = fs.existsSync(path.join(dir, 'audit.json')) ? JSON.parse(fs.readFileSync(path.join(dir, 'audit.json'), 'utf8')) : []
  return { code: result.code, answer, stdout: result.stdout, requests: provider.requests, guardAudit, audit, ws, dir }
}

const LAST_LINE = 'END OF LOG heartbeat summary written'
const bigFile = (chars = 36000) => {
  const lines = []
  for (let i = 0, size = 0; size < chars; i++) {
    lines.push(`${String(i).padStart(5, '0')} INFO worker heartbeat ok, queue depth ${i % 7}, latency ${i % 50}ms`)
    size += lines.at(-1).length + 1
  }
  lines.splice(200, 0, `API_TOKEN=${TOKEN}`)
  return `${lines.join('\n')}\n${LAST_LINE}\n`
}
// What the model got back for the Read: refused, truncated or the whole file; its size; masked or not.
function readOutcome(r) {
  for (const q of r.requests) {
    if (q.url.includes('count_tokens') || !q.raw.includes('toolu_read')) continue
    for (const message of JSON.parse(q.raw).messages) {
      for (const block of Array.isArray(message.content) ? message.content : []) {
        if (block.type !== 'tool_result' || block.tool_use_id !== 'toolu_read') continue
        const text = typeof block.content === 'string' ? block.content : (block.content || []).map(part => part.text || '').join('')
        const kind = /exceeds maximum allowed tokens/.test(text) ? 'refused' : text.includes(LAST_LINE) ? 'full' : 'truncated'
        const lines = /showing (\d+) of (\d+) lines/.exec(text)
        if (lines) return { kind: `truncated (${lines[1]} of ${lines[2]} lines, with a note)`, chars: text.length, masked: PLACEHOLDER.test(text), raw: text.includes(TOKEN) }
        return { kind, chars: text.length, masked: PLACEHOLDER.test(text), raw: text.includes(TOKEN) }
      }
    }
  }
  return { kind: 'none', chars: 0, masked: false, raw: false }
}
const describeRead = o => `${o.kind}, ${o.chars} chars, placeholder ${o.masked}, raw ${o.raw}`
const counts = r => r.requests.filter(q => q.url.includes('count_tokens')).map(q => q.count).join('/') || '-'
const readOnce = file => (body, ws) => JSON.stringify(body.messages).includes('toolu_read') ? null : [[{ type: 'tool_use', id: 'toolu_read', name: 'Read', input: { file_path: path.join(ws, file) } }], 'tool_use']
const raws = (r, value) => r.requests.filter(q => q.raw.includes(value))

const checks = {}
const info = {}
const worker = await startWorker()
try {
  // (a) count_tokens. Mod only (as metric-task runs it): the Read tool counts a large file with count_tokens inside
  // the tool, before tool.call hands the Mod its result, so the raw value goes out. Recorded, not a failure.
  const modOnly = await claude('count-tokens-mod-only', { files: { 'big.log': bigFile() }, plan: readOnce('big.log') }, worker)
  info.mod_only_count_tokens_requests = modOnly.requests.filter(q => q.url.includes('count_tokens')).length
  info.mod_only_raw_in_count_tokens = raws(modOnly, TOKEN).some(q => q.url.includes('count_tokens'))
  // With the Final Guard in front (promptguard run): the count_tokens request is refused (422) and never reaches the
  // API; Claude Code falls back to its own estimate and the session goes on with the masked file.
  const guarded = await claude('count-tokens-guard', { files: { 'big.log': bigFile() }, plan: readOnce('big.log'), guard: true }, worker)
  checks.guard_claude_exit_0 = guarded.code === 0
  checks.guard_session_continued = guarded.answer === 'Finished.'
  checks.guard_no_raw_reached_the_api = raws(guarded, TOKEN).length === 0
  checks.guard_blocked_count_tokens = guarded.guardAudit.some(row => String(row.endpoint).includes('count_tokens') && row.decision === 'block')
  checks.guard_masked_file_reached_the_model = guarded.requests.some(q => q.raw.includes('toolu_read') && PLACEHOLDER.test(q.raw))

  // (e) Read after count_tokens is refused, and PG_GUARD_COUNT_TOKENS=mask. 36,000 characters is above the engine's
  // count_tokens threshold (a quarter of the 25,000-token Read limit) and under the limit; 130,000 is over the limit.
  info.mod_only_read_36k = describeRead(readOutcome(modOnly))
  info.guard_block_read_36k = describeRead(readOutcome(guarded))
  checks.guard_block_read_36k_whole_file_masked = readOutcome(guarded).kind === 'full' && readOutcome(guarded).masked && !readOutcome(guarded).raw
  const maskSmall = await claude('count-tokens-mask', { files: { 'big.log': bigFile() }, plan: readOnce('big.log'), guard: true, guardEnv: { PG_GUARD_COUNT_TOKENS: 'mask' } }, worker)
  checks.mask_session_continued = maskSmall.code === 0 && maskSmall.answer === 'Finished.'
  checks.mask_count_tokens_reached_the_api_masked = raws(maskSmall, TOKEN).length === 0 && maskSmall.requests.some(q => q.url.includes('count_tokens') && PLACEHOLDER.test(q.raw))
  checks.mask_audit_count_tokens_masked = maskSmall.guardAudit.some(row => String(row.endpoint).includes('count_tokens') && row.decision === 'allow' && row.reason === 'COUNT_TOKENS_MASKED')
  checks.mask_read_36k_whole_file_masked = readOutcome(maskSmall).kind === 'full' && readOutcome(maskSmall).masked && !readOutcome(maskSmall).raw
  info.mask_read_36k = describeRead(readOutcome(maskSmall))
  info.count_tokens_36k_fake_count = `mod only ${counts(modOnly)}, mask ${counts(maskSmall)}, block ${counts(guarded)}`
  const big = bigFile(130000)
  const modLarge = await claude('count-tokens-mod-only-130k', { files: { 'big.log': big }, plan: readOnce('big.log') }, worker)
  const blockLarge = await claude('count-tokens-guard-130k', { files: { 'big.log': big }, plan: readOnce('big.log'), guard: true }, worker)
  const maskLarge = await claude('count-tokens-mask-130k', { files: { 'big.log': big }, plan: readOnce('big.log'), guard: true, guardEnv: { PG_GUARD_COUNT_TOKENS: 'mask' } }, worker)
  info.mod_only_read_130k = describeRead(readOutcome(modLarge))
  info.guard_block_read_130k = describeRead(readOutcome(blockLarge))
  info.mask_read_130k = describeRead(readOutcome(maskLarge))
  info.count_tokens_130k_fake_count = `mod only ${counts(modLarge)}, mask ${counts(maskLarge)}, block ${counts(blockLarge)}`
  // Over the limit the engine either refuses (an error result) or returns a partial view with a note; the version decides.
  checks.guard_block_read_130k_not_whole_session_continued = /^(refused|truncated)/.test(readOutcome(blockLarge).kind) && blockLarge.answer === 'Finished.'
  checks.mask_read_130k_not_whole_session_continued = /^(refused|truncated)/.test(readOutcome(maskLarge).kind) && maskLarge.answer === 'Finished.'
  checks.guard_130k_no_raw_reached_the_api = raws(blockLarge, TOKEN).length === 0 && raws(maskLarge, TOKEN).length === 0

  // (f) Launched without promptguard run: the Final Guard refuses every request that carries the raw system prompt,
  // and the error the user sees says to start with promptguard run.
  const direct = await claude('append-system-prompt-direct', { args: ['--append-system-prompt', `Deploy with API_KEY=${APPENDED} when asked.`], guard: true, plan: () => null }, worker)
  const directMessages = direct.guardAudit.filter(row => row.endpoint === '/v1/messages')
  checks.direct_every_request_blocked = directMessages.length > 0 && directMessages.every(row => row.decision === 'block') && !direct.requests.some(q => q.url.startsWith('/v1/messages') && !q.url.includes('count_tokens'))
  checks.direct_message_points_to_promptguard_run = /promptguard run/.test(direct.stdout) && !direct.stdout.includes(APPENDED)
  info.direct_blocked_requests = directMessages.length
  info.direct_exit_code = direct.code
  info.direct_message = (() => { try { return String(JSON.parse(direct.stdout).result).slice(0, 400) } catch { return direct.stdout.slice(0, 400) } })()

  // (b) --append-system-prompt: masked by the launcher module, restored by the Mod from the seed.
  const seedDir = path.join(OUT, 'system-prompt-seed')
  fs.rmSync(seedDir, { recursive: true, force: true })
  fs.mkdirSync(seedDir, { recursive: true })
  const seedFile = path.join(seedDir, 'seed.json')
  const masked = await run(process.execPath, [path.join(ROOT, 'src/launcher/system-prompt.cjs'), '--detector-url', worker.url, '--seed-file', seedFile, '--',
    '--append-system-prompt', `Deploy with API_KEY=${APPENDED} when asked.`], { cwd: ROOT })
  const maskedArgs = JSON.parse(masked.stdout)
  const appended = await claude('append-system-prompt', {
    args: maskedArgs,
    env: { PG_MOD_SEED_FILE: seedFile },
    plan: body => JSON.stringify(body.messages).includes('toolu_proof') ? null
      : [[{ type: 'tool_use', id: 'toolu_proof', name: 'Bash', input: { command: `printf '%s' '${JSON.stringify(body.system).match(PLACEHOLDER)?.[0] ?? '[MISSING_1]'}' > proof.txt`, description: 'use the key' } }], 'tool_use'],
  }, worker)
  checks.append_masked_before_start = maskedArgs.join(' ').includes('[') && !maskedArgs.join(' ').includes(APPENDED)
  checks.append_no_raw_reached_the_api = raws(appended, APPENDED).length === 0
  checks.append_placeholder_restored_in_bash = fs.existsSync(path.join(appended.ws, 'proof.txt')) && fs.readFileSync(path.join(appended.ws, 'proof.txt'), 'utf8') === APPENDED
  checks.append_seed_emptied = JSON.parse(fs.readFileSync(seedFile, 'utf8')).entries.length === 0
  const unmasked = await claude('append-system-prompt-unmasked', { args: ['--append-system-prompt', `Deploy with API_KEY=${APPENDED} when asked.`], plan: () => null }, worker)
  info.unmasked_append_raw_reached_the_api = raws(unmasked, APPENDED).length > 0

  // (c) guide: once in every request's system prompt.
  const guide = await claude('guide', { env: { PG_PLACEHOLDER_GUIDE: 'on' }, files: { '.env': `DB_PASSWORD=${PASSWORD}\n` }, plan: readOnce('.env') }, worker)
  const messages = guide.requests.filter(q => q.url.startsWith('/v1/messages') && !q.url.includes('count_tokens'))
  checks.guide_once_in_each_request = messages.length > 0 && messages.every(q => q.raw.split(GUIDE_MARK).length - 1 === 1)
  const off = await claude('guide-off', { files: { '.env': `DB_PASSWORD=${PASSWORD}\n` }, plan: readOnce('.env') }, worker)
  checks.guide_absent_when_off = off.requests.every(q => !q.raw.includes(GUIDE_MARK))
  info.guide_chars = (messages[0]?.raw.match(/PromptGuard: a bracketed name[^"]*/)?.[0] ?? '').length

  // (d) escaped restore: Grep with \[PASSWORD_1\] finds the line.
  const escaped = await claude('escaped-grep', {
    env: { PG_RESTORE_ESCAPED: 'on' },
    files: { '.env': `DB_HOST=demo-db.internal\nDB_PASSWORD=${PASSWORD}\n` },
    // Decided on the whole history, once each: Read, then Grep, then done.
    plan: (body, ws) => {
      const history = JSON.stringify(body.messages)
      if (!history.includes('toolu_read')) return [[{ type: 'tool_use', id: 'toolu_read', name: 'Read', input: { file_path: path.join(ws, '.env') } }], 'tool_use']
      if (!history.includes('toolu_grep')) {
        const ph = lastContent(body).match(PLACEHOLDER)?.[0] ?? '[MISSING_1]'
        return [[{ type: 'tool_use', id: 'toolu_grep', name: 'Grep', input: { pattern: `PASSWORD=${ph.replace('[', '\\[').replace(']', '\\]')}`, path: ws, output_mode: 'content', glob: '.env' } }], 'tool_use']
      }
      return null
    },
  }, worker)
  const grepResult = escaped.requests.map(q => q.raw).find(raw => raw.includes('toolu_grep') && raw.includes('tool_result')) ?? ''
  const grepRow = escaped.audit.find(row => row.tool === 'Grep' && row.event === 'tool_started') ?? {}
  checks.escaped_grep_restored = grepRow.restored_count === 1
  checks.escaped_grep_found_the_line = /DB_PASSWORD=\[PASSWORD_\d+\]/.test(grepResult)
  checks.escaped_no_raw_reached_the_api = raws(escaped, PASSWORD).length === 0
  checks.no_raw_in_any_audit = [modOnly, guarded, maskSmall, modLarge, blockLarge, maskLarge, direct, appended, guide, escaped].every(r => !JSON.stringify(r.audit).includes(TOKEN) && !JSON.stringify(r.audit).includes(APPENDED) && !JSON.stringify(r.audit).includes(PASSWORD))
} finally {
  worker.child.kill()
}

const { stdout: version } = await run('claude', ['--version'], {})
console.log(`Claude Code ${version.trim()}`)
let failed = 0
for (const [name, ok] of Object.entries(checks)) {
  if (!ok) failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`)
}
for (const [name, value] of Object.entries(info)) console.log(`INFO ${name}: ${value}`)
console.log(failed ? `${failed} check(s) failed. Evidence: ${OUT}` : `All checks passed. Evidence: ${OUT}`)
process.exitCode = failed ? 1 : 0
