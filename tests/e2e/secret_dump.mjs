// E2E on the real Claude Code CLI: the secret-file dump guard (PG_SECRET_DUMP_GUARD) and the preload
// (PG_SECRET_FILE_PRELOAD). A fake Anthropic API plays the model: it runs od -c, xxd, base64, a python character
// list and fold -w 3 on secrets/db_password.txt, od -c on README.md, and cat on the secret file, and records every
// request. Run from the repository root after install:  node tests/e2e/secret_dump.mjs
// Synthetic values only; nothing here prints them.
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const OUT = path.join(ROOT, '.runtime', 'e2e-secret-dump')
const MODEL = 'claude-sonnet-4-5-20250929'
const PASS = 'Sy nth$Pa ss9q' // a space and a $, as in g16
const FILE = 'secrets/db_password.txt'
const NOTICE = '[PROMPTGUARD: 비밀 파일을 변형해 출력한 결과라 가렸습니다. 값은 placeholder로 다루고, 속성은 값을 출력하지 않는 명령으로 확인하세요]'
const README = 'Synthetic readme for the dump guard e2e.\n'
const DUMPS = [
  ['od', `od -c ${FILE}`],
  ['xxd', `xxd ${FILE}`],
  ['base64', `base64 ${FILE}`],
  ['python', `python -c "print(list(open('${FILE}').read()))"`],
  ['fold', `fold -w 3 ${FILE}`],
  ['head', `head -c 6 ${FILE}`],
  ['cat', `cat -A ${FILE}`],
]
const PLACEHOLDER = /\[[A-Z_]+_\d+\]/
// Pieces of the value in the forms the dump tools print it: no request may hold any of them.
// od -c: a character every four columns; xxd: hex in groups of two bytes; fold -w 3: three characters a line.
const HEX = Buffer.from(PASS).toString('hex').match(/.{4}/g)
const FORMS = [PASS, PASS.slice(0, 6), Buffer.from(`${PASS}\n`).toString('base64').slice(0, 12), PASS.split('').map(c => `'${c}'`).join(', ').slice(0, 30), 'nth$P', 'Pa ',
  PASS.slice(3, 8).split('').join('   '), `${HEX[2]} ${HEX[3]}`, `${PASS.slice(3, 6)}\n${PASS.slice(6, 9)}`]

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

// Runs the commands one by one (one Bash call per request, decided on the whole history), then finishes.
// A command "READ <path>" is a Read tool call on that workspace file; any other is a Bash command.
function startProvider(commands, ws) {
  const requests = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      const body = raw ? JSON.parse(raw) : null
      requests.push({ url: req.url, raw })
      if (!req.url.startsWith('/v1/messages') || req.url.includes('count_tokens')) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ input_tokens: 10, data: [] }))
      }
      if (!body.stream) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ id: 'm', type: 'message', role: 'assistant', model: body.model, content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } }))
      }
      const history = JSON.stringify(body.messages)
      const next = (body.tools || []).length ? commands.findIndex((_, i) => !history.includes(`toolu_cmd${i}`)) : -1
      if (next === -1) return sse(res, [{ type: 'text', text: 'Finished.' }], 'end_turn')
      const call = commands[next].startsWith('READ ') ? { name: 'Read', input: { file_path: path.join(ws, commands[next].slice(5)) } } : { name: 'Bash', input: { command: commands[next], description: 'look at the file' } }
      return sse(res, [{ type: 'tool_use', id: `toolu_cmd${next}`, ...call }], 'tool_use')
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

async function session(name, commands, env, worker) {
  const dir = path.join(OUT, name)
  fs.rmSync(dir, { recursive: true, force: true })
  const ws = path.join(dir, 'ws')
  fs.mkdirSync(path.join(ws, 'secrets'), { recursive: true })
  fs.writeFileSync(path.join(ws, FILE), `${PASS}\n`)
  fs.writeFileSync(path.join(ws, 'README.md'), README)
  const provider = await startProvider(commands, ws)
  const mcpConfig = path.join(dir, 'mcp.json')
  fs.writeFileSync(mcpConfig, JSON.stringify({ mcpServers: { pgdetector: { command: 'node', args: [path.join(ROOT, 'src/detector/mcp-bridge.cjs')] } } }))
  const base = { ...process.env }
  for (const key of ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_SESSION_ID']) delete base[key]
  const result = await run('claude', ['-p', 'Check the database password file', '--plugin-dir', path.join(ROOT, 'src/native-mod'), '--mcp-config', mcpConfig,
    '--allowedTools', 'Bash', 'Read', 'mcp__pgdetector__scan_batch', '--output-format', 'json', '--model', MODEL], {
    cwd: ws,
    env: {
      ...base, CLAUDE_CONFIG_DIR: path.join(dir, 'cfg'), ANTHROPIC_BASE_URL: provider.url, ANTHROPIC_API_KEY: 'sk-ant-e2e-dummy',
      NO_PROXY: '127.0.0.1,localhost', no_proxy: '127.0.0.1,localhost', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '1',
      PG_DETECTOR_URL: worker.url, PG_SESSION_HASH: 'e2e', PG_MOD_AUDIT: path.join(dir, 'audit.json'), ...env,
    },
  })
  provider.server.close()
  const answer = (() => { try { return JSON.parse(result.stdout).result } catch { return null } })()
  const audit = fs.existsSync(path.join(dir, 'audit.json')) ? JSON.parse(fs.readFileSync(path.join(dir, 'audit.json'), 'utf8')) : []
  // The tool_result text each command came back with, from the last request that holds it.
  const results = commands.map((_, i) => {
    for (const q of [...provider.requests].reverse()) {
      if (q.url.includes('count_tokens') || !q.raw.includes(`toolu_cmd${i}`)) continue
      for (const message of JSON.parse(q.raw).messages) {
        for (const block of Array.isArray(message.content) ? message.content : []) {
          if (block.type === 'tool_result' && block.tool_use_id === `toolu_cmd${i}`) {
            return typeof block.content === 'string' ? block.content : (block.content || []).map(part => part.text || '').join('')
          }
        }
      }
    }
    return null
  })
  const leaked = provider.requests.some(q => FORMS.some(form => q.raw.includes(form) || q.raw.includes(JSON.stringify(form).slice(1, -1))))
  return { code: result.code, answer, audit, results, leaked, rawInAudit: JSON.stringify(audit).includes(PASS) || JSON.stringify(audit).includes(FILE) }
}

const checks = {}
const info = {}
const worker = await startWorker()
try {
  const guarded = await session('guard-on', [...DUMPS.map(([, command]) => command), 'od -c README.md'], {}, worker)
  checks.session_finished = guarded.code === 0 && guarded.answer === 'Finished.'
  // The engine may append its own reminder after a tool result; the leak check below covers the rest.
  DUMPS.forEach(([tool], i) => { checks[`${tool}_output_replaced_by_notice`] = guarded.results[i]?.trim().startsWith(NOTICE) === true })
  info.extra_after_notice_chars = guarded.results[0] ? guarded.results[0].trim().length - NOTICE.length : null
  checks.no_form_of_the_value_reached_the_api = !guarded.leaked
  const rows = guarded.audit.filter(row => row.event === 'secret_dump_guarded')
  checks.audit_one_row_per_dump_with_tool_names = rows.map(row => row.dump_tool).join(',') === DUMPS.map(([tool]) => tool).join(',') && rows.at(-1)?.secret_dump_count === DUMPS.length
  checks.audit_has_no_path_or_value = !guarded.rawInAudit
  checks.readme_dump_not_guarded = typeof guarded.results.at(-1) === 'string' && !guarded.results.at(-1).includes('PROMPTGUARD') && /R\s+e\s+a\s+d|S\s+y\s+n\s+t/.test(guarded.results.at(-1))

  const off = await session('guard-off', [DUMPS[0][1]], { PG_SECRET_DUMP_GUARD: 'off' }, worker)
  info.guard_off_od_output_reached_the_api = off.leaked
  checks.guard_off_not_replaced = typeof off.results[0] === 'string' && !off.results[0].includes('PROMPTGUARD:')

  const cat = await session('cat-preload-off', [`cat ${FILE}`], {}, worker)
  info.cat_preload_off_masked = PLACEHOLDER.test(cat.results[0] ?? '')
  info.cat_preload_off_raw_reached_the_api = cat.leaked
  checks.cat_not_guarded = typeof cat.results[0] === 'string' && !cat.results[0].includes('PROMPTGUARD:')
  const preload = await session('cat-preload-on', [`cat ${FILE}`, `od -c ${FILE}`], { PG_SECRET_FILE_PRELOAD: 'on' }, worker)
  checks.cat_preload_on_masked_with_placeholder = PLACEHOLDER.test(preload.results[0] ?? '') && !(preload.results[0] ?? '').includes('PROMPTGUARD:')
  checks.cat_preload_on_no_raw_reached_the_api = !preload.leaked
  checks.preload_audit_has_no_path_or_value = !preload.rawInAudit

  // Read of a password file with no key name: the detector finds nothing, so only the preload keeps it back.
  const readOff = await session('read-preload-off', [`READ ${FILE}`], { PG_SECRET_FILE_PRELOAD: 'off' }, worker)
  info.read_preload_off_raw_reached_the_api = readOff.leaked
  const readOn = await session('read-preload-on', [`READ ${FILE}`], { PG_SECRET_FILE_PRELOAD: 'on' }, worker)
  checks.read_preload_on_session_finished = readOn.code === 0 && readOn.answer === 'Finished.'
  checks.read_preload_on_masked_with_placeholder = PLACEHOLDER.test(readOn.results[0] ?? '')
  checks.read_preload_on_no_raw_reached_the_api = !readOn.leaked
  checks.read_preload_audit_has_no_path_or_value = !readOn.rawInAudit
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
