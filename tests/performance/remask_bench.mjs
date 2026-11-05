// Re-mask cost with many known secrets and a large tool output.
// Run: node tests/performance/remask_bench.mjs [path/to/register.mjs]
// Times one Bash tool.call (detector stubbed to answer at once with no findings, so the time is the
// Mod's own: collect, rebuild, full and partial re-mask) with 50 secrets in the vault and 100KB of
// stdout. Pass another register.mjs to compare (e.g. a copy from main without the partial pass).
import { createHash } from 'node:crypto'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const MODULE = path.resolve(process.argv[2] || 'src/native-mod/hooks/register.mjs')
const SECRETS = 50
const OUTPUT_BYTES = 100 * 1024
const RUNS = 30

// Deterministic synthetic values.
let seed = 42
const random = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!_-'
const word = length => Array.from({ length }, () => ALPHABET[Math.floor(random() * ALPHABET.length)]).join('')
const secrets = Array.from({ length: SECRETS }, () => word(16 + Math.floor(random() * 33))) // 16..48 characters

function filler(bytes) {
  const words = ['deploy', 'report', 'service', 'started', 'listening', 'on', 'port', '5432', 'ok', 'request', 'GET', '/api/v1/items', '200', 'took', 'ms']
  let out = ''
  while (out.length < bytes) out += `${words[Math.floor(random() * words.length)]}${random() < 0.1 ? '\n' : ' '}`
  return out.slice(0, bytes)
}

function withInserts(base, inserts) {
  const step = Math.floor(base.length / (inserts.length + 1))
  let out = ''
  inserts.forEach((insert, i) => { out += base.slice(i * step, (i + 1) * step) + insert })
  return (out + base.slice(inserts.length * step)).slice(0, OUTPUT_BYTES + inserts.join('').length)
}

const CASES = {
  'no secret text': filler(OUTPUT_BYTES),
  '50 partial values (first 12 chars)': withInserts(filler(OUTPUT_BYTES), secrets.map(s => ` ${s.slice(0, 12)} `)),
  '50 full values': withInserts(filler(OUTPUT_BYTES), secrets.map(s => ` ${s} `)),
}

const { register } = await import(`${pathToFileURL(MODULE).href}?bench=${Math.random()}`)
const hooks = {}
register((name, handler) => { hooks[name] = handler; return { catch() {} } })
const $ = {
  env: { get: async () => undefined },
  fs: { write: async () => {} },
  mcp: { call: async (_s, _t, { items }) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify({ ok: true, items: items.map(item => {
    // Finds the secrets only as "key=value", which is how they enter the vault below.
    const findings = []
    for (const raw of secrets) {
      const index = item.text.indexOf(`=${raw};`)
      if (index !== -1) findings.push({ type: 'PASSWORD', start: index + 1, end: index + 1 + raw.length, value_hash: createHash('sha256').update(raw).digest('hex'), offset_unit: 'utf16_code_units' })
    }
    findings.sort((a, b) => a.start - b.start)
    return { id: item.id, ok: true, findings, errors: [] }
  }) }) }] }) },
}
await hooks['prompt.submit']($, { text: secrets.map((raw, i) => `S${i}=${raw};`).join(' '), context: [] }, e => e)

const summary = values => {
  const sorted = [...values].sort((a, b) => a - b)
  const at = q => sorted[Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1)]
  return `p50 ${at(0.5).toFixed(1)}  p95 ${at(0.95).toFixed(1)}  max ${sorted.at(-1).toFixed(1)} ms`
}

console.log(`${path.relative(process.cwd(), MODULE)}: ${SECRETS} secrets (${secrets.filter(raw => raw.length <= 24).length} of <= 24 chars), ${OUTPUT_BYTES / 1024}KB stdout, ${RUNS} runs`)
for (const [name, stdout] of Object.entries(CASES)) {
  const times = []
  let left = []
  for (let run = 0; run < RUNS; run++) {
    const started = performance.now()
    const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: `t${run}`, command: 'cat app.log' }, () => ({ result: { stdout, stderr: '', interrupted: false } }))
    times.push(performance.now() - started)
    left = secrets.filter(raw => result.result.stdout.includes(raw.slice(0, 12)))
  }
  // 12 characters are masked only for values of 24 characters or fewer (at least half must match).
  const short = left.filter(raw => raw.length <= 24).length
  console.log(`  ${name.padEnd(36)} ${summary(times)}  first-12 left: ${left.length} (${short} of them from values <= 24 chars)`)
}
