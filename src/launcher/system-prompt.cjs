'use strict'

// Masks secrets in Claude Code's system prompt flags before Claude Code starts.
//
// No Native Mod hook sees --append-system-prompt or --system-prompt (nor their -file forms): on Claude Code 2.1.291
// and 2.1.312 their text reaches the API's `system` field without passing prompt.compose, prompt.section or any other
// hook, and with --system-prompt prompt.compose is not called at all. So the text is masked here, with the Mod's
// placeholder format, and the map (placeholder, raw value, value hash) goes to a seed file the Mod reads once at its
// first scan: the same value elsewhere gets the same placeholder, numbering continues after it, and the placeholder
// restores in tool input like any other. The seed file is written with mode 0600 and emptied by the Mod once read.
//
// Fail-closed: a scan that fails or reports errors refuses to start Claude Code. Errors never quote values.
//
// CLI (for runners that start Claude Code themselves, such as promptguard-data's metric-task m2.py):
//   node src/launcher/system-prompt.cjs --detector-url URL --seed-file FILE [--work-dir DIR] -- <claude args...>
// prints the masked arguments as a JSON array; give Claude Code PG_MOD_SEED_FILE=FILE when it printed any seed.

const crypto = require('node:crypto')
const fs = require('node:fs')
const http = require('node:http')
const path = require('node:path')

const TEXT_FLAGS = new Set(['--system-prompt', '--append-system-prompt'])
const FILE_FLAGS = new Set(['--system-prompt-file', '--append-system-prompt-file'])

// register.mjs typeName.
function typeName(value) {
  return String(value || 'CREDENTIAL').toUpperCase().replace(/[^A-Z0-9_]/g, '_') || 'CREDENTIAL'
}

class SystemPromptScanError extends Error {
  constructor() {
    super('PromptGuard could not scan the system prompt; Claude Code was not started.')
    this.name = 'SystemPromptScanError'
  }
}

// Each system prompt value as { index, kind: 'text' | 'file', flag, inline }: the argument that holds it.
function locate(args) {
  const out = []
  args.forEach((arg, index) => {
    const eq = arg.indexOf('=')
    const name = eq > 0 ? arg.slice(0, eq) : arg
    if (!TEXT_FLAGS.has(name) && !FILE_FLAGS.has(name)) return
    const kind = TEXT_FLAGS.has(name) ? 'text' : 'file'
    if (eq > 0) out.push({ index, kind, flag: name, inline: true })
    else if (index + 1 < args.length) out.push({ index: index + 1, kind, flag: name, inline: false })
  })
  return out
}

async function maskSystemPromptArgs(args, { scan, seedFile, workDir }) {
  const places = locate(args)
  if (!places.length) return { args: [...args], seeded: 0 }
  const texts = places.map(place => {
    const value = place.inline ? args[place.index].slice(place.flag.length + 1) : args[place.index]
    return place.kind === 'file' ? fs.readFileSync(value, 'utf8') : value
  })
  let results
  try { results = await scan(texts) } catch { throw new SystemPromptScanError() }
  if (!Array.isArray(results) || results.length !== texts.length || results.some(r => !r || r.ok !== true || (r.errors && r.errors.length) || !Array.isArray(r.findings))) {
    throw new SystemPromptScanError()
  }
  const ledger = new Map() // value hash -> placeholder
  const counters = new Map()
  const entries = []
  const masked = texts.map((text, i) => {
    const findings = [...results[i].findings].sort((a, b) => a.start - b.start)
    let out = ''
    let cursor = 0
    for (const finding of findings) {
      if (finding.offset_unit !== 'utf16_code_units' || finding.start < cursor || finding.end > text.length || finding.start >= finding.end) throw new SystemPromptScanError()
      const raw = text.slice(finding.start, finding.end)
      const key = finding.value_hash || crypto.createHash('sha256').update(raw).digest('hex')
      if (!ledger.has(key)) {
        const kind = typeName(finding.type)
        const next = (counters.get(kind) || 0) + 1
        counters.set(kind, next)
        const placeholder = `[${kind}_${next}]`
        ledger.set(key, placeholder)
        entries.push({ placeholder, raw, value_hash: key })
      }
      out += text.slice(cursor, finding.start) + ledger.get(key)
      cursor = finding.end
    }
    return out + text.slice(cursor)
  })
  const out = [...args]
  places.forEach((place, i) => {
    if (masked[i] === texts[i]) return
    let value = masked[i]
    if (place.kind === 'file') {
      fs.mkdirSync(workDir, { recursive: true, mode: 0o700 })
      value = path.join(workDir, `system-prompt-${i + 1}${path.extname(place.inline ? out[place.index].slice(place.flag.length + 1) : out[place.index]) || '.txt'}`)
      fs.writeFileSync(value, masked[i], { encoding: 'utf8', mode: 0o600 })
    }
    out[place.index] = place.inline ? `${place.flag}=${value}` : value
  })
  if (entries.length) fs.writeFileSync(seedFile, `${JSON.stringify({ entries })}\n`, { encoding: 'utf8', mode: 0o600 })
  return { args: out, seeded: entries.length }
}

// The detector's /scan-batch, as the Mod's bridge calls it.
function detectorScan(detectorUrl, timeoutMs = 30000) {
  return texts => new Promise((resolve, reject) => {
    const url = new URL('/scan-batch', detectorUrl)
    const body = Buffer.from(JSON.stringify({ request_id: `system-prompt-${Date.now()}`, items: texts.map((text, id) => ({ id, text, source: 'claude_md' })) }))
    const request = http.request(url, { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': body.length }, timeout: timeoutMs }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.on('end', () => {
        try {
          const value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
          if (response.statusCode !== 200 || value.ok !== true || !Array.isArray(value.items)) return reject(new SystemPromptScanError())
          const byId = new Map(value.items.map(item => [item.id, item]))
          resolve(texts.map((_, id) => byId.get(id)))
        } catch { reject(new SystemPromptScanError()) }
      })
    })
    request.on('timeout', () => request.destroy(new SystemPromptScanError()))
    request.on('error', reject)
    request.end(body)
  })
}

async function main(argv) {
  const split = argv.indexOf('--')
  const own = split === -1 ? argv : argv.slice(0, split)
  const claudeArgs = split === -1 ? [] : argv.slice(split + 1)
  const option = name => { const at = own.indexOf(name); return at === -1 ? undefined : own[at + 1] }
  const detectorUrl = option('--detector-url')
  const seedFile = option('--seed-file')
  if (!detectorUrl || !seedFile) {
    process.stderr.write('usage: system-prompt.cjs --detector-url URL --seed-file FILE [--work-dir DIR] -- <claude args...>\n')
    return 2
  }
  try {
    const { args } = await maskSystemPromptArgs(claudeArgs, { scan: detectorScan(detectorUrl), seedFile, workDir: option('--work-dir') || path.dirname(path.resolve(seedFile)) })
    process.stdout.write(`${JSON.stringify(args)}\n`)
    return 0
  } catch (error) {
    process.stderr.write(`${error instanceof SystemPromptScanError ? error.message : 'PromptGuard could not mask the system prompt.'}\n`)
    return 1
  }
}

if (require.main === module) main(process.argv.slice(2)).then(code => { process.exitCode = code })

module.exports = { maskSystemPromptArgs, detectorScan, SystemPromptScanError, TEXT_FLAGS, FILE_FLAGS }
