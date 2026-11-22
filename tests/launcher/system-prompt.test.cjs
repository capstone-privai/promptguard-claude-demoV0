'use strict'

// System prompt flags are masked before Claude Code starts: no Mod hook sees --append-system-prompt or --system-prompt
// (checked on 2.1.291 and 2.1.312), so the launcher replaces their secrets with placeholders and hands the Mod the
// map (a seed file) so they restore like any other. Synthetic values only; messages never print them.
const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { maskSystemPromptArgs } = require('../../src/launcher/system-prompt.cjs')

const KEY = 'SYNTHapiKEYx7Qk2mR9vL4'
const PASS = 'SynthPass!92qDemo'
const hash = raw => crypto.createHash('sha256').update(raw).digest('hex')

// Fake detector: finds KEY after "key " and PASS after "password ".
function scan(texts) {
  return texts.map(text => {
    const findings = []
    for (const [cue, raw, type] of [['key ', KEY, 'API_KEY'], ['password ', PASS, 'PASSWORD']]) {
      let at = text.indexOf(cue + raw)
      while (at !== -1) {
        const start = at + cue.length
        findings.push({ start, end: start + raw.length, type, value_hash: hash(raw), offset_unit: 'utf16_code_units' })
        at = text.indexOf(cue + raw, at + 1)
      }
    }
    return { ok: true, findings: findings.sort((a, b) => a.start - b.start), errors: [] }
  })
}

function temp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pg-sysprompt-'))
}

test('--append-system-prompt and --system-prompt values are masked, numbered top to bottom', async () => {
  const dir = temp()
  const seedFile = path.join(dir, 'seed.json')
  const { args, seeded } = await maskSystemPromptArgs(
    ['-p', 'go', '--append-system-prompt', `use key ${KEY} and password ${PASS}`, '--system-prompt', `again key ${KEY}`],
    { scan: async texts => scan(texts), seedFile, workDir: dir })
  assert.deepEqual(args, ['-p', 'go', '--append-system-prompt', 'use key [API_KEY_1] and password [PASSWORD_1]', '--system-prompt', 'again key [API_KEY_1]'])
  assert.equal(seeded, 2)
  const seed = JSON.parse(fs.readFileSync(seedFile, 'utf8'))
  assert.deepEqual(seed.entries.map(e => [e.placeholder, e.raw === KEY || e.raw === PASS, e.value_hash.length]), [['[API_KEY_1]', true, 64], ['[PASSWORD_1]', true, 64]])
  assert.ok(!args.join(' ').includes(KEY) && !args.join(' ').includes(PASS))
})

test('--flag=value and the -file variants are masked too; the file is copied, not changed', async () => {
  const dir = temp()
  const promptFile = path.join(dir, 'prompt.txt')
  fs.writeFileSync(promptFile, `deploy with key ${KEY}\n`)
  const { args } = await maskSystemPromptArgs(
    [`--append-system-prompt=key ${KEY}`, '--system-prompt-file', promptFile],
    { scan: async texts => scan(texts), seedFile: path.join(dir, 'seed.json'), workDir: dir })
  assert.equal(args[0], '--append-system-prompt=key [API_KEY_1]')
  assert.equal(args[1], '--system-prompt-file')
  assert.notEqual(args[2], promptFile)
  assert.equal(fs.readFileSync(args[2], 'utf8'), 'deploy with key [API_KEY_1]\n')
  assert.equal(fs.readFileSync(promptFile, 'utf8'), `deploy with key ${KEY}\n`, 'the user file is left alone')
})

test('no secret: arguments unchanged and no seed file', async () => {
  const dir = temp()
  const seedFile = path.join(dir, 'seed.json')
  const input = ['-p', 'go', '--append-system-prompt', 'be brief']
  const { args, seeded } = await maskSystemPromptArgs(input, { scan: async texts => scan(texts), seedFile, workDir: dir })
  assert.deepEqual(args, input)
  assert.equal(seeded, 0)
  assert.equal(fs.existsSync(seedFile), false)
})

test('no system prompt flag: the detector is not called', async () => {
  let calls = 0
  const { args } = await maskSystemPromptArgs(['-p', `key ${KEY}`], { scan: async texts => { calls++; return scan(texts) }, seedFile: 'x', workDir: temp() })
  assert.deepEqual(args, ['-p', `key ${KEY}`], 'the prompt itself goes through the Mod, not here')
  assert.equal(calls, 0)
})

test('a failed scan refuses to start (fail-closed), without the value in the error', async () => {
  for (const scanner of [async () => { throw new Error(`boom ${KEY}`) }, async texts => texts.map(() => ({ ok: false, findings: [], errors: ['x'] }))]) {
    await assert.rejects(
      maskSystemPromptArgs(['--append-system-prompt', `key ${KEY}`], { scan: scanner, seedFile: 'x', workDir: temp() }),
      error => !String(error.message).includes(KEY) && /system prompt/.test(error.message))
  }
})
