// Native Mod: the launcher's system-prompt seed, the placeholder guide (PG_PLACEHOLDER_GUIDE) and escaped restore
// (PG_RESTORE_ESCAPED). Run: node --test tests/mod/test_gaps.mjs. Synthetic values only.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

const hash = raw => createHash('sha256').update(raw).digest('hex')
const TOKEN = 'SYNTHtok.en$x7Qk2/m+R9' // regex and shell characters on purpose
const PASS = 'SynthPass!92qDemo'
const RESTORE_TOOLS = ['Bash', 'PowerShell', 'Edit', 'MultiEdit', 'Write', 'NotebookEdit', 'Grep']

function fakeScan(items, values) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      for (const [cue, raw, type] of values) {
        let at = item.text.indexOf(cue + raw)
        while (at !== -1) {
          const start = at + cue.length
          findings.push({ type, start, end: start + raw.length, value_hash: hash(raw), offset_unit: 'utf16_code_units' })
          at = item.text.indexOf(cue + raw, at + 1)
        }
      }
      // The guide must never reach the detector; if it did, this would flag a word in it.
      const guide = item.text.indexOf('PromptGuard')
      if (guide !== -1) findings.push({ type: 'SECRET', start: guide, end: guide + 11, value_hash: hash('PromptGuard'), offset_unit: 'utf16_code_units' })
      findings.sort((a, b) => a.start - b.start)
      return { id: item.id, ok: true, findings, errors: [] }
    }),
  }
}

async function load(env = {}, { files = {}, values = [['TOKEN=', TOKEN, 'TOKEN'], ['PASSWORD=', PASS, 'PASSWORD']] } = {}) {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const writes = {}
  const audit = []
  const $ = {
    env: { get: async key => env[key] ?? (key === 'PG_MOD_AUDIT' ? 'audit.json' : null) },
    fs: {
      read: async file => { if (!(file in files)) throw new Error('ENOENT'); return files[file] },
      write: async (file, text) => { writes[file] = text; if (file === 'audit.json') audit.splice(0, audit.length, ...JSON.parse(text)) },
    },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items, values)) }] }) },
  }
  return { hooks, $, writes, audit }
}

async function read(hooks, $, content) {
  const result = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 't', file_path: 'x' }, () => ({ result: { type: 'text', file: { content } } }))
  return result.result.file.content
}

async function run(hooks, $, input) {
  let ran
  await hooks['tool.call']($, { tool_use_id: 't', ...input }, e => { ran = e; return { result: { stdout: '', stderr: '', interrupted: false } } })
  return ran
}

async function compose(hooks, $) {
  return hooks['prompt.compose']($, { model: 'm', tools: [], traits: [] }, async () => ({ sections: [{ id: 'intro', text: 'You are Claude.', scope: 'shared' }] }))
}

// ---- seed from the launcher (system prompt placeholders)

test('a seed file registers the system prompt placeholders: restore, numbering and the same value', async () => {
  const seed = JSON.stringify({ entries: [{ placeholder: '[TOKEN_1]', raw: TOKEN, value_hash: hash(TOKEN) }] })
  const { hooks, $, writes } = await load({ PG_MOD_SEED_FILE: 'seed.json' }, { files: { 'seed.json': seed }, values: [['TOKEN=', TOKEN, 'TOKEN'], ['TOKEN=', PASS, 'TOKEN']] })
  assert.equal(await read(hooks, $, `TOKEN=${TOKEN}\nTOKEN=${PASS}`), 'TOKEN=[TOKEN_1]\nTOKEN=[TOKEN_2]')
  assert.equal((await run(hooks, $, { tool: 'Bash', command: 'deploy [TOKEN_1]' })).command, `deploy ${TOKEN}`)
  assert.equal(JSON.parse(writes['seed.json']).entries.length, 0, 'the seed file is emptied once read')
})

test('a seed file that cannot be read blocks (fail-closed), since numbers could collide', async () => {
  const { hooks, $ } = await load({ PG_MOD_SEED_FILE: 'missing.json' })
  let sent
  await hooks['prompt.submit']($, { text: 'hi', context: [] }, e => { sent = e; return e })
  assert.match(sent.text, /^\[PROMPTGUARD_BLOCKED/)
})

// ---- placeholder guide

test('guide on: one section in every composed system prompt, naming the restore tools exactly', async () => {
  const { hooks, $ } = await load({ PG_PLACEHOLDER_GUIDE: 'on', PG_RESTORE_ESCAPED: 'off' })
  for (let round = 0; round < 2; round++) {
    const { sections } = await compose(hooks, $)
    const guides = sections.filter(section => section.id === 'promptguard:placeholder-guide')
    assert.equal(guides.length, 1)
    assert.equal(sections.at(-1).id, 'promptguard:placeholder-guide', 'last, after the engine sections')
    assert.equal(guides[0].scope, 'session')
    const text = guides[0].text
    assert.ok(text.includes('PromptGuard'), 'not sent to the detector, so not masked')
    for (const tool of RESTORE_TOOLS) assert.ok(text.includes(tool), tool)
    for (const tool of ['Read', 'WebFetch', 'Agent']) assert.ok(!new RegExp(`\\b${tool}\\b`).test(text), tool)
    assert.ok(!/\[[A-Z0-9_]+_\d+\]/.test(text), 'no placeholder-shaped example')
    assert.ok(!text.includes('\\['), 'escaped form only mentioned when PG_RESTORE_ESCAPED=on')
  }
})

test('guide mentions escaped placeholders only with PG_RESTORE_ESCAPED=on', async () => {
  const { hooks, $ } = await load({ PG_PLACEHOLDER_GUIDE: 'on', PG_RESTORE_ESCAPED: 'on' })
  const guide = (await compose(hooks, $)).sections.find(section => section.id === 'promptguard:placeholder-guide')
  assert.ok(guide.text.includes('\\[TYPE_N\\]'))
})

test('guide on by default (unset or empty), with the escaped form since PG_RESTORE_ESCAPED is on by default too', async () => {
  for (const value of [null, '']) {
    const { hooks, $ } = await load({ PG_PLACEHOLDER_GUIDE: value, PG_RESTORE_ESCAPED: value })
    const { sections } = await compose(hooks, $)
    assert.deepEqual(sections.map(section => section.id), ['intro', 'promptguard:placeholder-guide'], JSON.stringify(value))
    assert.ok(sections.at(-1).text.includes('\\[TYPE_N\\]'))
  }
})

test('guide off: the composed prompt is unchanged', async () => {
  for (const value of ['off', 'no']) {
    const { hooks, $ } = await load({ PG_PLACEHOLDER_GUIDE: value })
    assert.deepEqual((await compose(hooks, $)).sections.map(section => section.id), ['intro'])
  }
})

// ---- escaped restore

const ESCAPED = '\\[TOKEN_1\\]'
const REGEX_ESCAPED = 'SYNTHtok\\.en\\$x7Qk2/m\\+R9' // ERE/rg: . $ + escaped
const BRE_ESCAPED = 'SYNTHtok\\.en\\$x7Qk2/m+R9' // BRE: + is literal

test('escaped restore on by default: the Grep pattern gets the regex-escaped value', async () => {
  const { hooks, $ } = await load()
  await read(hooks, $, `TOKEN=${TOKEN}`)
  assert.equal((await run(hooks, $, { tool: 'Grep', pattern: ESCAPED })).pattern, REGEX_ESCAPED)
})

test('escaped restore off: \\[TOKEN_1\\] stays as written', async () => {
  const { hooks, $ } = await load({ PG_RESTORE_ESCAPED: 'off' })
  await read(hooks, $, `TOKEN=${TOKEN}`)
  assert.equal((await run(hooks, $, { tool: 'Grep', pattern: ESCAPED })).pattern, ESCAPED)
  assert.equal((await run(hooks, $, { tool: 'Bash', command: `grep '${ESCAPED}' app.log` })).command, `grep '${ESCAPED}' app.log`)
})

test('escaped restore on: the Grep pattern gets the regex-escaped value', async () => {
  const { hooks, $, audit } = await load({ PG_RESTORE_ESCAPED: 'on' })
  await read(hooks, $, `TOKEN=${TOKEN}`)
  assert.equal((await run(hooks, $, { tool: 'Grep', pattern: `key=${ESCAPED}$`, path: 'src' })).pattern, `key=${REGEX_ESCAPED}$`)
  const started = audit.filter(row => row.event === 'tool_started' && row.tool === 'Grep').at(-1)
  assert.equal(started.restored_count, 1)
  assert.ok(!JSON.stringify(audit).includes(TOKEN), 'no value in the audit')
})

test('escaped restore on: grep, rg and sed arguments, by regex dialect and shell quoting', async () => {
  const { hooks, $ } = await load({ PG_RESTORE_ESCAPED: 'on' })
  await read(hooks, $, `TOKEN=${TOKEN}`)
  const cases = [
    [`grep '${ESCAPED}' app.log`, `grep '${BRE_ESCAPED}' app.log`],
    [`grep -E '${ESCAPED}' app.log`, `grep -E '${REGEX_ESCAPED}' app.log`],
    [`cat app.log | rg -n '${ESCAPED}'`, `cat app.log | rg -n '${REGEX_ESCAPED}'`],
    // double quotes: the shell removes one backslash level and expands $, so both are escaped again
    [`rg "${ESCAPED}" src`, `rg "${REGEX_ESCAPED.replaceAll('\\', '\\\\').replaceAll('$', '\\$')}" src`],
    // sed's default delimiter / is escaped as well
    [`sed -n '/${ESCAPED}/p' app.log`, `sed -n '/${BRE_ESCAPED.replaceAll('/', '\\/')}/p' app.log`],
    [`grep -F '${ESCAPED}' app.log`, `grep -F '${TOKEN}' app.log`],
  ]
  for (const [command, expected] of cases) assert.equal((await run(hooks, $, { tool: 'Bash', command })).command, expected, command)
})

test('escaped restore on: not in other commands, not without brackets, not for unknown placeholders', async () => {
  const { hooks, $ } = await load({ PG_RESTORE_ESCAPED: 'on' })
  await read(hooks, $, `TOKEN=${TOKEN}`)
  for (const command of [`echo '${ESCAPED}'`, 'grep TOKEN_1 app.log', 'grep "TOKEN_1" app.log', "grep '\\[TOKEN_9\\]' app.log"]) {
    assert.equal((await run(hooks, $, { tool: 'Bash', command })).command, command, command)
  }
  // the plain form still restores everywhere it did
  assert.equal((await run(hooks, $, { tool: 'Bash', command: 'grep -F "[TOKEN_1]" app.log' })).command, `grep -F "${TOKEN}" app.log`)
})
