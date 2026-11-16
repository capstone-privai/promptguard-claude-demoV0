// Public-prefix placeholder tests for the Native Mod. Run: node --test tests/mod/test_public_prefix.mjs
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

// Synthetic values only. Joined at run time so no complete provider-shaped value sits in the repository.
const STRIPE_PREFIX = ['sk', 'live', ''].join('_')
const STRIPE = `${STRIPE_PREFIX}SYNTHxFAKExVALUExONLYx0001` // the rest is 26 characters
const STRIPE_2 = `${STRIPE_PREFIX}SYNTHxFAKExVALUExONLYx0002`
const AWS_TEMP = `${['AS', 'IA'].join('')}SYNTHFAKEVALUE01` // the rest is exactly 16 characters
const GITHUB_PAT = `${['github', 'pat', ''].join('_')}SYNTHxFAKExVALUExONLYx0003`
const SHORT_REST = `${STRIPE_PREFIX}SYNTHxSHORT0004` // the rest is 15 characters
const UNKNOWN = 'pgSynthKey_8vM2qR7xK4pL9sN3'
const hash = raw => createHash('sha256').update(raw).digest('hex')
const ALL = [STRIPE, STRIPE_2, AWS_TEMP, GITHUB_PAT, SHORT_REST, UNKNOWN]

// Fake detector that names a value by its context, like the real ensemble: the same key is SECRET
// after `"secret": "` and API_KEY after `API_KEY=`. A bare value is not found, so it relies on re-masking.
const CONTEXTS = [['"secret": "', 'SECRET'], ['API_KEY=', 'API_KEY'], ['TOKEN=', 'TOKEN']]
function fakeScan(items) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      for (const raw of ALL) {
        for (const [prefix, type] of CONTEXTS) {
          let index = item.text.indexOf(prefix + raw)
          while (index !== -1) {
            const start = index + prefix.length
            findings.push({ type, start, end: start + raw.length, value_hash: hash(raw), offset_unit: 'utf16_code_units' })
            index = item.text.indexOf(prefix + raw, index + 1)
          }
        }
      }
      findings.sort((a, b) => a.start - b.start)
      return { id: item.id, ok: true, findings, errors: [] }
    }),
  }
}

async function load(option = 'on', { read = file => readFile(file, 'utf8') } = {}) {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const $ = {
    env: { get: async key => (key === 'PG_PLACEHOLDER_PUBLIC_PREFIX' ? option : undefined) },
    fs: { write: async () => {}, read },
    plugin: { root: path.join(ROOT, 'src', 'native-mod') },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items)) }] }) },
  }
  return { hooks, $ }
}

async function mask(hooks, $, text) {
  let sent
  await hooks['prompt.submit']($, { text, context: [] }, e => { sent = e; return e })
  return sent.text
}

async function readFileResult(hooks, $, content, file = 'x') {
  const result = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 't', file_path: file }, () => ({ result: { type: 'text', file: { content } } }))
  return result.result.file.content
}

// Runs Bash: returns the command the tool really got and what goes back to the model.
async function bash(hooks, $, command, stdout = 'done') {
  let ran
  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't', command }, e => { ran = e.command; return { result: { stdout, stderr: '', interrupted: false } } })
  return { ran, output: result.result.stdout }
}

const PREFIXED = `${STRIPE_PREFIX}[STRIPE_SECRET_KEY_1]`

test('a value with a public prefix is masked as prefix + [TYPE_N]', async () => {
  const { hooks, $ } = await load()
  assert.equal(await mask(hooks, $, `API_KEY=${STRIPE}`), `API_KEY=${PREFIXED}`)
  assert.equal(await mask(hooks, $, `TOKEN=${AWS_TEMP}`), `TOKEN=${AWS_TEMP.slice(0, 4)}[AWS_ACCESS_KEY_ID_1]`)
  assert.equal(await mask(hooks, $, `TOKEN=${GITHUB_PAT}`), `TOKEN=${GITHUB_PAT.slice(0, 11)}[GITHUB_TOKEN_1]`, 'the longest prefix in the table is used')
})

test('the same value gets the same result from any file and any detected type', async () => {
  const { hooks, $ } = await load()
  assert.equal(await readFileResult(hooks, $, `{ "secret": "${STRIPE}" }`, 'a.json'), `{ "secret": "${PREFIXED}" }`)
  assert.equal(await readFileResult(hooks, $, `API_KEY=${STRIPE}`, 'b.env'), `API_KEY=${PREFIXED}`)
  assert.equal(await mask(hooks, $, `TOKEN=${STRIPE}`), `TOKEN=${PREFIXED}`)
})

test('numbers follow the whole value, so two values with one prefix differ', async () => {
  const { hooks, $ } = await load()
  assert.equal(await mask(hooks, $, `API_KEY=${STRIPE} TOKEN=${STRIPE_2}`), `API_KEY=${PREFIXED} TOKEN=${STRIPE_PREFIX}[STRIPE_SECRET_KEY_2]`)
})

test('restoring before Bash gives the whole value, character for character', async () => {
  const { hooks, $ } = await load()
  await mask(hooks, $, `API_KEY=${STRIPE}`)
  const { ran } = await bash(hooks, $, `curl -u '${PREFIXED}:' https://example.test`)
  assert.equal(ran, `curl -u '${STRIPE}:' https://example.test`)
})

test('a placeholder the model wrote without the prefix still restores the whole value', async () => {
  const { hooks, $ } = await load()
  await mask(hooks, $, `API_KEY=${STRIPE}`)
  const { ran } = await bash(hooks, $, "export K='[STRIPE_SECRET_KEY_1]'")
  assert.equal(ran, `export K='${STRIPE}'`)
})

test('the whole value in command output goes back to prefix + [TYPE_N]', async () => {
  const { hooks, $ } = await load()
  await mask(hooks, $, `API_KEY=${STRIPE}`)
  const { output } = await bash(hooks, $, `echo ${PREFIXED}`, `${STRIPE}\n`)
  assert.equal(output, `${PREFIXED}\n`)
})

test('part of the rest in command output is masked as [TYPE_N_PART]', async () => {
  const { hooks, $ } = await load()
  await mask(hooks, $, `API_KEY=${STRIPE}`)
  const rest = STRIPE.slice(STRIPE_PREFIX.length)
  const part = rest.slice(0, 14)
  const { output } = await bash(hooks, $, 'head -c 14 key', `value: ${part}\n`)
  assert.equal(output, 'value: [STRIPE_SECRET_KEY_1_PART]\n')
  assert.ok(!output.includes(part))
})

test('a run of half the rest counts as a part, and the prefix alone never does', async () => {
  const { hooks, $ } = await load()
  await mask(hooks, $, `API_KEY=${STRIPE}`)
  const rest = STRIPE.slice(STRIPE_PREFIX.length)
  const half = Math.ceil(rest.length / 2)
  assert.equal((await bash(hooks, $, 'x', `a ${rest.slice(0, half)} b`)).output, 'a [STRIPE_SECRET_KEY_1_PART] b')
  assert.equal((await bash(hooks, $, 'x', `a ${rest.slice(0, half - 1)} b`)).output, `a ${rest.slice(0, half - 1)} b`)
  assert.equal((await bash(hooks, $, 'x', `prefix ${STRIPE_PREFIX} only`)).output, `prefix ${STRIPE_PREFIX} only`)
  assert.equal((await bash(hooks, $, 'x', `${STRIPE_PREFIX}${rest.slice(0, 14)}`)).output, `${STRIPE_PREFIX}[STRIPE_SECRET_KEY_1_PART]`)
})

test('a value not in the table, or with a rest under 16 characters, is masked whole as before', async () => {
  const { hooks, $ } = await load()
  assert.equal(await mask(hooks, $, `API_KEY=${UNKNOWN}`), 'API_KEY=[API_KEY_1]')
  assert.equal(await mask(hooks, $, `TOKEN=${SHORT_REST}`), 'TOKEN=[TOKEN_1]')
  const { ran, output } = await bash(hooks, $, 'echo [TOKEN_1] [API_KEY_1]', `${SHORT_REST}\n`)
  assert.equal(ran, `echo ${SHORT_REST} ${UNKNOWN}`)
  assert.equal(output, '[TOKEN_1]\n')
})

test('with the option off nothing changes and the table is not read', async () => {
  for (const option of [null, 'off']) {
    let reads = 0
    const { hooks, $ } = await load(option, { read: async () => { reads++; return '' } })
    assert.equal(await mask(hooks, $, `API_KEY=${STRIPE}`), 'API_KEY=[API_KEY_1]')
    assert.equal(await readFileResult(hooks, $, `{ "secret": "${STRIPE}" }`), '{ "secret": "[API_KEY_1]" }')
    const { ran, output } = await bash(hooks, $, 'echo [API_KEY_1]', `${STRIPE}\n`)
    assert.equal(ran, `echo ${STRIPE}`)
    assert.equal(output, '[API_KEY_1]\n')
    assert.equal(reads, 0)
  }
})

test('an unreadable table masks whole, the safe way', async () => {
  const { hooks, $ } = await load('on', { read: async () => { throw new Error('ENOENT') } })
  assert.equal(await mask(hooks, $, `API_KEY=${STRIPE}`), 'API_KEY=[API_KEY_1]')
})

test('the table in docs has the confirmed prefixes and not the unconfirmed ones', async () => {
  const table = await readFile(path.join(ROOT, 'docs', 'PLACEHOLDER_PUBLIC_PREFIXES.md'), 'utf8')
  const rows = [...table.matchAll(/^\| `([^`]+)` \| ([A-Z][A-Z0-9_]*) \| (https:\/\/\S+) \| \S/gm)].map(row => row[1])
  assert.equal(rows.length, 17)
  for (const prefix of [`${STRIPE_PREFIX}`, 'AKIA', 'ASIA', 'ghp_', 'github_pat_', 'xoxb-', 'sk-ant-', 'glpat-']) assert.ok(rows.includes(prefix), prefix)
  for (const prefix of ['sk-proj-', 'AIza']) assert.ok(!rows.includes(prefix), prefix)
})
