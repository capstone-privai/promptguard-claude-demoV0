// Re-mask admission tests for the Native Mod. Run: node --test tests/mod/test_remask_admission.mjs
//
// PG_REMASK_POLICY=admitted: a value the detector found is still masked where it was found, but it is
// re-masked elsewhere (whole or in part) only if a high-confidence rule found it, it looks like a secret,
// or it was restored into a command.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const hash = raw => createHash('sha256').update(raw).digest('hex')

// Synthetic values only.
const IDENT = 'buildCacheDirectory' // a low-confidence rule's false positive: an identifier
const RANDOM = 'SYNTHx7Qk2mR9vL4wP' // looks like a secret
const HEX = '0123456789abcdef0123456789abcdef' // a hex shape, found by a high-confidence rule

// Fake detector: a value is found only after its key, with the rule and adapter a real ensemble gives.
const KEYS = [
  ['password=', 'PASSWORD', 'Password', ['credsweeper']],
  ['secret: ', 'SECRET', 'generic-api-key+secret-assignment', ['gitleaks', 'promptguard-rules']],
  ['bearer ', 'TOKEN', 'Bearer Authorization', ['credsweeper']],
]
function fakeScan(items, values) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      for (const raw of values) {
        for (const [key, type, rule, detectors] of KEYS) {
          let index = item.text.indexOf(key + raw)
          while (index !== -1) {
            const start = index + key.length
            findings.push({ type, rule_id: rule, detectors, start, end: start + raw.length, value_hash: hash(raw), offset_unit: 'utf16_code_units' })
            index = item.text.indexOf(key + raw, index + 1)
          }
        }
      }
      findings.sort((a, b) => a.start - b.start)
      return { id: item.id, ok: true, findings, errors: [] }
    }),
  }
}

async function load(policy, { values = [IDENT, RANDOM, HEX], read = file => readFile(file, 'utf8') } = {}) {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const $ = {
    env: { get: async key => (key === 'PG_REMASK_POLICY' ? policy : null) },
    fs: { write: async () => {}, read },
    plugin: { root: path.join(ROOT, 'src', 'native-mod') },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items, values)) }] }) },
  }
  return { hooks, $ }
}

async function read(hooks, $, content) {
  const result = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 't', file_path: 'x' }, () => ({ result: { type: 'text', file: { content } } }))
  return result.result.file.content
}

async function bash(hooks, $, command, stdout = 'done') {
  let ran
  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't', command }, e => { ran = e.command; return { result: { stdout, stderr: '', interrupted: false } } })
  return { ran, output: result.result.stdout }
}

// A long file where the value is found once, after its key, and then used 20 more times.
const longFile = value => [`password=${value}`, ...Array.from({ length: 20 }, (_, i) => `line ${i}: cache = ${value}`)].join('\n')
const count = (text, part) => text.split(part).length - 1

test('admitted: a low-confidence false positive is masked where found, not where it repeats', async () => {
  const { hooks, $ } = await load('admitted')
  const out = await read(hooks, $, longFile(IDENT))
  assert.equal(count(out, '[PASSWORD_1]'), 1)
  assert.equal(count(out, IDENT), 20)
  assert.equal((await bash(hooks, $, 'ls', `${IDENT}\n`)).output, `${IDENT}\n`)
})

test('all: the same false positive is masked everywhere, as before', async () => {
  for (const policy of [null, 'all', 'something-else']) {
    const { hooks, $ } = await load(policy)
    const out = await read(hooks, $, longFile(IDENT))
    assert.equal(count(out, '[PASSWORD_1]'), 21, String(policy))
    assert.equal(count(out, IDENT), 0)
  }
})

test('admitted: a value that looks like a secret is re-masked wherever it repeats', async () => {
  const { hooks, $ } = await load('admitted')
  const out = await read(hooks, $, longFile(RANDOM))
  assert.equal(count(out, '[PASSWORD_1]'), 21)
  assert.equal((await bash(hooks, $, 'env', `X=${RANDOM}\n`)).output, 'X=[PASSWORD_1]\n')
})

test('admitted: a high-confidence rule admits a value whatever its shape', async () => {
  const { hooks, $ } = await load('admitted')
  await read(hooks, $, `Authorization: bearer ${HEX}`)
  assert.equal((await bash(hooks, $, 'cat log', `used ${HEX} today\n`)).output, 'used [TOKEN_1] today\n')
  // The same hex found only by a low-confidence rule stays out of the list.
  const low = await load('admitted')
  await read(low.hooks, low.$, `password=${HEX}`)
  assert.equal((await bash(low.hooks, low.$, 'cat log', `used ${HEX} today\n`)).output, `used ${HEX} today\n`)
})

test('admitted: a value restored into a command is re-masked in its output', async () => {
  const { hooks, $ } = await load('admitted')
  await read(hooks, $, `password=${IDENT}`)
  const { ran, output } = await bash(hooks, $, "printf '%s\\n' '[PASSWORD_1]'", `${IDENT}\n`)
  assert.equal(ran, `printf '%s\\n' '${IDENT}'`)
  assert.equal(output, '[PASSWORD_1]\n')
})

test('restoring gives the value character for character in both policies', async () => {
  for (const policy of ['all', 'admitted']) {
    const { hooks, $ } = await load(policy)
    await read(hooks, $, `password=${IDENT}\nsecret: ${RANDOM}`)
    const { ran } = await bash(hooks, $, 'deploy --a [PASSWORD_1] --b [SECRET_1]')
    assert.equal(ran, `deploy --a ${IDENT} --b ${RANDOM}`, policy)
  }
})

test('admitted: partial re-masking only touches values on the re-mask list', async () => {
  const { hooks, $ } = await load('admitted', { values: [RANDOM, 'Zq8nW3xL5vT1kR7mY'] })
  await read(hooks, $, `password=${RANDOM}`)
  const part = RANDOM.slice(0, 12)
  assert.equal((await bash(hooks, $, 'head -c 12 key', `${part}\n`)).output, '[PASSWORD_1_PART]\n')

  const ident = await load('admitted', { values: ['deployStagingCluster'] })
  await read(ident.hooks, ident.$, 'password=deployStagingCluster')
  assert.equal((await bash(ident.hooks, ident.$, 'x', 'deployStaging\n')).output, 'deployStaging\n')
})

test('admitted: an unreadable rule list falls back to all, the masking side', async () => {
  const { hooks, $ } = await load('admitted', { read: async () => { throw new Error('ENOENT') } })
  const out = await read(hooks, $, longFile(IDENT))
  assert.equal(count(out, IDENT), 0)
})

test('all: the rule list is never read', async () => {
  let reads = 0
  const { hooks, $ } = await load('all', { read: async () => { reads++; return '{}' } })
  await read(hooks, $, longFile(IDENT))
  assert.equal(reads, 0)
})

test('admitted: each shape in the shared fixture is admitted only when it looks like a secret', async () => {
  const { cases } = JSON.parse(await readFile(path.join(ROOT, 'tests', 'fixtures', 'remask_shapes.json'), 'utf8'))
  for (const [value, shape] of cases) {
    const { hooks, $ } = await load('admitted', { values: [value] })
    await read(hooks, $, `password=${value}`)
    const { output } = await bash(hooks, $, 'x', `\n${value}\n`)
    assert.equal(!output.includes(value), shape === 'secret_like', `${shape} (length ${value.length})`)
  }
})
