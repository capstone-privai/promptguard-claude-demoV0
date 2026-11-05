// Placeholder numbering tests for the Native Mod. Run: node --test tests/mod/test_placeholder_numbering.mjs
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

// Synthetic values only.
const KEY = 'pgSynthKey_8vM2qR7xK4pL9sN3'
const OLD_PASSWORD = 'SynthOldPass!41a'
const NEW_PASSWORD = 'SynthNewPass!72b'
const hash = raw => createHash('sha256').update(raw).digest('hex')

// Fake detector that names a value by its context, like the real ensemble: the same key is SECRET
// after `"secret": "` and API_KEY after `API_KEY=`.
const CONTEXTS = [['"secret": "', 'SECRET'], ['API_KEY=', 'API_KEY'], ['PASSWORD=', 'PASSWORD'], ['PASSWORD_OLD=', 'PASSWORD']]
function fakeScan(items) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      for (const raw of [KEY, OLD_PASSWORD, NEW_PASSWORD]) {
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

async function load() {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const audit = []
  const $ = {
    env: { get: async key => (key === 'PG_MOD_AUDIT' ? 'audit.json' : undefined) },
    fs: { write: async (_path, text) => { audit.splice(0, audit.length, ...JSON.parse(text)) } },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items)) }] }) },
  }
  return { hooks, $, audit }
}

async function read(hooks, $, content) {
  const result = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 't', file_path: 'x' }, () => ({ result: { type: 'text', file: { content } } }))
  return result.result.file.content
}

// (a) metric-task t15: one key, two detector types, two placeholders.
test('the same value keeps its first placeholder when a later finding names another type', async () => {
  const { hooks, $ } = await load()
  assert.equal(await read(hooks, $, `{ "secret": "${KEY}" }`), '{ "secret": "[SECRET_1]" }')
  assert.equal(await read(hooks, $, `API_KEY=${KEY}`), 'API_KEY=[SECRET_1]')
})

test('a value seen under two types in one text gets one placeholder', async () => {
  const { hooks, $ } = await load()
  assert.equal(await read(hooks, $, `API_KEY=${KEY}\n{ "secret": "${KEY}" }`), 'API_KEY=[API_KEY_1]\n{ "secret": "[API_KEY_1]" }')
})

test('the shared placeholder restores to the value and its audit rows name it', async () => {
  const { hooks, $, audit } = await load()
  await read(hooks, $, `{ "secret": "${KEY}" }`)
  await read(hooks, $, `API_KEY=${KEY}`)
  let executed
  await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 'b', command: 'curl -H "x-key: [SECRET_1]"' }, input => { executed = input; return { result: { stdout: '', stderr: '' } } })
  assert.equal(executed.command, `curl -H "x-key: ${KEY}"`)
  const placeholders = audit.flatMap(row => row.findings || []).map(finding => `${finding.secret_type}:${finding.placeholder}`)
  assert.deepEqual(placeholders, ['SECRET:[SECRET_1]', 'API_KEY:[SECRET_1]'])
  assert.ok(!JSON.stringify(audit).includes(KEY))
})

test('a different value of the second type still gets its own number', async () => {
  const { hooks, $ } = await load()
  await read(hooks, $, `{ "secret": "${KEY}" }`)
  assert.equal(await read(hooks, $, `PASSWORD=${NEW_PASSWORD}`), 'PASSWORD=[PASSWORD_1]')
})

// (b) numbering follows the text, top to bottom.
test('placeholders are numbered from the top of a .env, not the bottom', async () => {
  const { hooks, $ } = await load()
  const env = `PASSWORD_OLD=${OLD_PASSWORD}\nHOST=db\nPASSWORD=${NEW_PASSWORD}\n`
  assert.equal(await read(hooks, $, env), 'PASSWORD_OLD=[PASSWORD_1]\nHOST=db\nPASSWORD=[PASSWORD_2]\n')
})

test('a value repeated in one text keeps the number of its first appearance', async () => {
  const { hooks, $ } = await load()
  const env = `PASSWORD=${NEW_PASSWORD}\nPASSWORD_OLD=${OLD_PASSWORD}\nPASSWORD_OLD=${OLD_PASSWORD}\n`
  assert.equal(await read(hooks, $, env), 'PASSWORD=[PASSWORD_1]\nPASSWORD_OLD=[PASSWORD_2]\nPASSWORD_OLD=[PASSWORD_2]\n')
})

test('numbers follow the order of strings in one payload too', async () => {
  const { hooks, $ } = await load()
  let sent
  await hooks['prompt.submit']($, { text: `PASSWORD=${NEW_PASSWORD}`, context: [`PASSWORD=${OLD_PASSWORD}`] }, e => { sent = e; return e })
  assert.equal(sent.text, 'PASSWORD=[PASSWORD_1]')
  assert.deepEqual(sent.context, ['PASSWORD=[PASSWORD_2]'])
})
