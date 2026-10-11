// Placeholder restore tests for the Native Mod. Run: node --test tests/mod/test_restore.mjs
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

const PASSWORD = 'MyS3cretPass!2026'
const TOKEN = 'pgdemoToken_4mN8qR2vX7kP5sL9'

// Fake detector: finds the synthetic values above by exact match, like the CredSweeper worker contract.
function fakeScan(items) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      for (const [raw, type] of [[PASSWORD, 'PASSWORD'], [TOKEN, 'TOKEN']]) {
        // Only detects values in "key=value" context, so bare echoes must be caught by re-masking.
        let index = item.text.indexOf(`=${raw}`)
        while (index !== -1) {
          findings.push({ type, start: index + 1, end: index + 1 + raw.length, value_hash: createHash('sha256').update(raw).digest('hex'), offset_unit: 'utf16_code_units', source: item.source })
          index = item.text.indexOf(`=${raw}`, index + 1)
        }
      }
      findings.sort((a, b) => a.start - b.start)
      return { id: item.id, ok: true, findings, errors: [] }
    }),
  }
}

async function load(env = {}) {
  // Fresh module instance per test so the in-memory vault starts empty.
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler })
  const $ = {
    env: { get: async key => env[key] },
    fs: { write: async () => {} },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items)) }] }) },
  }
  return { hooks, $ }
}

async function maskPrompt(hooks, $, text) {
  let sent
  await hooks['prompt.submit']($, { text, context: [] }, e => { sent = e; return e })
  return sent.text
}

test('placeholders in a Bash command are restored right before execution and re-masked after', async () => {
  const { hooks, $ } = await load()
  const masked = await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD} API_TOKEN=${TOKEN}`)
  assert.equal(masked, 'DB_PASSWORD=[PASSWORD_1] API_TOKEN=[TOKEN_1]')

  let executed
  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't1', command: 'psql -p [PASSWORD_1] && echo [TOKEN_1] [UNKNOWN_9]' }, input => {
    executed = input
    return { result: { stdout: `${PASSWORD}\n${TOKEN}\n`, stderr: '' } }
  })

  assert.equal(executed.command, `psql -p ${PASSWORD} && echo ${TOKEN} [UNKNOWN_9]`)
  assert.equal(executed.tool, 'Bash')
  assert.equal(executed.tool_use_id, 't1')
  assert.equal(result.result.stdout, '[PASSWORD_1]\n[TOKEN_1]\n')
})

test('nested Edit inputs are restored so old_string matches the real file', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`)

  let executed
  await hooks['tool.call']($, { tool: 'MultiEdit', tool_use_id: 't2', file_path: '.env', edits: [{ old_string: 'DB_PASSWORD=[PASSWORD_1]', new_string: 'DB_PASSWORD=[PASSWORD_1]\nDB_PORT=5432' }] }, input => {
    executed = input
    return { result: 'ok' }
  })

  assert.deepEqual(executed.edits, [{ old_string: `DB_PASSWORD=${PASSWORD}`, new_string: `DB_PASSWORD=${PASSWORD}\nDB_PORT=5432` }])
})

test('model-bound tools never receive raw values', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`)

  let executed
  await hooks['tool.call']($, { tool: 'Agent', tool_use_id: 't3', prompt: 'check [PASSWORD_1]' }, input => {
    executed = input
    return { result: 'done' }
  })

  assert.equal(executed.prompt, 'check [PASSWORD_1]')
})

test('PG_RESTORE_PLACEHOLDERS=off disables restore', async () => {
  const { hooks, $ } = await load({ PG_RESTORE_PLACEHOLDERS: 'off' })
  await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`)

  let executed
  await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't4', command: 'echo [PASSWORD_1]' }, input => {
    executed = input
    return { result: 'x' }
  })

  assert.equal(executed.command, 'echo [PASSWORD_1]')
})

test('a denied call does not echo the restored raw value', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`)

  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't5', command: 'echo [PASSWORD_1]' }, input => ({ deny: `blocked: ${input.command}` }))

  assert.equal(result.deny, 'blocked: echo [PASSWORD_1]')
})
