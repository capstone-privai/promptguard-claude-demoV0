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

// `!` shell-mode rows reach the session only through session.append (door `command`).
async function append(hooks, $, door, content) {
  let stored
  await hooks['session.append']($, { door, origin: { kind: 'unclassified' }, uuid: 'u1', message: { type: 'user', role: 'user', content } }, e => { stored = e; return {} })
  return stored
}

test('shell-mode input and output are masked before the row is stored or sent', async () => {
  const { hooks, $ } = await load()
  const input = await append(hooks, $, 'command', [{ type: 'text', text: `<bash-input>echo DB_PASSWORD=${PASSWORD}</bash-input>` }])
  const output = await append(hooks, $, 'command', [{ type: 'text', text: `<bash-stdout>DB_PASSWORD=${PASSWORD}\nAPI_TOKEN=${TOKEN}</bash-stdout><bash-stderr></bash-stderr>` }])

  assert.equal(input.message.content[0].text, '<bash-input>echo DB_PASSWORD=[PASSWORD_1]</bash-input>')
  assert.equal(output.message.content[0].text, '<bash-stdout>DB_PASSWORD=[PASSWORD_1]\nAPI_TOKEN=[TOKEN_1]</bash-stdout><bash-stderr></bash-stderr>')
  assert.equal(output.door, 'command')
  assert.equal(output.uuid, 'u1')

  // The same placeholder still restores for a later model-issued Bash call.
  let executed
  await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't6', command: 'psql -p [PASSWORD_1]' }, e => { executed = e; return { result: 'ok' } })
  assert.equal(executed.command, `psql -p ${PASSWORD}`)
})

test('tool_result text in an unsanitized row is masked; non-text blocks pass through', async () => {
  const { hooks, $ } = await load()
  const image = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } }
  const stored = await append(hooks, $, 'tool-message', [
    { type: 'tool_result', tool_use_id: 'x', content: [{ type: 'text', text: `TOKEN=${TOKEN}` }, image] },
    { type: 'tool_result', tool_use_id: 'y', content: `PASS=${PASSWORD}` },
  ])
  assert.equal(stored.message.content[0].content[0].text, 'TOKEN=[TOKEN_1]')
  assert.deepEqual(stored.message.content[0].content[1], image)
  assert.equal(stored.message.content[1].content, 'PASS=[PASSWORD_1]')
})

test('rows already sanitized by other hooks are not rescanned', async () => {
  const { hooks, $ } = await load()
  let scans = 0
  const call = $.mcp.call
  $.mcp.call = async (...args) => { scans++; return call(...args) }
  for (const door of ['prompt', 'tool-result', 'response', 'attachment', 'compaction']) {
    const stored = await append(hooks, $, door, [{ type: 'text', text: `DB_PASSWORD=${PASSWORD}` }])
    assert.equal(stored.message.content[0].text, `DB_PASSWORD=${PASSWORD}`)
  }
  assert.equal(scans, 0)
})

test('a detector failure on a shell-mode row fails closed without storing it', async () => {
  const { hooks, $ } = await load({ PG_MOD_CONNECT_WAIT_MS: '0' })
  $.mcp.call = async () => { throw new Error('down') }
  let stored = false
  await assert.rejects(hooks['session.append']($, { door: 'command', origin: { kind: 'unclassified' }, uuid: 'u2', message: { type: 'user', role: 'user', content: [{ type: 'text', text: `DB_PASSWORD=${PASSWORD}` }] } }, () => { stored = true; return {} }), /PromptGuard detector failure/)
  assert.equal(stored, false)
})

// The engine connects the pgdetector MCP server after the session starts; early hooks must wait, not be skipped.
const notConnected = () => new Error('$.mcp.call: no connected MCP tool "scan_batch" on a server named "pgdetector"')

test('hooks that run before the detector connects wait for it instead of failing', async () => {
  const { hooks, $ } = await load()
  const call = $.mcp.call
  let attempts = 0
  $.mcp.call = async (...args) => { if (++attempts < 3) throw notConnected(); return call(...args) }
  const stored = await append(hooks, $, 'command', [{ type: 'text', text: `<bash-stdout>DB_PASSWORD=${PASSWORD}</bash-stdout>` }])
  assert.equal(attempts, 3)
  assert.equal(stored.message.content[0].text, '<bash-stdout>DB_PASSWORD=[PASSWORD_1]</bash-stdout>')
})

test('a detector that never connects fails closed after the bounded wait', async () => {
  const { hooks, $ } = await load({ PG_MOD_CONNECT_WAIT_MS: '300' })
  $.mcp.call = async () => { throw notConnected() }
  const started = Date.now()
  await assert.rejects(maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`), /PromptGuard detector failure/)
  assert.ok(Date.now() - started >= 250)
})

test('once connected, a later detector failure fails at once without waiting', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, 'hello')
  $.mcp.call = async () => { throw new Error('down') }
  const started = Date.now()
  await assert.rejects(maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`), /PromptGuard detector failure/)
  assert.ok(Date.now() - started < 1000)
})
