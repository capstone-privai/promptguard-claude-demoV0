// Partial re-mask tests for the Native Mod. Run: node --test tests/mod/test_remask_partial.mjs
//
// A restored command can print only part of a secret (sed, cut, head -c). The full-value re-mask
// misses it, so a long enough run of the secret must be masked too.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

// Synthetic values only.
const PASSWORD = 'Qx7!mR2vK9pL4sNw' // 16 characters
const DEPLOY_PASSWORD = 'deploy-Pr0d!x7Qw' // starts like an ordinary word
const REPORT_TOKEN = 'reportTok_9vK2mQ'

const SECRETS = [[PASSWORD, 'PASSWORD'], [DEPLOY_PASSWORD, 'PASSWORD'], [REPORT_TOKEN, 'TOKEN']]

// Fake detector: finds the values only in "key=value" context, so bare output relies on re-masking.
function fakeScan(items, secrets) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      for (const [raw, type] of secrets) {
        let index = item.text.indexOf(`=${raw}`)
        while (index !== -1) {
          findings.push({ type, start: index + 1, end: index + 1 + raw.length, value_hash: createHash('sha256').update(raw).digest('hex'), offset_unit: 'utf16_code_units' })
          index = item.text.indexOf(`=${raw}`, index + 1)
        }
      }
      findings.sort((a, b) => a.start - b.start)
      return { id: item.id, ok: true, findings, errors: [] }
    }),
  }
}

async function load(secrets = SECRETS) {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const $ = {
    env: { get: async () => undefined },
    fs: { write: async () => {} },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items, secrets)) }] }) },
  }
  return { hooks, $ }
}

async function maskPrompt(hooks, $, text) {
  let sent
  await hooks['prompt.submit']($, { text, context: [] }, e => { sent = e; return e })
  return sent.text
}

// Runs a Bash call whose stdout is `stdout`, and returns what goes back to the model.
async function bashOutput(hooks, $, stdout, command = 'cat config/service.env') {
  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't', command }, () => ({ result: { stdout, stderr: '', interrupted: false } }))
  return result.result.stdout
}

for (const [label, part] of [
  ['first 12', PASSWORD.slice(0, 12)],
  ['last 10', PASSWORD.slice(-10)],
  ['middle 9', PASSWORD.slice(4, 13)],
]) {
  test(`the ${label} characters of a 16-character password printed by Bash are masked`, async () => {
    const { hooks, $ } = await load()
    assert.equal(await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`), 'DB_PASSWORD=[PASSWORD_1]')
    const out = await bashOutput(hooks, $, `DB_PASSWORD=${part}…(redacted)\n`, "sed -E 's/(=.{12}).*/\\1…(redacted)/' config/service.env")
    assert.equal(out, 'DB_PASSWORD=[PASSWORD_1_PART]…(redacted)\n')
    assert.ok(!out.includes(part))
  })
}

test('a part next to other text is masked without eating the text around it', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`)
  const out = await bashOutput(hooks, $, `prefix:${PASSWORD.slice(2, 14)}:suffix`)
  assert.equal(out, 'prefix:[PASSWORD_1_PART]:suffix')
})

test('the full value is still masked with the full placeholder', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`)
  assert.equal(await bashOutput(hooks, $, `${PASSWORD}\n${PASSWORD.slice(0, 12)}\n`), '[PASSWORD_1]\n[PASSWORD_1_PART]\n')
})

test('the _PART marker is not placeholder-shaped, so it is never restored to the full value', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`)
  let executed
  await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't2', command: 'echo [PASSWORD_1_PART] [PASSWORD_1]' }, input => { executed = input; return { result: { stdout: '', stderr: '' } } })
  assert.equal(executed.command, `echo [PASSWORD_1_PART] ${PASSWORD}`)
})

// False positives.
test('ordinary words that share only a prefix with a secret are left alone', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, `DEPLOY_PASSWORD=${DEPLOY_PASSWORD} REPORT_TOKEN=${REPORT_TOKEN}`)
  // "deploy-" and "reportT" are 7 characters of a secret, one short of the minimum.
  const text = 'deploy succeeded; report generated; deploy-staging tag; reportTip list\n'
  assert.equal(await bashOutput(hooks, $, text), text)
})

test('fragments shorter than 8 characters are left alone', async () => {
  const { hooks, $ } = await load()
  await maskPrompt(hooks, $, `DB_PASSWORD=${PASSWORD}`)
  const text = `${PASSWORD.slice(0, 7)} ${PASSWORD.slice(5, 12)} ${PASSWORD.slice(-7)}\n`
  assert.equal(await bashOutput(hooks, $, text), text)
})

test('for a long secret, a fragment shorter than half of it is left alone', async () => {
  const long = 'Lk3vN9qR2xM7pT5wZ8yB4cD6fG1hJ0sA' // 32 characters: 16 or more must match
  const { hooks, $ } = await load([[long, 'API_KEY']])
  await maskPrompt(hooks, $, `API_KEY=${long}`)
  assert.equal(await bashOutput(hooks, $, `${long.slice(0, 15)}\n`), `${long.slice(0, 15)}\n`)
  assert.equal(await bashOutput(hooks, $, `${long.slice(0, 16)}\n`), '[API_KEY_1_PART]\n')
})

test('a secret shorter than 8 characters is masked only when it appears whole', async () => {
  const short = 'Ab3$xY9' // 7 characters
  const { hooks, $ } = await load([[short, 'PASSWORD']])
  await maskPrompt(hooks, $, `PIN=${short}`)
  assert.equal(await bashOutput(hooks, $, `${short} ${short.slice(0, 6)}\n`), `[PASSWORD_1] ${short.slice(0, 6)}\n`)
})
