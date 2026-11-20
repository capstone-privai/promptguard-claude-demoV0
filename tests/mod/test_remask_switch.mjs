// PG_REMASK=on|off (default on) for the Native Mod. Run: node --test tests/mod/test_remask_switch.mjs
//
// One synthetic session per run: a file read with a password the (fake) detector finds after PASSWORD=, then a Bash
// call that uses the placeholder and prints the value alone, part of it, and inside other text, where the detector
// does not find it. on: the re-mask hides each re-appearance. off: they go out as they are (measurement only), while
// the vault still restores the placeholder in the Bash command. Synthetic values only; messages never print one.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

const hash = raw => createHash('sha256').update(raw).digest('hex')
const PASS = ['Synth', 'Remask', 'Pass', '!', '92', 'qDemo'].join('') // 21 characters
const PART = PASS.slice(0, 12)

function fakeScan(items) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      let at = item.text.indexOf(`PASSWORD=${PASS}`)
      while (at !== -1) {
        const start = at + 'PASSWORD='.length
        findings.push({ type: 'PASSWORD', rule_id: 'stub', start, end: start + PASS.length, value_hash: hash(PASS), offset_unit: 'utf16_code_units' })
        at = item.text.indexOf(`PASSWORD=${PASS}`, at + 1)
      }
      return { id: item.id, ok: true, findings, errors: [] }
    }),
  }
}

async function load(env = {}) {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const audit = []
  const $ = {
    env: { get: async key => env[key] ?? (key === 'PG_MOD_AUDIT' ? 'audit.json' : null) },
    fs: { write: async (file, text) => { if (file === 'audit.json') audit.splice(0, audit.length, ...JSON.parse(text)) } },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items)) }] }) },
  }
  return { hooks, $, audit }
}

// The session: read .env, then run a Bash command with the placeholder whose output repeats the value.
async function session(env) {
  const { hooks, $, audit } = await load(env)
  const read = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 'r', file_path: '.env' }, () => ({ result: { type: 'text', file: { content: `PASSWORD=${PASS}\n` } } }))
  let ran
  const stdout = `${PASS}\nfirst 12: ${PART}\nlogin ok for user:${PASS}@db\n`
  const bash = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 'b', command: "printf '%s\\n' '[PASSWORD_1]'" }, e => { ran = e.command; return { result: { stdout, stderr: '', interrupted: false } } })
  const denied = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 'd', command: 'false' }, () => ({ deny: `refused: ${PASS}` }))
  const reply = []
  for await (const chunk of hooks['turn.step']($, {}, async function* () { yield { kind: 'text', text: `The password is ${PASS}.` } })) reply.push(chunk.text)
  return { read: read.result.file.content, ran, out: bash.result.stdout, deny: denied.deny, reply: reply.join(''), audit }
}

const remasked = audit => audit.reduce((sum, row) => sum + (row.remasked_count || 0), 0)

test('on (default, unset or empty): every re-appearance of the restored value is hidden', async () => {
  for (const env of [{}, { PG_REMASK: '' }, { PG_REMASK: 'on' }]) {
    const run = await session(env)
    const label = JSON.stringify(env)
    assert.equal(run.read, 'PASSWORD=[PASSWORD_1]\n', label)
    assert.equal(run.ran, `printf '%s\\n' '${PASS}'`, `${label}: restored`)
    assert.equal(run.out, '[PASSWORD_1]\nfirst 12: [PASSWORD_1_PART]\nlogin ok for user:[PASSWORD_1]@db\n', label)
    assert.equal(run.deny, 'refused: [PASSWORD_1]', label)
    assert.equal(run.reply, 'The password is [PASSWORD_1].', label)
    assert.ok(!JSON.stringify(run.audit).includes(PASS) && !JSON.stringify(run.audit).includes(PART), `${label}: audit is raw-free`)
    assert.equal(remasked(run.audit), 4, `${label}: whole x2 and part x1 in stdout, whole x1 in the reply`)
  }
})

test('off: no whole or partial re-mask, the vault still restores the Bash command, and the audit counts 0', async () => {
  for (const value of ['off', 'OFF', 'no']) {
    const run = await session({ PG_REMASK: value })
    assert.equal(run.read, 'PASSWORD=[PASSWORD_1]\n', 'the detector pass still masks')
    assert.equal(run.ran, `printf '%s\\n' '${PASS}'`, 'restored')
    // Measurement only: what the detector does not find goes out as the tool printed it.
    assert.ok(run.out.startsWith(`${PASS}\n`), 'whole value not re-masked')
    assert.ok(run.out.includes(`first 12: ${PART}\n`), 'part not re-masked')
    assert.ok(!run.out.includes('[PASSWORD_1'), 'no placeholder in the output')
    assert.equal(run.deny, `refused: ${PASS}`)
    assert.equal(run.reply, `The password is ${PASS}.`)
    assert.equal(remasked(run.audit), 0)
    const bash = run.audit.find(row => row.tool === 'Bash' && row.event === 'tool_started')
    assert.equal(bash.restored_count, 1)
    assert.ok(run.audit.every(row => !('raw' in row)), 'no value field')
  }
})

test('off: the detector pass still masks a value it finds in the output', async () => {
  const { hooks, $ } = await load({ PG_REMASK: 'off' })
  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 'b', command: 'cat .env' }, () => ({ result: { stdout: `PASSWORD=${PASS}\n`, stderr: '', interrupted: false } }))
  assert.equal(result.result.stdout, 'PASSWORD=[PASSWORD_1]\n')
})
