// Fail-closed tests for the Native Mod. Run: node --test tests/mod/test_fail_closed.mjs
//
// When the detector call fails, no hook may let unscanned text through. The engine skips a hook
// that throws and runs what is beneath it with the ORIGINAL input (types written by Claude Code
// 2.1.291: src/native-mod/.claude-plugin/types/claude-code/index.d.ts, EngineEventOf and
// Registration). `dispatch` below plays that part, including a registration's `.catch`.
import assert from 'node:assert/strict'
import { test } from 'node:test'

// Synthetic values only.
const PASSWORD = 'SynthFailPass!2026x'
const BLOCKED = '[PROMPTGUARD_BLOCKED: detector failure]'

const FAILURES = {
  // $.mcp.call throws: permission denied, bridge not connected.
  throw: async () => { throw new Error('$.mcp.call: permission denied for mcp__pgdetector__scan_batch') },
  // The bridge answers isError (worker timeout, body over 8MB, HTTP error).
  isError: async () => ({ isError: true, content: [{ type: 'text', text: 'DETECTOR_FAILURE' }] }),
  // A response of the wrong shape.
  malformed: async () => ({ isError: false, content: [{ type: 'text', text: '{"ok":true,"items":"nope"' }] }),
}

async function load(failure = 'throw') {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  const catches = {}
  register((name, handler) => {
    hooks[name] = handler
    return { catch: fn => { catches[name] = fn } }
  })
  const writes = []
  const $ = {
    env: { get: async key => ({ PG_MOD_CONNECT_WAIT_MS: '0', PG_MOD_AUDIT: 'audit.json' })[key] },
    fs: { write: async (_path, text) => { writes.push(text) } },
    mcp: { call: FAILURES[failure] },
  }
  return { hooks, catches, $, writes }
}

// Plays the engine: a hook that throws is skipped, so beneath runs with the original `e`, unless
// the registration's `.catch` answers in its place (its `next` replays a settled call).
async function dispatch({ hooks, catches }, name, $, e, core) {
  let called = false
  let settled
  const next = async arg => { called = true; settled = await core(arg); return settled }
  try {
    return await hooks[name]($, e, next)
  } catch (error) {
    if (!catches[name]) return called ? settled : core(e)
    const replay = Object.assign(async arg => (called ? settled : core(arg)), { error, called })
    return catches[name]($, e, replay)
  }
}

function assertNoRaw(value, label) {
  assert.ok(!JSON.stringify(value ?? null).includes(PASSWORD), `${label}: raw value reached the model side`)
}

for (const failure of Object.keys(FAILURES)) {
  test(`prompt.submit: a detector ${failure} sends the block marker, not the prompt`, async () => {
    const mod = await load(failure)
    let sent
    await dispatch(mod, 'prompt.submit', mod.$, { text: `DB_PASSWORD=${PASSWORD}`, context: [`old ${PASSWORD}`], wait: false }, e => { sent = e; return e })
    assert.equal(sent.text, BLOCKED)
    assert.deepEqual(sent.context, [BLOCKED])
    assert.equal(sent.wait, false)
    assertNoRaw(mod.writes, 'audit')
  })

  test(`tool.call: a detector ${failure} on the result denies it with the block marker`, async () => {
    const mod = await load(failure)
    let ran = false
    const result = await dispatch(mod, 'tool.call', mod.$, { tool: 'Bash', tool_use_id: 't1', command: 'cat .env' }, () => { ran = true; return { result: { stdout: `DB_PASSWORD=${PASSWORD}\n`, stderr: '', interrupted: false } } })
    assert.equal(ran, true)
    assert.deepEqual(result, { deny: BLOCKED })
    assertNoRaw(mod.writes, 'audit')
  })

  test(`session.append: a detector ${failure} stores the block marker, not the shell row`, async () => {
    const mod = await load(failure)
    let stored
    const image = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } }
    const e = { door: 'command', origin: { kind: 'unclassified' }, uuid: 'u1', message: { type: 'user', role: 'user', content: [{ type: 'text', text: `<bash-stdout>${PASSWORD}</bash-stdout>` }, image] } }
    await dispatch(mod, 'session.append', mod.$, e, row => { stored = row; return {} })
    assert.equal(stored.uuid, 'u1')
    assert.equal(stored.message.role, 'user')
    assert.equal(stored.message.content[0].text, BLOCKED)
    assert.deepEqual(stored.message.content[1], image)
    assertNoRaw(stored, 'stored row')
  })
}

// Each hook, with its own text fields, under a throwing $.mcp.call. Non-text fields keep their shape.
const CASES = {
  'prompt.context': {
    e: { blocks: [{ name: 'claudeMd', text: `pw ${PASSWORD}` }], instructionFiles: [{ path: 'CLAUDE.md', kind: 'Project', content: `pw ${PASSWORD}` }] },
    check: sent => {
      assert.deepEqual(sent.blocks, [{ name: 'claudeMd', text: BLOCKED }])
      assert.deepEqual(sent.instructionFiles, [{ path: 'CLAUDE.md', kind: 'Project', content: BLOCKED }])
    },
  },
  'prompt.section': {
    e: { name: 'env', text: `pw ${PASSWORD}` },
    check: sent => assert.deepEqual(sent, { name: 'env', text: BLOCKED }),
  },
  'prompt.attachment': {
    e: { type: 'file', text: `pw ${PASSWORD}` },
    check: sent => assert.deepEqual(sent, { type: 'file', text: BLOCKED }),
  },
  'skill.prompt': {
    e: { skill: 'deploy', text: `pw ${PASSWORD}` },
    check: sent => assert.deepEqual(sent, { skill: 'deploy', text: BLOCKED }),
  },
  'agent.spawn': {
    e: { tool_use_id: 't', prompt: `use ${PASSWORD}`, description: `with ${PASSWORD}`, subagentType: 'general-purpose', parentModel: 'm' },
    check: sent => assert.deepEqual(sent, { tool_use_id: 't', prompt: BLOCKED, description: BLOCKED, subagentType: 'general-purpose', parentModel: 'm' }),
  },
}

for (const [name, { e, check }] of Object.entries(CASES)) {
  test(`${name}: a detector failure replaces only its text fields with the block marker`, async () => {
    const mod = await load('throw')
    let sent
    await dispatch(mod, name, mod.$, e, arg => { sent = arg; return arg })
    check(sent)
  })
}

test('prompt.compose: a detector failure on composed sections sends the block marker', async () => {
  const mod = await load('throw')
  const result = await dispatch(mod, 'prompt.compose', mod.$, {}, () => ({ sections: [{ id: 's1', text: `pw ${PASSWORD}`, scope: 'session' }] }))
  assert.deepEqual(result, { sections: [{ id: 's1', text: BLOCKED, scope: 'session' }] })
})

test('session.compact: a detector failure skips compaction instead of sending history', async () => {
  const mod = await load('throw')
  let compacted = false
  const result = await dispatch(mod, 'session.compact', mod.$, { trigger: 'manual', messages: [{ type: 'user', message: { role: 'user', content: `pw ${PASSWORD}` } }] }, () => { compacted = true; return { messages: [] } })
  assert.equal(compacted, false)
  assert.deepEqual(result, { skip: BLOCKED })
})

test('turn.step: a detector failure yields the block marker in place of response text', async () => {
  const mod = await load('throw')
  const chunks = []
  async function* beneath() { yield { kind: 'text', index: 0, text: `pw ${PASSWORD}` }; yield { kind: 'stop', reason: 'end_turn' } }
  for await (const chunk of mod.hooks['turn.step'](mod.$, { agentId: undefined }, beneath)) chunks.push(chunk)
  assert.deepEqual(chunks, [{ kind: 'text', index: 0, text: BLOCKED }, { kind: 'stop', reason: 'end_turn' }])
})

test('the block marker is not placeholder-shaped, so tool.call never restores it', async () => {
  const mod = await load('throw')
  let sent
  await dispatch(mod, 'prompt.submit', mod.$, { text: `DB_PASSWORD=${PASSWORD}`, context: [] }, e => { sent = e; return e })
  let executed
  mod.$.mcp.call = async (_s, _t, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify({ ok: true, items: args.items.map(item => ({ id: item.id, ok: true, findings: [], errors: [] })) }) }] })
  await dispatch(mod, 'tool.call', mod.$, { tool: 'Bash', tool_use_id: 't2', command: `echo ${sent.text}` }, input => { executed = input; return { result: { stdout: 'ok', stderr: '' } } })
  assert.equal(executed.command, `echo ${BLOCKED}`)
})

// Backstop: a hook that fails for any other reason (a bug, an overrun budget) is answered by its
// `.catch`, which blocks in its place.
test('a hook that throws for another reason is answered by its .catch with the block marker', async () => {
  const mod = await load('throw')
  mod.$.env.get = async key => ({ PG_MOD_FAILURE_MODE: 'throw' })[key]
  let sent
  await dispatch(mod, 'prompt.submit', mod.$, { text: `DB_PASSWORD=${PASSWORD}`, context: [] }, e => { sent = e; return e })
  assert.equal(sent.text, BLOCKED)
})

test('every hook registers a .catch that blocks in its place', async () => {
  const mod = await load('throw')
  assert.deepEqual(Object.keys(mod.catches).sort(), Object.keys(mod.hooks).sort())
  assert.equal(Object.keys(mod.hooks).length, 11)
})

// A denied permission throws like a server that is not connected yet. On 2.1.291, one wait per hook,
// queued behind one another, outran the hook budget and the engine unloaded the whole Mod.
test('the connect wait is one window per session, not one per hook', async () => {
  const mod = await load('throw')
  mod.$.env.get = async key => ({ PG_MOD_CONNECT_WAIT_MS: '300' })[key]
  const first = Date.now()
  await dispatch(mod, 'prompt.section', mod.$, { name: 'a', text: `pw ${PASSWORD}` }, e => e)
  assert.ok(Date.now() - first >= 250)
  const started = Date.now()
  for (let i = 0; i < 5; i++) await dispatch(mod, 'prompt.section', mod.$, { name: 'b', text: `pw ${PASSWORD}` }, e => e)
  assert.ok(Date.now() - started < 250, 'later hooks waited again')
})

test('a hook whose signal aborts stops waiting at once and blocks', async () => {
  const mod = await load('throw')
  mod.$.env.get = async key => ({ PG_MOD_CONNECT_WAIT_MS: '60000' })[key]
  const controller = new AbortController()
  let sent
  const next = Object.assign(async e => { sent = e; return e }, { signal: controller.signal })
  const started = Date.now()
  setTimeout(() => controller.abort(), 100)
  await mod.hooks['prompt.submit'](mod.$, { text: `DB_PASSWORD=${PASSWORD}`, context: [] }, next)
  assert.ok(Date.now() - started < 1000, 'the wait ignored the signal')
  assert.equal(sent.text, BLOCKED)
})
