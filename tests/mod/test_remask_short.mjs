// Short-value re-mask tests for the Native Mod. Run: node --test tests/mod/test_remask_short.mjs
//
// PG_REMASK_SHORT=boundary: a known value shorter than 8 characters is re-masked only where it stands as a word
// (no [A-Za-z0-9_] right before or after it); the default since release/defaults-1120. substring (or any other value,
// off included) keeps the earlier behaviour. Synthetic values only.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

const hash = raw => createHash('sha256').update(raw).digest('hex')
const HEX_KEY = '9f8e7d6e5c4b3a2e1f0d8c7b6a5e4d3c' // a 32-character hex key with many e's
const SHORT = 'mgb'
const DIGITS = '45678'
const LONG = 'SynthPass8x'

// Fake detector: finds a value only as the literal argument of a credential-named call, as shell-aware does.
function fakeScan(items, values) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      for (const raw of values) {
        for (const call of ['CreateOrUpdateEnvSecret(ctx, 1, "', 'login("']) {
          let index = item.text.indexOf(call + raw + '"')
          while (index !== -1) {
            const start = index + call.length
            findings.push({ type: 'PASSWORD', rule_id: 'function_argument', detectors: ['shell-aware'], start, end: start + raw.length, value_hash: hash(raw), offset_unit: 'utf16_code_units' })
            index = item.text.indexOf(call + raw + '"', index + 1)
          }
        }
      }
      findings.sort((a, b) => a.start - b.start)
      return { id: item.id, ok: true, findings, errors: [] }
    }),
  }
}

async function load(mode, values = ['e', SHORT, DIGITS, LONG]) {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const $ = {
    env: { get: async key => (key === 'PG_REMASK_SHORT' ? mode : null) },
    fs: { write: async () => {} },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items, values)) }] }) },
  }
  return { hooks, $ }
}

async function read(hooks, $, content) {
  const result = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 't', file_path: 'x' }, () => ({ result: { type: 'text', file: { content } } }))
  return result.result.file.content
}

async function bash(hooks, $, command, stdout) {
  let ran
  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't', command }, e => { ran = e.command; return { result: { stdout, stderr: '', interrupted: false } } })
  return { ran, output: result.result.stdout }
}

test('boundary: a hex key that contains a found "e" is left as it is', async () => {
  const { hooks, $ } = await load('boundary')
  assert.equal(await read(hooks, $, 'CreateOrUpdateEnvSecret(ctx, 1, "e", input)'), 'CreateOrUpdateEnvSecret(ctx, 1, "[PASSWORD_1]", input)')
  assert.equal(await read(hooks, $, `key = ${HEX_KEY}\n`), `key = ${HEX_KEY}\n`)
})

test('boundary is the default (unset or empty)', async () => {
  for (const mode of [null, '']) {
    const { hooks, $ } = await load(mode)
    assert.equal(await read(hooks, $, 'CreateOrUpdateEnvSecret(ctx, 1, "e", input)'), 'CreateOrUpdateEnvSecret(ctx, 1, "[PASSWORD_1]", input)')
    assert.equal(await read(hooks, $, `key = ${HEX_KEY}\n`), `key = ${HEX_KEY}\n`, JSON.stringify(mode))
  }
})

test('substring, off or another value: the earlier behaviour, every "e" in the hex key is masked', async () => {
  for (const mode of ['substring', 'off', 'other']) {
    const { hooks, $ } = await load(mode)
    await read(hooks, $, 'CreateOrUpdateEnvSecret(ctx, 1, "e", input)')
    const out = await read(hooks, $, `key = ${HEX_KEY}\n`)
    assert.equal(out, `k[PASSWORD_1]y = ${HEX_KEY.replaceAll('e', '[PASSWORD_1]')}\n`, String(mode))
  }
})

test('boundary: a short value alone is masked, inside another word it is not', async () => {
  const { hooks, $ } = await load('boundary')
  await read(hooks, $, `login("${SHORT}")\nlogin("${DIGITS}")`)
  assert.equal(await read(hooks, $, `${SHORT}\n${DIGITS}\n`), '[PASSWORD_1]\n[PASSWORD_2]\n')
  for (const word of [`${SHORT}x`, `x${SHORT}`, `${SHORT}_1`, `${DIGITS}9`, `1${DIGITS}`, `${SHORT}2`]) {
    assert.equal(await read(hooks, $, `use ${word} now`), `use ${word} now`, word)
  }
})

test('boundary: quotes, brackets, spaces, punctuation and line ends are boundaries', async () => {
  const { hooks, $ } = await load('boundary')
  await read(hooks, $, `login("${SHORT}")`)
  const cases = [
    [`"${SHORT}"`, '"[PASSWORD_1]"'], [`'${SHORT}'`, "'[PASSWORD_1]'"], [`(${SHORT})`, '([PASSWORD_1])'],
    [`[${SHORT}]`, '[[PASSWORD_1]]'], [`a ${SHORT} b`, 'a [PASSWORD_1] b'], [`end ${SHORT}`, 'end [PASSWORD_1]'],
    [`${SHORT} start`, '[PASSWORD_1] start'], [`pw=${SHORT};`, 'pw=[PASSWORD_1];'], [`\t${SHORT}\r\n`, '\t[PASSWORD_1]\r\n'],
    [`${SHORT}-${SHORT}`, '[PASSWORD_1]-[PASSWORD_1]'], [`${SHORT}.`, '[PASSWORD_1].'],
  ]
  for (const [text, expected] of cases) assert.equal(await read(hooks, $, text), expected, JSON.stringify(text))
})

test('boundary: Hangul next to a value counts as a boundary (a Korean particle does not hide it)', async () => {
  const { hooks, $ } = await load('boundary')
  await read(hooks, $, `login("${SHORT}")`)
  assert.equal(await read(hooks, $, `비밀번호는${SHORT}입니다`), '비밀번호는[PASSWORD_1]입니다')
  assert.equal(await read(hooks, $, `${SHORT}를 쓰세요`), '[PASSWORD_1]를 쓰세요')
})

test('boundary: a restored short value is masked alone in the output, not inside a word', async () => {
  const { hooks, $ } = await load('boundary')
  await read(hooks, $, `login("${SHORT}")`)
  const alone = await bash(hooks, $, "printf '%s\\n' '[PASSWORD_1]'", `${SHORT}\n`)
  assert.equal(alone.ran, `printf '%s\\n' '${SHORT}'`)
  assert.equal(alone.output, '[PASSWORD_1]\n')
  assert.equal((await bash(hooks, $, 'ls', `${SHORT}x.log\n`)).output, `${SHORT}x.log\n`)
})

test('boundary: a short value with regex characters is matched literally', async () => {
  const { hooks, $ } = await load('boundary', ['a.b$', 'x+y'])
  await read(hooks, $, 'login("a.b$")\nlogin("x+y")')
  assert.equal(await read(hooks, $, 'v a.b$ w x+y'), 'v [PASSWORD_1] w [PASSWORD_2]')
  assert.equal(await read(hooks, $, 'v aXb$ w xxy xy'), 'v aXb$ w xxy xy')
})

test('8 characters and more: substring re-mask in both modes, and partial re-mask is unchanged', async () => {
  for (const mode of ['boundary', 'substring']) {
    const { hooks, $ } = await load(mode)
    await read(hooks, $, `login("${LONG}")`)
    assert.equal(await read(hooks, $, `pre${LONG}post`), 'pre[PASSWORD_1]post', mode)
    assert.equal(await read(hooks, $, `x ${LONG.slice(0, 8)} y`), 'x [PASSWORD_1_PART] y', mode)
  }
})
