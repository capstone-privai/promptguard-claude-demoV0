// Native Mod: the secret-file dump guard (PG_SECRET_DUMP_GUARD, default on), the secret-file preload
// (PG_SECRET_FILE_PRELOAD, default off) and the guide's sentence against dumping. Run:
//   node --test tests/mod/test_secret_dump_guard.mjs
// A Bash command that reads a secret-looking path through a transform or dump tool (od, xxd, base64, fold,
// a character split...) gets its whole output replaced by one notice: the output came from a secret, whatever its
// format. Plain reads (cat) keep the detector and placeholder path. Synthetic values only; nothing prints them.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

const hash = raw => createHash('sha256').update(raw).digest('hex')
const PASS = 'Sy nth$Pa ss9q' // a space and a $ on purpose
const FILE = 'secrets/db_password.txt'
const NOTICE = '[PROMPTGUARD: 비밀 파일을 변형해 출력한 결과라 가렸습니다. 값은 placeholder로 다루고, 속성은 값을 출력하지 않는 명령으로 확인하세요]'
const ODLIKE = PASS.split('').join('  ') // what od -c and friends print: the value, a character at a time

// Fake detector: finds PASS wherever it stands whole (as the gold condition would), never when it is split up.
function fakeScan(items, find) {
  return {
    ok: true,
    items: items.map(item => {
      const findings = []
      if (find) {
        let at = item.text.indexOf(PASS)
        while (at !== -1) {
          findings.push({ type: 'PASSWORD', start: at, end: at + PASS.length, value_hash: hash(PASS), offset_unit: 'utf16_code_units' })
          at = item.text.indexOf(PASS, at + 1)
        }
      }
      return { id: item.id, ok: true, findings, errors: [] }
    }),
  }
}

async function load(env = {}, { find = true, files = { [FILE]: `${PASS}\n` } } = {}) {
  const { register } = await import(`../../src/native-mod/hooks/register.mjs?case=${Math.random()}`)
  const hooks = {}
  register((name, handler) => { hooks[name] = handler; return { catch() {} } })
  const audit = []
  const reads = []
  const $ = {
    env: { get: async key => env[key] ?? (key === 'PG_MOD_AUDIT' ? 'audit.json' : null) },
    fs: {
      read: async file => { reads.push(file); if (!(file in files)) throw new Error('ENOENT'); return files[file] },
      write: async (file, text) => { if (file === 'audit.json') audit.splice(0, audit.length, ...JSON.parse(text)) },
    },
    mcp: { call: async (_server, _tool, args) => ({ isError: false, content: [{ type: 'text', text: JSON.stringify(fakeScan(args.items, find)) }] }) },
  }
  return { hooks, $, audit, reads }
}

async function bash(hooks, $, command, stdout, stderr = '') {
  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't', command }, () => ({ result: { stdout, stderr, interrupted: false } }))
  return result.result
}

async function read(hooks, $, content) {
  const result = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 't', file_path: 'x' }, () => ({ result: { type: 'text', file: { content } } }))
  return result.result.file.content
}

const DUMPS = [
  ['od', `od -c ${FILE}`],
  ['xxd', `xxd ${FILE}`],
  ['base64', `base64 ${FILE}`],
  ['python', `python -c "print(list(open('${FILE}').read()))"`],
  ['fold', `fold -w 3 ${FILE}`],
  ['od', `cat ${FILE} | od -c`],
  ['od', `od -An -c < ${FILE}`],
  ['hexdump', `hexdump -C ${FILE}`],
  ['base32', `base32 ${FILE}`],
  ['cut', `cut -c1-3 ${FILE}`],
  ['rev', `rev ${FILE}`],
  ['sed', `sed 's/./& /g' ${FILE}`],
  ['sed', `sed -E 's/(.)/\\1 /g' ${FILE}`],
  ['awk', `awk '{ n = split($0, c, ""); for (i = 1; i <= n; i++) print c[i] }' ${FILE}`],
  ['node', `node -e "console.log(require('fs').readFileSync('${FILE}', 'utf8').split(''))"`],
  ['perl', `perl -ne 'print join(" ", split(//)), "\\n"' ${FILE}`],
  ['python3', `python3 -c "import sys; print([ord(c) for c in open('${FILE}').read()])"`],
  ['od', `cd /tmp/work && od -c ${FILE}`],
]

test('a dump of a secret file is replaced by the notice, whatever the tool', async () => {
  for (const [tool, command] of DUMPS) {
    const { hooks, $, audit } = await load()
    const out = await bash(hooks, $, command, `0000000   ${ODLIKE}\n0000016\n`, 'warning: ' + ODLIKE)
    assert.equal(out.stdout, NOTICE, `${tool}: stdout`)
    assert.equal(out.stderr, '', `${tool}: stderr`)
    const row = audit.find(entry => entry.event === 'secret_dump_guarded')
    assert.ok(row, `${tool}: audited`)
    assert.equal(row.dump_tool, tool)
    assert.equal(row.secret_dump_count, 1)
    const text = JSON.stringify(audit)
    assert.ok(!text.includes(FILE) && !text.includes('db_password') && !text.includes(PASS), `${tool}: no path or value in the audit`)
  }
})

test('every secret-looking path is guarded', async () => {
  for (const path of ['.env', '.env.local', 'config/.env.production', 'secrets/api.txt', 'my_secret.txt', 'DB_PASSWORD', 'passwd.bak',
    'aws_credentials.json', 'token.txt', 'certs/server.pem', 'server.key', '/home/u/.ssh/id_rsa', '~/.ssh/id_ed25519.pub', '.netrc', '~/.npmrc', '.pypirc']) {
    const { hooks, $ } = await load({}, { files: {} })
    assert.equal((await bash(hooks, $, `od -c ${path}`, ODLIKE)).stdout, NOTICE, path)
  }
})

test('a dump of a file that does not look secret is left to the detector', async () => {
  for (const command of ['od -c README.md', 'od -c package.json', 'xxd package.json | head', 'base64 logo.png', 'fold -w 80 notes.txt',
    'python -c "tokens = [1, 2]; print(list(\'abc\'))"', 'cat .env && od -c README.md', 'od -c README.md; ls secrets/']) {
    const { hooks, $, audit } = await load()
    const output = `0000000   R  E  A  D  M  E\n`
    assert.equal((await bash(hooks, $, command, output)).stdout, output, command)
    assert.ok(!audit.some(entry => entry.event === 'secret_dump_guarded'), command)
  }
})

test('cat of a secret file keeps the detector and placeholder path', async () => {
  const { hooks, $, audit } = await load()
  const out = await bash(hooks, $, `cat ${FILE}`, `${PASS}\n`)
  assert.match(out.stdout, /^\[PASSWORD_1\]\n$/)
  assert.ok(!audit.some(entry => entry.event === 'secret_dump_guarded'))
})

test('PG_SECRET_DUMP_GUARD=off: the dump goes through as before', async () => {
  const { hooks, $, audit } = await load({ PG_SECRET_DUMP_GUARD: 'off' })
  assert.equal((await bash(hooks, $, `od -c ${FILE}`, ODLIKE)).stdout, ODLIKE)
  assert.ok(!audit.some(entry => entry.event === 'secret_dump_guarded'))
})

test('on by default: unset or empty', async () => {
  for (const value of [undefined, '', '  ']) {
    const { hooks, $ } = await load(value === undefined ? {} : { PG_SECRET_DUMP_GUARD: value })
    assert.equal((await bash(hooks, $, `xxd ${FILE}`, ODLIKE)).stdout, NOTICE, JSON.stringify(value))
  }
})

test('a failed dump command is denied with the notice, not its error text', async () => {
  const { hooks, $ } = await load()
  const result = await hooks['tool.call']($, { tool: 'Bash', tool_use_id: 't', command: `od -c ${FILE}` },
    () => ({ isError: true, text: `od: ${ODLIKE}`, result: { stdout: '', stderr: `od: ${ODLIKE}`, interrupted: false } }))
  assert.equal(result.deny, NOTICE)
})

test('the guard counts per session', async () => {
  const { hooks, $, audit } = await load()
  await bash(hooks, $, `od -c ${FILE}`, ODLIKE)
  await bash(hooks, $, `base64 ${FILE}`, 'U3kgbnRo')
  assert.deepEqual(audit.filter(entry => entry.event === 'secret_dump_guarded').map(entry => [entry.dump_tool, entry.secret_dump_count]), [['od', 1], ['base64', 2]])
})

// ---- PG_SECRET_FILE_PRELOAD (default off): a small secret file's trimmed content goes into the vault before the command

test('preload on: the trimmed content of a small secret file is re-masked later, even where the detector misses it', async () => {
  const { hooks, $ } = await load({ PG_SECRET_FILE_PRELOAD: 'on' }, { find: false })
  await bash(hooks, $, `od -c ${FILE}`, ODLIKE)
  assert.equal(await read(hooks, $, `value: ${PASS}`), 'value: [PASSWORD_1]')
})

test('preload is off by default', async () => {
  const { hooks, $, reads } = await load({}, { find: false })
  await bash(hooks, $, `od -c ${FILE}`, ODLIKE)
  assert.equal(await read(hooks, $, `value: ${PASS}`), `value: ${PASS}`)
  assert.deepEqual(reads.filter(file => file === FILE), [], 'the file is not read')
})

test('preload also for a plain read (cat) the detector misses', async () => {
  const { hooks, $ } = await load({ PG_SECRET_FILE_PRELOAD: 'on' }, { find: false })
  assert.equal((await bash(hooks, $, `cat ${FILE}`, `${PASS}\n`)).stdout, '[PASSWORD_1]\n')
})

test('preload skips a big, multi-line, short or missing file', async () => {
  const cases = {
    'secrets/big.txt': 'x'.repeat(257),
    'secrets/multi.txt': 'Synth.Line.One9q\nSynth.Line.Two9q\n',
    'secrets/short.txt': 'ab\n', // under 3 characters, even in secrets/
    'notes_password.txt': 'Zq8x5\n', // a name match alone needs 8
  }
  const { hooks, $ } = await load({ PG_SECRET_FILE_PRELOAD: 'on' }, { find: false, files: cases })
  for (const file of [...Object.keys(cases), 'secrets/missing.txt']) await bash(hooks, $, `od -c ${file}`, 'x')
  for (const content of Object.values(cases)) {
    const line = content.trim().split('\n')[0]
    assert.equal(await read(hooks, $, `v=${line}`), `v=${line}`)
  }
})

test('preload types the value by its file name', async () => {
  const files = { 'secrets/api_token.txt': 'SynthTok.en9qXyz\n', '.env': 'SynthEnvOnly9q\n', 'id_rsa.key': 'SynthKeyLine9qAbc\n' }
  const { hooks, $ } = await load({ PG_SECRET_FILE_PRELOAD: 'on' }, { find: false, files })
  for (const file of Object.keys(files)) await bash(hooks, $, `od -c ${file}`, 'x')
  assert.equal(await read(hooks, $, 'SynthTok.en9qXyz SynthEnvOnly9q SynthKeyLine9qAbc'), '[TOKEN_1] [SECRET_1] [SECRET_2]')
})

// ---- the guide

async function guideText(env = {}) {
  const { hooks, $ } = await load(env)
  const composed = await hooks['prompt.compose']($, { model: 'm', tools: [], traits: [] }, async () => ({ sections: [{ id: 'intro', text: 'You are Claude.', scope: 'shared' }] }))
  return composed.sections.find(section => section.id === 'promptguard:placeholder-guide').text
}

test('the guide says not to dump a secret file or a hidden value, and how to check a property instead', async () => {
  const text = await guideText()
  for (const word of ['od', 'xxd', 'hexdump', 'base64', "grep -c '[$]'", 'python']) assert.ok(text.includes(word), word)
  assert.match(text, /character/)
  assert.match(text, /does not print the value/)
})

// ---- known limits (docs/SECRET_DUMP_GUARD.md): the path is not in the command text, so the guard does not see it

test('limits: a path from a variable, a glob or another file is not seen', async () => {
  for (const command of ['f=secrets/db_password.txt; od -c "$f"', 'od -c sec*/*', 'od -c "$(cat paths.txt)"', 'ln -s secrets/db_password.txt a && od -c a']) {
    const { hooks, $, audit } = await load({}, { find: false })
    await bash(hooks, $, command, 'x')
    assert.ok(!audit.some(entry => entry.event === 'secret_dump_guarded'), command)
  }
})

test('a path in $( ) that names the secret directory is seen', async () => {
  const { hooks, $ } = await load()
  assert.equal((await bash(hooks, $, 'od -c $(ls secrets/*)', 'x')).stdout, NOTICE)
})

// ---- fix/secret-dump-guard follow-up: partial and visible-character dumps, name rules, preload length, Read

const MORE_DUMPS = [
  ['head', `head -c 6 ${FILE}`],
  ['head', `head --bytes=6 ${FILE}`],
  ['head', `head -c6 ${FILE}`],
  ['tail', `tail -c 4 ${FILE}`],
  ['dd', `dd if=${FILE} bs=1 count=4 2>/dev/null`],
  ['cat', `cat -A ${FILE}`],
  ['cat', `cat -v ${FILE}`],
  ['cat', `cat -e ${FILE}`],
  ['cat', `cat -t ${FILE}`],
  ['cat', `cat -vet ${FILE}`],
  ['cat', `cat --show-all ${FILE}`],
  ['sed', `sed -n l ${FILE}`],
  ['sed', `sed -n 'l' ${FILE}`],
  ['grep', `grep -o . ${FILE}`],
  ['grep', `grep -o '.{1,2}' ${FILE}`],
  ['grep', `grep -oE '.{1,2}' ${FILE}`],
  ['grep', `grep -Eo '..' ${FILE}`],
  ['awk', `awk '{print substr($0,1,6)}' ${FILE}`],
  ['awk', `awk '{ print substr($0, 3) }' ${FILE}`],
  ['base64', "kubectl get secret db -o jsonpath='{.data.password}' | base64 -d"],
]

test('partial and visible-character dumps of a secret file are replaced too', async () => {
  for (const [tool, command] of MORE_DUMPS) {
    const { hooks, $, audit } = await load()
    const out = await bash(hooks, $, command, PASS.slice(0, 6))
    assert.equal(out.stdout, NOTICE, command)
    assert.equal(audit.find(entry => entry.event === 'secret_dump_guarded')?.dump_tool, tool, command)
  }
})

test('plain reads stay on the detector path: cat, head -n, line grep', async () => {
  for (const command of [`cat ${FILE}`, `head -n 1 ${FILE}`, `head -1 ${FILE}`, `tail -n 2 ${FILE}`, `grep PASS ${FILE}`, `grep -c '[$]' ${FILE}`,
    `grep -o 'DB_[A-Z_]*' ${FILE}`, `sed -n 1p ${FILE}`, `awk '{print $1}' ${FILE}`]) {
    const { hooks, $, audit } = await load()
    await bash(hooks, $, command, 'x')
    assert.ok(!audit.some(entry => entry.event === 'secret_dump_guarded'), command)
  }
})

test('name rules: whole words only, and source files picked by name alone are left out', async () => {
  for (const path of ['tokenizer.json', 'src/token_utils.py', 'src/secret_scanner.py', 'docs/password_policy.md', 'lib/credentials.ts', 'mysecretsauce.txt']) {
    const { hooks, $, audit } = await load({}, { files: {} })
    await bash(hooks, $, `od -c ${path}`, 'x')
    assert.ok(!audit.some(entry => entry.event === 'secret_dump_guarded'), path)
  }
  for (const path of ['credentials.json', 'api_token.txt', 'dbPassword.txt', 'secrets/app.py', 'secrets/notes.md', 'certs/server.key', 'tls.pem',
    'id_rsa', '.netrc', '.npmrc', '.pypirc', 'DB_PASSWORD', 'passwords.txt', 'aws_credentials']) {
    const { hooks, $ } = await load({}, { files: {} })
    assert.equal((await bash(hooks, $, `od -c ${path}`, 'x')).stdout, NOTICE, path)
  }
})

test('preload length: 3 characters in secrets/ or an exact name, 8 for a name match alone', async () => {
  const files = { 'secrets/pin.txt': 'q7Z\n', '.netrc': 'w9Kp\n', 'my_password.txt': 'Zq8x5\n', 'api_token.txt': 'SynthTok9qXy\n' }
  const { hooks, $ } = await load({ PG_SECRET_FILE_PRELOAD: 'on' }, { find: false, files })
  for (const file of Object.keys(files)) await bash(hooks, $, `cat ${file}`, 'x')
  assert.equal(await read(hooks, $, 'pin q7Z, netrc w9Kp, short Zq8x5, token SynthTok9qXy, word xq7Zy'),
    'pin [SECRET_1], netrc [SECRET_2], short Zq8x5, token [TOKEN_1], word xq7Zy')
})

async function readTool(hooks, $, filePath, content) {
  const result = await hooks['tool.call']($, { tool: 'Read', tool_use_id: 't', file_path: filePath }, () => ({ result: { type: 'text', file: { filePath, content } } }))
  return result.result.file.content
}

test('preload on Read: a secret-looking file is preloaded before its content is scanned', async () => {
  const { hooks, $, reads } = await load({ PG_SECRET_FILE_PRELOAD: 'on' }, { find: false })
  assert.equal(await readTool(hooks, $, FILE, `${PASS}\n`), '[PASSWORD_1]\n')
  assert.ok(reads.includes(FILE))
  const off = await load({}, { find: false })
  assert.equal(await readTool(off.hooks, off.$, FILE, `${PASS}\n`), `${PASS}\n`, 'off: as before')
  const other = await load({ PG_SECRET_FILE_PRELOAD: 'on' }, { find: false, files: { 'README.md': 'Synth readme text\n' } })
  await readTool(other.hooks, other.$, 'README.md', 'Synth readme text\n')
  assert.deepEqual(other.reads.filter(file => file === 'README.md'), [], 'a file that does not look secret is not read again')
})
