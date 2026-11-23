const ledger = new Map()
const counters = new Map()
// placeholder -> raw value. Memory only: never audited, persisted, or sent to the model.
const vault = new Map()
// raw value -> placeholder, for re-masking raw values that come back from restored tool runs.
const reverseVault = new Map()
// placeholder -> the public prefix left in front of it. Empty unless PG_PLACEHOLDER_PUBLIC_PREFIX=on.
// The vault then holds only the rest of the value; ledger numbers and reverseVault still use the whole value.
const publicPrefixes = new Map()
let prefixTable = null
const PREFIX_TABLE = '../../docs/PLACEHOLDER_PUBLIC_PREFIXES.md'
// A shorter rest is too little to hide once the prefix is shown, so such a value is masked whole.
const PUBLIC_PREFIX_MIN_REST = 16
// The Native Mod's settings and their defaults (release/defaults-1120). An unset or empty variable takes the default;
// an on/off setting is on only for "on". The detector's own settings and defaults are in
// src/detector/pgdetector/settings.py; tests/launcher/defaults.test.cjs checks both against one table.
const DEFAULTS = Object.freeze({
  // off: no re-masking at all (remaskText and remaskPartial); the vault still fills, so restores keep working. For
  // measurement only: a restored value printed back then goes out as it is unless the detector finds it.
  PG_REMASK: 'on',
  // "boundary" or "substring" (the behaviour before release/defaults-1120).
  PG_REMASK_SHORT: 'boundary',
  PG_PLACEHOLDER_GUIDE: 'on',
  // on: a Bash command that reads a secret-looking path through a transform or dump tool gets its whole output
  // replaced by SECRET_DUMP_NOTICE (secretDumpTool).
  PG_SECRET_DUMP_GUARD: 'on',
  // on: before a Bash command that names a secret-looking path, a small one-line file's trimmed content goes into the
  // vault, so it is re-masked wherever it shows up later, even where the detector misses it. Off until measured.
  PG_SECRET_FILE_PRELOAD: 'off',
  PG_RESTORE_ESCAPED: 'on',
  PG_PLACEHOLDER_PUBLIC_PREFIX: 'off',
})

// The value of setting `name`, given what the environment holds for it. Each caller reads the variable itself, by
// its literal name: the engine refuses the whole module when the name is a variable (Claude Code 2.1.291).
function setting(name, raw) {
  return raw === undefined || raw === null || String(raw).trim() === '' ? DEFAULTS[name] : String(raw).trim()
}

// Read once per session (loadSettings, from sanitize and tool.call).
let remaskShort = null
let remaskOn = null

async function loadSettings($) {
  if (remaskShort === null) remaskShort = setting('PG_REMASK_SHORT', await $.env.get('PG_REMASK_SHORT')) === 'boundary' ? 'boundary' : 'substring'
  if (remaskOn === null) remaskOn = setting('PG_REMASK', await $.env.get('PG_REMASK')) === 'on'
}
// boundary: a known value shorter than this is re-masked only where it stands as a word.
const SHORT_REMASK = 8
const WORD_CHAR = '[A-Za-z0-9_]'
const PLACEHOLDER_PATTERN = /\[[A-Z0-9_]+_\d+\]/g
// Tools that execute locally. Model-bound tools (Agent, WebFetch, ...) never get raw values.
const RESTORE_TOOLS = new Set(['Bash', 'PowerShell', 'Edit', 'MultiEdit', 'Write', 'NotebookEdit', 'Grep'])
// The launcher's system-prompt seed (src/launcher/system-prompt.cjs), loaded once per session.
let seedLoaded = false
const TOOL_META_KEYS = new Set(['tool', 'tool_use_id'])
// session.append doors whose content no earlier hook sanitized. `command` is `!` shell mode:
// its <bash-input>/<bash-stdout> rows skip prompt.submit and tool.call entirely.
const UNSANITIZED_DOORS = new Set(['command', 'tool-message', 'delivery', 'hook-context', 'note', 'notice'])
const auditRows = []
let detectorQueue = Promise.resolve()
let auditQueue = Promise.resolve()
let toolOperation = 0

function collectStrings(value, source, entries = []) {
  if (typeof value === 'string') entries.push({ id: entries.length, text: value, source })
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, source, entries)
  else if (value && typeof value === 'object') for (const item of Object.values(value)) collectStrings(item, source, entries)
  return entries
}

function typeName(value) {
  return String(value || 'CREDENTIAL').toUpperCase().replace(/[^A-Z0-9_]/g, '_') || 'CREDENTIAL'
}

// One placeholder per value: keyed by value_hash alone, so a value keeps the placeholder (and the
// type) it got first even when a later finding names another type. The ensemble names a value by
// its context: one key is SECRET after `"secret": ` and API_KEY after `API_KEY=`, and two numbers
// for one key hid from the model that the files share it (metric-task t15).
function placeholder(finding, raw) {
  const key = finding.value_hash
  if (ledger.has(key)) return ledger.get(key)
  if (reverseVault.has(raw)) {
    ledger.set(key, reverseVault.get(raw))
    return reverseVault.get(raw)
  }
  const known = publicEntry(raw)
  const kind = known ? known.type : typeName(finding.type)
  const next = (counters.get(kind) || 0) + 1
  counters.set(kind, next)
  const value = `[${kind}_${next}]`
  ledger.set(key, value)
  if (known) publicPrefixes.set(value, known.prefix)
  vault.set(value, known ? raw.slice(known.prefix.length) : raw)
  if (!reverseVault.has(raw)) reverseVault.set(raw, value)
  return value
}

// Rows of docs/PLACEHOLDER_PUBLIC_PREFIXES.md, longest prefix first. Read once; a table that cannot be
// read leaves it empty, which masks every value whole.
async function loadPrefixTable($) {
  if (prefixTable) return
  prefixTable = []
  if (setting('PG_PLACEHOLDER_PUBLIC_PREFIX', await $.env.get('PG_PLACEHOLDER_PUBLIC_PREFIX')) !== 'on') return
  try {
    const rows = String(await $.fs.read(`${$.plugin.root}/${PREFIX_TABLE}`)).split(/\r?\n/)
    prefixTable = rows.flatMap(row => {
      const cells = row.match(/^\|\s*`([^`]+)`\s*\|\s*([A-Z][A-Z0-9_]*)\s*\|/)
      return cells ? [{ prefix: cells[1], type: cells[2] }] : []
    }).sort((a, b) => b.prefix.length - a.prefix.length)
  } catch { prefixTable = [] }
}

function publicEntry(raw) {
  const entry = raw === undefined ? undefined : prefixTable?.find(row => raw.startsWith(row.prefix))
  return entry && raw.length - entry.prefix.length >= PUBLIC_PREFIX_MIN_REST ? entry : null
}

const maskedForm = value => (publicPrefixes.get(value) || '') + value
const secretPart = raw => raw.slice((publicPrefixes.get(reverseVault.get(raw)) || '').length)

function mapStrings(value, fn) {
  if (typeof value === 'string') return fn(value)
  if (Array.isArray(value)) return value.map(item => mapStrings(item, fn))
  if (value && typeof value === 'object') {
    const out = {}
    for (const [key, item] of Object.entries(value)) out[key] = mapStrings(item, fn)
    return out
  }
  return value
}

// Swaps placeholders the model wrote back to their raw values. Unknown placeholders stay as is.
// A placeholder with a public prefix gets only the rest when the prefix is in front of it, and the
// whole value when the model dropped the prefix.
function restoreText(text, counter) {
  return text.replace(PLACEHOLDER_PATTERN, (match, offset) => {
    if (!vault.has(match)) return match
    counter.count++
    const prefix = publicPrefixes.get(match)
    const inPlace = !prefix || (offset >= prefix.length && text.startsWith(prefix, offset - prefix.length))
    return inPlace ? vault.get(match) : prefix + vault.get(match)
  })
}

function restoreToolInput(e, escaped = false) {
  const counter = { count: 0 }
  // PG_RESTORE_ESCAPED (default on): a regex-escaped placeholder in a regex argument first (metric-task t14 wrote
  // \[TOKEN_1\] in a Grep pattern and got no match), then the plain form everywhere as before.
  let source = e
  if (escaped && e.tool === 'Grep' && typeof e.pattern === 'string') source = { ...e, pattern: restoreEscapedPattern(e.pattern, 'ere', counter) }
  if (escaped && e.tool === 'Bash' && typeof e.command === 'string') source = { ...e, command: restoreEscapedCommand(e.command, counter) }
  const input = {}
  for (const [key, item] of Object.entries(source)) input[key] = TOOL_META_KEYS.has(key) ? item : mapStrings(item, text => restoreText(text, counter))
  return { input, restoredCount: counter.count }
}

// Escaped restore. \[TYPE_N\] (the placeholder escaped for a regex) becomes the real value escaped for the same
// regex dialect; only in a Grep pattern and in the arguments of grep, egrep, fgrep, rg and sed in a Bash command,
// where a model writes a regex. A bare TYPE_N is never restored: it is also an ordinary code identifier.
const ESCAPED_PLACEHOLDER = /\\\[([A-Z0-9_]+_\d+)\\\]/g
const REGEX_META = { bre: /[\\.*[\]^$]/g, ere: /[\\.+*?()|[\]{}^$]/g }
const REGEX_COMMANDS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'sed'])
const COMMAND_PREFIXES = new Set(['sudo', 'command', 'env', 'time', 'nice'])

function escapedValue(text, offset, name) {
  const placeholder = `[${name}]`
  if (!vault.has(placeholder)) return null
  const prefix = publicPrefixes.get(placeholder)
  const inPlace = !prefix || (offset >= prefix.length && text.startsWith(prefix, offset - prefix.length))
  return inPlace ? vault.get(placeholder) : prefix + vault.get(placeholder)
}

function restoreEscapedPattern(pattern, dialect, counter) {
  return pattern.replace(ESCAPED_PLACEHOLDER, (match, name, offset) => {
    const raw = escapedValue(pattern, offset, name)
    if (raw === null) return match
    counter.count++
    return dialect === 'fixed' ? raw : raw.replace(REGEX_META[dialect], '\\$&')
  })
}

// The quote state ('n' none, 's' single, 'd' double) at each index, and the command segments between unquoted
// | ; & and newlines. A small scanner: enough to place a placeholder and pick its command, not a shell parser.
function shellLayout(command) {
  const quote = new Array(command.length)
  const segments = []
  let state = 'n'
  let segmentStart = 0
  for (let i = 0; i < command.length; i++) {
    const char = command[i]
    quote[i] = state
    if (state === 's') { if (char === "'") state = 'n'; continue }
    if (state === 'd') {
      if (char === '\\' && i + 1 < command.length) { quote[++i] = 'd'; continue }
      if (char === '"') state = 'n'
      continue
    }
    if (char === '\\' && i + 1 < command.length) { quote[++i] = 'n'; continue }
    if (char === "'") state = 's'
    else if (char === '"') state = 'd'
    else if ('|;&\n'.includes(char)) { segments.push([segmentStart, i]); segmentStart = i + 1 }
  }
  segments.push([segmentStart, command.length])
  return { quote, segments }
}

// The regex dialect of a segment's command (bre, ere or fixed), or null when it is not grep, rg or sed.
function segmentDialect(command, quote, start, end) {
  const words = []
  let word = ''
  for (let i = start; i < end; i++) {
    if (quote[i] === 'n' && /\s/.test(command[i])) { if (word) words.push(word); word = ''; continue }
    word += command[i]
  }
  if (word) words.push(word)
  const plain = words.map(w => w.replace(/^['"]|['"]$/g, ''))
  let at = 0
  while (at < plain.length && (COMMAND_PREFIXES.has(plain[at]) || /^[A-Za-z_]\w*=/.test(plain[at]))) at++
  const name = (plain[at] || '').split(/[\\/]/).pop().replace(/\.exe$/i, '')
  if (!REGEX_COMMANDS.has(name)) return null
  const flags = plain.slice(at + 1).filter(w => /^-/.test(w))
  const short = flags.filter(f => /^-[A-Za-z]+$/.test(f)).join('')
  const has = (letter, long) => short.includes(letter) || flags.includes(long)
  if (name === 'fgrep' || ((name === 'grep' || name === 'rg') && has('F', '--fixed-strings'))) return { name, dialect: 'fixed' }
  if (name === 'rg' || name === 'egrep') return { name, dialect: 'ere' }
  if (name === 'grep') return { name, dialect: has('E', '--extended-regexp') || has('P', '--perl-regexp') ? 'ere' : 'bre' }
  return { name, dialect: has('E', '--regexp-extended') || has('r', '--regexp-extended') ? 'ere' : 'bre' }
}

function shellQuoted(value, state) {
  if (state === 's') return value.replace(/'/g, "'\\''")
  if (state === 'd') return value.replace(/[\\$`"]/g, '\\$&')
  return value.replace(/[^A-Za-z0-9_./:@%+=,-]/g, '\\$&')
}

function restoreEscapedCommand(command, counter) {
  if (!command.includes('\\[')) return command
  const { quote, segments } = shellLayout(command)
  const commands = segments.map(([start, end]) => ({ start, end, command: segmentDialect(command, quote, start, end) }))
  return command.replace(ESCAPED_PLACEHOLDER, (match, name, offset) => {
    const segment = commands.find(item => offset >= item.start && offset < item.end)
    if (!segment?.command) return match
    const raw = escapedValue(command, offset, name)
    if (raw === null) return match
    counter.count++
    let value = segment.command.dialect === 'fixed' ? raw : raw.replace(REGEX_META[segment.command.dialect], '\\$&')
    if (segment.command.name === 'sed' && segment.command.dialect !== 'fixed') value = value.replace(/\//g, '\\/')
    return shellQuoted(value, quote[offset])
  })
}

// The launcher masks Claude Code's system prompt flags (no hook sees them) and writes their placeholders here:
// registering them first keeps one placeholder per value and numbering unique. A seed that cannot be read fails
// the scan (and so blocks), since a number the system prompt already uses could be given to another value.
async function loadSeed($) {
  if (seedLoaded) return
  const path = await $.env.get('PG_MOD_SEED_FILE')
  if (!path) { seedLoaded = true; return }
  const entries = JSON.parse(String(await $.fs.read(path))).entries
  if (!Array.isArray(entries)) throw new Error('PromptGuard system prompt seed malformed')
  for (const entry of entries) {
    const kind = /^\[([A-Z0-9_]+)_(\d+)\]$/.exec(entry?.placeholder ?? '')
    if (!kind || typeof entry.raw !== 'string' || !entry.raw || typeof entry.value_hash !== 'string') throw new Error('PromptGuard system prompt seed malformed')
    ledger.set(entry.value_hash, entry.placeholder)
    vault.set(entry.placeholder, entry.raw)
    if (!reverseVault.has(entry.raw)) reverseVault.set(entry.raw, entry.placeholder)
    counters.set(kind[1], Math.max(counters.get(kind[1]) || 0, Number(kind[2])))
  }
  seedLoaded = true
  if (entries.length) await $.fs.write(path, '{"entries":[]}\n')
}

// PG_PLACEHOLDER_GUIDE (default on): one section at the end of every composed system prompt. In metric-task (161 tasks) a
// model stopped on a key that arrived as [SECRET_1] (g29), "fixed" a password bug it could not see (t12), and ten
// successful runs told the user the file held a fake string. The tool list is RESTORE_TOOLS itself, so the guide
// never promises a restore the Mod does not make. No placeholder-shaped example (digits), so nothing restores it.
function placeholderGuide(escaped) {
  const tools = [...RESTORE_TOOLS]
  const list = `${tools.slice(0, -1).join(', ')} or ${tools.at(-1)}`
  return [
    'PromptGuard: a bracketed name such as [TYPE_N] (for example [PASSWORD_N] or [API_KEY_N], N a number) is a real value',
    'that PromptGuard hid before it reached you; the user did give it.',
    `Written in the input of ${list}, it becomes the real value right before the tool runs; other tools get it as written.`,
    ...(escaped ? ['In a Grep pattern, and in grep, rg and sed arguments in Bash, the regex-escaped form \\[TYPE_N\\] is replaced by the regex-escaped value.'] : []),
    'Do not ask the user for the value again, and do not report that a file contains a placeholder or a fake string.',
    'If you need a property of the value (its length, a character it contains), check it with a local command that uses',
    'the placeholder, and do not print the value.',
    'Do not print a secret file or a hidden value through od, xxd, hexdump or base64, by splitting it into characters, or by',
    'cutting out a part of it. If you need a property such as whether it contains a special character or its length, check',
    "it with a command that does not print the value (for example grep -c '[$]' FILE, or python printing only the result of a condition).",
  ].join(' ')
}

// ---- PG_SECRET_DUMP_GUARD (default on) and PG_SECRET_FILE_PRELOAD (default off)
//
// metric-task g16, g20 (gold) and g16, t14 (promptguard): the model ran od -c on secrets/db_password.txt to see the
// exact bytes. od prints a character at a time with offsets, so no detector found the value, it never entered the
// vault, the model read it and wrote it raw into an Edit, and that went to the server with the history. Output
// formats are endless, so the guard does not parse them: a Bash pipeline that names a secret-looking path and runs a
// transform or dump tool has its whole output replaced by one notice. A plain read (cat, Read) keeps the detector and
// placeholder path. Heuristic on the command text: a path built from a variable, $( ), a glob or a link, a cd before a
// relative path, and tools other than Bash are not seen (docs/SECRET_DUMP_GUARD.md).
const SECRET_DUMP_NOTICE = '[PROMPTGUARD: 비밀 파일을 변형해 출력한 결과라 가렸습니다. 값은 placeholder로 다루고, 속성은 값을 출력하지 않는 명령으로 확인하세요]'
// Whole words of the file name (snake, kebab, dot and camelCase split): token_utils has "token", tokenizer does not.
const SECRET_NAME_WORDS = new Set(['secret', 'secrets', 'password', 'passwords', 'passwd', 'credential', 'credentials', 'token', 'tokens'])
// A file picked by its name alone is not a secret when it is source or docs (src/token_utils.py, docs/password_policy.md).
const SOURCE_EXTENSIONS = new Set(['py', 'js', 'ts', 'tsx', 'jsx', 'go', 'rs', 'java', 'kt', 'rb', 'php', 'c', 'cc', 'cpp', 'h', 'cs', 'swift', 'md', 'rst'])
const SECRET_EXACT_NAMES = new Set(['.env', '.netrc', '.npmrc', '.pypirc'])
const DUMP_COMMANDS = new Set(['od', 'xxd', 'hexdump', 'hd', 'base64', 'base32', 'basenc', 'fold', 'rev', 'dd'])
// grep -o with a pattern that matches any short run of characters (., .{1,2}, [^ ]): one character or two a line.
const ANY_CHARS = /^(?:(?:\.|\\[Sw]|\[[^\]]*\])(?:\{\d+(?:,\d*)?\}|[?*+])?)+$/
const COMMAND_WRAPPERS = new Set(['sudo', 'env', 'nice', 'time', 'command', 'exec', 'nohup', 'stdbuf'])
// Code of an interpreter that prints a value a character (or a byte) at a time, or encoded.
const CHAR_CODE = {
  awk: /split\([^)]*,\s*""\s*\)|substr\(/,
  python: /\blist\(|\bord\(|\[::|\.hex\(|hexlify|b64encode|b32encode|b16encode|\bbytes\(|\brepr\(|\.join\(|\.encode\(/,
  node: /split\(\s*(['"`])\1\s*\)|charCodeAt|codePointAt|\[\s*\.\.\.|Array\.from\(|toString\(\s*['"](?:hex|base64)|\.join\(/,
  perl: /split\s*\(?\s*\/\/|\bunpack\b|\bord\b|\bsprintf\b|\bjoin\b/,
}
const INTERPRETERS = { awk: 'awk', gawk: 'awk', mawk: 'awk', python: 'python', python3: 'python', py: 'python', node: 'node', deno: 'node', bun: 'node', perl: 'perl', ruby: 'perl' }

// 'place' (secrets/, an exact name, .env.*, .pem, .key, id_rsa, id_ed25519: secret by where or what it is), 'name'
// (a secret word in the file name, source and docs extensions left out), or null.
function secretPathKind(path) {
  const parts = path.split(/[\\/]/)
  const base = parts.at(-1)
  // secrets/ itself too: secrets/* and $(ls secrets/*) read what is in it.
  if (parts.slice(0, -1).some(part => part.toLowerCase() === 'secrets')) return 'place'
  if (!base) return null
  if (SECRET_EXACT_NAMES.has(base) || base.startsWith('.env.')) return 'place'
  if (/^id_(?:rsa|ed25519)/.test(base) || /\.(?:pem|key)$/i.test(base)) return 'place'
  const extension = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1).toLowerCase() : ''
  if (SOURCE_EXTENSIONS.has(extension)) return null
  const words = base.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/)
  return words.some(word => SECRET_NAME_WORDS.has(word)) ? 'name' : null
}

function secretPath(path) {
  return secretPathKind(path) !== null
}

// The words of one segment, quotes removed.
function segmentWords(command, quote, start, end) {
  const words = []
  let word = ''
  for (let i = start; i < end; i++) {
    if (quote[i] === 'n' && /\s/.test(command[i])) { if (word) words.push(word); word = ''; continue }
    if (quote[i] === 'n' && (command[i] === "'" || command[i] === '"')) continue
    if (quote[i] === 's' && command[i] === "'") continue
    if (quote[i] === 'd' && command[i] === '"' && command[i - 1] !== '\\') continue
    word += command[i]
  }
  if (word) words.push(word)
  return words
}

// Secret-looking paths a segment names: an argument word as a whole, and inside code (python -c "...open('x')...")
// a path-shaped piece (with / or an extension), so a variable named tokens is not taken for a file.
function segmentSecretPaths(words, at) {
  const out = []
  words.forEach((word, index) => {
    if (index === at) return
    const value = word.startsWith('-') ? (word.includes('=') ? word.slice(word.indexOf('=') + 1) : '') : word.replace(/^[<>]+/, '')
    if (!value) return
    if (/^[\w.~\/\\:-]+$/.test(value)) {
      if (secretPath(value)) out.push(value)
      return
    }
    for (const piece of value.match(/[\w.~\/\\-]+/g) || []) {
      if (/[\/\\]|\.[A-Za-z0-9]+$/.test(piece) && secretPath(piece)) out.push(piece)
    }
  })
  return out
}

// The dump tool a segment runs, or null.
function segmentDumpTool(words, at) {
  const name = (words[at] || '').split(/[\\/]/).pop().replace(/\.exe$/i, '')
  const args = words.slice(at + 1)
  if (DUMP_COMMANDS.has(name)) return name
  if (name === 'cut' && args.some(arg => /^-[a-z]*c/.test(arg) || arg.startsWith('--characters'))) return 'cut'
  // head -c N / tail -c N: the first or last bytes only (metric-task t10). head -n and -5 are line reads.
  if ((name === 'head' || name === 'tail') && args.some(arg => /^-[a-z]*c\d*$/.test(arg) || arg.startsWith('--bytes'))) return name
  // cat -A -v -e -t (-E -T): special characters made visible.
  if (name === 'cat' && args.some(arg => /^-[A-Za-z]*[AvetET]/.test(arg) || /^--show-/.test(arg))) return 'cat'
  // sed: a substitution a character at a time, or the l command (prints special characters visibly).
  if (name === 'sed' && args.some(arg => /s(.)(?:\.|\\?\(\.\\?\))\1/.test(arg) || /(?:^|[;{}\s/\d])l(?:\s*\d+)?\s*(?:$|[;}])/.test(arg))) return 'sed'
  if ((name === 'grep' || name === 'egrep') && args.some(arg => /^-[A-Za-z]*o/.test(arg) || arg === '--only-matching')) {
    const pattern = args.find((arg, index) => !arg.startsWith('-') && args[index - 1] !== '-e' && args[index - 1] !== '-f') ?? args[args.indexOf('-e') + 1]
    if (pattern && pattern.length <= 16 && ANY_CHARS.test(pattern.replace(/^\^|\$$/g, ''))) return 'grep'
  }
  const family = INTERPRETERS[name]
  if (family && args.some(arg => CHAR_CODE[family].test(arg))) return name
  return null
}

// { tool, paths }: tool is the dump tool of the first pipeline that names a secret-looking path and runs one (null when
// none does); paths are every secret-looking path the command names (for the preload).
function secretDumpTool(command) {
  if (typeof command !== 'string' || !command) return { tool: null, paths: [] }
  const { quote, segments } = shellLayout(command)
  const pipelines = [[]]
  segments.forEach(([start, end], index) => {
    const words = segmentWords(command, quote, start, end)
    let at = 0
    while (at < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[at]) || COMMAND_WRAPPERS.has(words[at]))) at++
    pipelines.at(-1).push({ paths: segmentSecretPaths(words, at), tool: segmentDumpTool(words, at) })
    const pipe = command[end] === '|' && command[end + 1] !== '|' && command[end - 1] !== '|'
    if (!pipe && index < segments.length - 1) pipelines.push([])
  })
  let tool = null
  for (const pipeline of pipelines) {
    if (tool) break
    if (pipeline.some(segment => segment.paths.length)) tool = pipeline.find(segment => segment.tool)?.tool ?? null
  }
  return { tool, paths: [...new Set(pipelines.flat().flatMap(segment => segment.paths))] }
}

// The whole output of a guarded command: the notice as stdout, every other text field empty.
function guardedResult(result) {
  const out = { ...result }
  if (out.result && typeof out.result === 'object') {
    out.result = Object.fromEntries(Object.entries(out.result).map(([key, value]) => [key, typeof value === 'string' ? '' : value]))
    out.result.stdout = SECRET_DUMP_NOTICE
  } else if (typeof out.result === 'string') out.result = SECRET_DUMP_NOTICE
  if (out.text !== undefined) out.text = SECRET_DUMP_NOTICE
  return out
}

const PRELOAD_MAX_BYTES = 256
// 3 for a file secret by where or what it is (secrets/, .netrc ...), 8 for one picked by a word in its name alone.
const PRELOAD_MIN_CHARS = { place: 3, name: 8 }
const preloaded = new Set()

function preloadType(path) {
  const base = path.split(/[\\/]/).pop()
  if (/password|passwd|pwd/i.test(base)) return 'PASSWORD'
  if (/token/i.test(base)) return 'TOKEN'
  return 'SECRET'
}

// A small one-line secret file's trimmed content into the vault, before the command runs. Paths are read relative
// to the session's working directory (not a cd inside the command); ~ is not expanded. Anything unreadable is skipped.
async function preloadSecretFiles($, paths) {
  for (const path of paths) {
    if (preloaded.has(path) || path.startsWith('~')) continue
    preloaded.add(path)
    try {
      // The engine allows $ only as $.noun.event(...) at the call site, so stat is called, not tested for. A stat
      // that fails (missing file, or an engine without it) leaves the decision to the read below.
      let size = null
      try {
        const stat = await $.fs.stat(path)
        if (stat.kind !== 'file') continue
        size = stat.size
      } catch { /* decided by the read */ }
      if (size !== null && size > PRELOAD_MAX_BYTES) continue
      const text = String(await $.fs.read(path))
      if (new TextEncoder().encode(text).length > PRELOAD_MAX_BYTES) continue
      const raw = text.trim()
      if (raw.length < (PRELOAD_MIN_CHARS[secretPathKind(path)] ?? Infinity) || /[\r\n]/.test(raw) || /^\[[A-Z0-9_]+_\d+\]$/.test(raw) || reverseVault.has(raw)) continue
      const kind = preloadType(path)
      const next = (counters.get(kind) || 0) + 1
      counters.set(kind, next)
      const value = `[${kind}_${next}]`
      vault.set(value, raw)
      reverseVault.set(raw, value)
    } catch { /* missing or unreadable: nothing to preload */ }
  }
}
let secretDumpCount = 0

// Replaces known raw values with their placeholders, even where the detector would miss them
// (e.g. a restored password echoed alone on a line). Longest first so substrings never win.
//
// With PG_REMASK_SHORT=boundary (the default) a value shorter than SHORT_REMASK characters is replaced only where no
// [A-Za-z0-9_] stands right before or after it. A short value found once (shell-aware's "e" in
// CreateOrUpdateEnvSecret(ctx, 1, "e", input), CredData-trajectory test) was otherwise masked inside every word
// and hex key that contains it. Any other character, Hangul included, is a boundary: "비밀번호는mgb입니다" still
// masks mgb. Longer values and remaskPartial are unchanged.
//
// PG_REMASK=off returns the text as it is, partial pass included, and counts nothing (remasked_count 0).
function remaskText(text, counter) {
  if (remaskOn === false || !reverseVault.size) return text
  let out = text
  for (const raw of [...reverseVault.keys()].sort((a, b) => b.length - a.length)) {
    if (!out.includes(raw)) continue
    const replacement = maskedForm(reverseVault.get(raw))
    if (remaskShort === 'boundary' && raw.length < SHORT_REMASK) {
      const word = new RegExp(`(?<!${WORD_CHAR})${raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?!${WORD_CHAR})`, 'g')
      out = out.replace(word, () => { counter.count++; return replacement })
      continue
    }
    const parts = out.split(raw)
    counter.count += parts.length - 1
    out = parts.join(replacement)
  }
  return remaskPartial(out, counter)
}

// Partial re-mask. A restored command can print part of a secret (`sed 's/(=.{12}).*/…/'`,
// `cut -c1-12`, `head -c 20`), and the full-value pass above misses it: in the metric-task t09 run,
// 12 of a 16-character password went out. So a run of at least partMinLength(raw) consecutive
// characters of a known raw value is masked too, as [TYPE_N_PART].
//
// The minimum is max(8, half the value's length), rounded up:
// - 8: shorter runs are shared by ordinary words and identifiers (`deploy-`, `report`), and give
//   little of a value away. A value shorter than 8 characters is masked only whole.
// - half: long values (JWTs, keys) have long common prefixes and fixed headers (a JWT header such as
//   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` is 36 characters), and less than half of a long random
//   value leaves the rest out of reach.
// The marker ends in `_PART]`, outside PLACEHOLDER_PATTERN, so tool.call never restores a part to
// the full value. With a public prefix only the rest counts: it is the part that is secret, and the
// prefix stays where it is in the text.
//
// A run made only of ordinary words is not masked as a part (the whole value still is). A password a
// person chose (`password123!`, `my-super-secret-key`) shares its words with ordinary output, and
// masking every `password` or `localhost` in later source code and logs breaks the model's reads and
// edits of that code, while the provider cannot tell such a word belongs to a secret. A word here is
// all lower case, all upper case or capitalized, joined by - _ . or spaces; a run with a digit, a
// symbol or mixed case inside a word is masked. A random value rarely has such a run: about 3 in
// 1,000 8-character pieces of a base62 value and 9 in 100,000 12-character ones. The cost: a fragment
// of a password made only of words (`correct-horse-battery`) goes out when printed alone.
const PART_MIN = 8
const partMinLength = raw => Math.max(PART_MIN, Math.ceil(raw.length / 2))
const partMarker = placeholder => `${placeholder.slice(0, -1)}_PART]`
const WORD = '(?:[a-z]+|[A-Z]+|[A-Z][a-z]+)'
const WORDS_ONLY = new RegExp(`^[-_. ]*${WORD}(?:[-_. ]+${WORD})*[-_. ]*$`)

// Every PART_MIN-character window of every raw value long enough to have parts, so one pass over a
// text finds them all, however many values there are. The vault only grows: rebuilt on a new value.
let partIndex = { size: -1, windows: new Map() }

function partWindows() {
  if (partIndex.size === reverseVault.size) return partIndex.windows
  const windows = new Map()
  for (const owner of reverseVault.keys()) {
    const raw = secretPart(owner)
    if (raw.length < PART_MIN) continue
    for (let offset = 0; offset + PART_MIN <= raw.length; offset++) {
      const window = raw.slice(offset, offset + PART_MIN)
      const hits = windows.get(window)
      if (hits) hits.push({ raw, owner, offset })
      else windows.set(window, [{ raw, owner, offset }])
    }
  }
  partIndex = { size: reverseVault.size, windows }
  return windows
}

function remaskPartial(text, counter) {
  if (text.length < PART_MIN || !reverseVault.size) return text
  const windows = partWindows()
  if (!windows.size) return text
  const spans = []
  for (let start = 0; start + PART_MIN <= text.length; start++) {
    const hits = windows.get(text.slice(start, start + PART_MIN))
    if (!hits) continue
    // A run starting here, extended as far as it keeps matching; the longest one that is long
    // enough for its value wins. Scanning left to right, the first hit of a run is its start.
    let best = null
    for (const { raw, owner, offset } of hits) {
      let end = start + PART_MIN
      let at = offset + PART_MIN
      while (end < text.length && at < raw.length && text[end] === raw[at]) { end++; at++ }
      if (end - start >= partMinLength(raw) && (!best || end > best.end)) best = { start, end, raw: owner }
    }
    if (!best || WORDS_ONLY.test(text.slice(best.start, best.end))) continue
    spans.push(best)
    start = best.end - 1
  }
  if (!spans.length) return text
  counter.count += spans.length
  let out = text
  for (const { start, end, raw } of spans.reverse()) out = out.slice(0, start) + partMarker(reverseVault.get(raw)) + out.slice(end)
  return out
}

// Checks every span first, then numbers top to bottom (so the first value in a .env is _1), then
// replaces from the end so earlier offsets stay valid.
function redactText(text, findings) {
  const ordered = [...findings].sort((a, b) => b.start - a.start || b.end - a.end)
  let previousStart = text.length + 1
  for (const finding of ordered) {
    if (finding.offset_unit !== 'utf16_code_units') throw new Error('PromptGuard detector offset unit mismatch')
    if (!Number.isInteger(finding.start) || !Number.isInteger(finding.end) || finding.start < 0 || finding.end > text.length || finding.start >= finding.end) throw new Error('PromptGuard detector invalid span')
    if (finding.end > previousStart) throw new Error('PromptGuard detector overlapping normalized spans')
    previousStart = finding.start
  }
  const placeholders = new Map()
  for (const finding of [...ordered].reverse()) placeholders.set(finding, maskedForm(placeholder(finding, text.slice(finding.start, finding.end))))
  let out = text
  for (const finding of ordered) out = out.slice(0, finding.start) + placeholders.get(finding) + out.slice(finding.end)
  return out
}

// The pgdetector MCP server connects in the background after the session starts, and until then
// $.mcp.call throws. Failing then would block the first prompt for no reason, so wait for the first
// connection (bounded); after that, a throw fails at once. Either way a failure blocks (BLOCKED_TEXT).
//
// The wait is one window for the whole session, from the first call, not one per hook: a denied
// permission also throws, and per-hook windows queued behind one another (detectorQueue) outran
// the hook budget (HookBudget.ms, 10s, which counts these timers). Claude Code 2.1.291 then unloaded
// the whole Mod as "a runaway plugin" for ignoring next.signal, and later text went out unscanned.
// So every wait also stops on the hook's signal; the hook's .catch then blocks in its place. A
// PG_MOD_CONNECT_WAIT_MS past the budget is cut there.
const CONNECT_RETRY_MS = 250
let detectorConnected = false
let connectDeadline = null

class DetectorAbandoned extends Error {}

function pause(ms, signal) {
  return new Promise(resolve => {
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
  })
}

// Settles with `promise`, or rejects as soon as `signal` aborts.
function untilAborted(promise, signal) {
  if (!signal) return promise
  if (signal.aborted) return Promise.reject(new DetectorAbandoned('PromptGuard detector call abandoned'))
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new DetectorAbandoned('PromptGuard detector call abandoned'))
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort))
  })
}

async function callDetector($, entries, signal) {
  if (connectDeadline === null) {
    const wait = Number(await $.env.get('PG_MOD_CONNECT_WAIT_MS') ?? 15000)
    connectDeadline = Date.now() + (Number.isFinite(wait) && wait >= 0 ? wait : 15000)
  }
  for (;;) {
    if (signal?.aborted) throw new DetectorAbandoned('PromptGuard detector call abandoned')
    try {
      const response = await $.mcp.call('pgdetector', 'scan_batch', { items: entries })
      detectorConnected = true
      return response
    } catch (error) {
      if (detectorConnected || Date.now() >= connectDeadline) throw error
      await pause(CONNECT_RETRY_MS, signal)
    }
  }
}

async function scanBatch($, entries, signal) {
  if (!entries.length) return { items: [], latencyMs: 0 }
  const started = Date.now()
  const operation = detectorQueue.then(() => callDetector($, entries, signal))
  detectorQueue = operation.catch(() => {})
  const response = await untilAborted(operation, signal)
  if (!response || response.isError === true || !Array.isArray(response.content)) throw new Error('PromptGuard detector bridge failure')
  const text = response.content.find(block => block?.type === 'text')?.text
  let value
  try { value = JSON.parse(text) } catch { throw new Error('PromptGuard detector malformed response') }
  if (!value || value.ok !== true || !Array.isArray(value.items) || value.items.length !== entries.length) throw new Error('PromptGuard detector malformed response')
  for (const item of value.items) {
    if (item.ok !== true || !Array.isArray(item.findings) || (Array.isArray(item.errors) && item.errors.length)) throw new Error('PromptGuard detector unsafe result')
  }
  return { items: value.items, latencyMs: Date.now() - started }
}

async function appendFailureAudit($, source, error, extra = {}) {
  const path = await $.env.get('PG_MOD_AUDIT')
  if (!path) return
  const row = {
    timestamp: new Date().toISOString(),
    session_id_hash: await $.env.get('PG_SESSION_HASH') || 'unavailable',
    source,
    finding_count: null,
    type_counts: {},
    redacted_count: null,
    blocked: true,
    reason: error?.pgStage === 'sanitizer' ? 'SANITIZER_FAILURE' : 'DETECTOR_FAILURE',
    event: 'scan_failed',
    hook: extra.hook, tool: auditTool(extra.tool), operation: extra.operation,
    failure_stage: error?.pgStage === 'sanitizer' ? 'sanitizer' : 'detector',
    latency_ms: 0,
  }
  auditRows.push(row)
  auditQueue = auditQueue.then(() => $.fs.write(path, JSON.stringify(auditRows, null, 2))).catch(() => {})
  await auditQueue
}

function rebuild(value, byId, cursor = { value: 0 }) {
  if (typeof value === 'string') return redactText(value, byId.get(cursor.value++) || [])
  if (Array.isArray(value)) return value.map(item => rebuild(item, byId, cursor))
  if (value && typeof value === 'object') {
    const out = {}
    for (const [key, item] of Object.entries(value)) out[key] = rebuild(item, byId, cursor)
    return out
  }
  return value
}

async function sanitize($, value, source, signal) {
  await loadSettings($)
  await loadSeed($)
  await loadPrefixTable($)
  const entries = collectStrings(value, source)
  const scanned = await scanBatch($, entries, signal)
  const byId = new Map(scanned.items.map(item => [item.id, item.findings]))
  const findings = scanned.items.flatMap(item => item.findings)
  const types = {}
  for (const finding of findings) types[finding.type] = (types[finding.type] || 0) + 1
  let sanitized
  try { sanitized = rebuild(value, byId) }
  catch (error) { error.pgStage = 'sanitizer'; throw error }
  // After the detector pass, so remasked_count counts only raw values the detector missed.
  const remasked = { count: 0 }
  sanitized = mapStrings(sanitized, text => remaskText(text, remasked))
  // Never retain text, hashes, object keys, or caller-provided error messages in audit.
  const details = scanned.items.flatMap(item => item.findings.map(finding => ({
    detector: item.detector === 'CredSweeper' ? 'CredSweeper' : undefined,
    secret_type: typeName(finding.type), rule_id: finding.rule_id,
    payload_index: item.id, start: finding.start, end: finding.end,
    offset_unit: finding.offset_unit, action: 'MASK', placeholder: placeholder(finding),
  })))
  return { value: sanitized, findingCount: findings.length, types, latencyMs: scanned.latencyMs,
    scannedPayloadCount: entries.length, findings: details, remaskedCount: remasked.count }
}

async function appendAudit($, source, result, extra = {}) {
  const path = await $.env.get('PG_MOD_AUDIT')
  if (!path) return
  auditRows.push({
    timestamp: new Date().toISOString(),
    session_id_hash: await $.env.get('PG_SESSION_HASH') || 'unavailable',
    source,
    event: extra.event || 'scan_completed',
    operation: extra.operation,
    scanned_payload_count: result.scannedPayloadCount,
    findings: result.findings,
    finding_count: result.findingCount,
    type_counts: result.types,
    redacted_count: result.findingCount === null ? null : result.findingCount + (result.remaskedCount || 0),
    remasked_count: result.remaskedCount || 0,
    restored_count: extra.restored_count,
    blocked: false,
    reason: null,
    latency_ms: result.latencyMs,
    hook: extra.hook,
    tool: auditTool(extra.tool),
    is_error: extra.is_error,
    // secret_dump_guarded rows only: the dump tool's name and the session's running count, never a path or value.
    dump_tool: extra.dump_tool,
    secret_dump_count: extra.secret_dump_count,
  })
  auditQueue = auditQueue.then(() => $.fs.write(path, JSON.stringify(auditRows, null, 2))).catch(() => {})
  await auditQueue
}

// Fail closed. The engine skips a hook that throws, fails its budget or answers a wrong shape, and
// runs what is beneath it with the ORIGINAL input, so a throw here would send raw text to the model
// (Claude Code 2.1.291 types: EngineEventOf, "a guard fails open unless its registration carries a
// `.catch`"). So a failed scan never throws: each text it could not check becomes BLOCKED_TEXT and
// the hook answers normally. BLOCKED_TEXT is not placeholder-shaped, so tool.call never restores it.
const BLOCKED_TEXT = '[PROMPTGUARD_BLOCKED: detector failure]'
const blockStrings = value => mapStrings(value, () => BLOCKED_TEXT)

// { ok: true, value } with the sanitized value, or { ok: false } after a raw-free failure audit row.
// `signal` is the hook's next.signal; it never reaches the audit row.
async function trySanitize($, value, source, { signal, ...extra } = {}) {
  try {
    const result = await sanitize($, value, source, signal)
    await appendAudit($, source, result, extra)
    return { ok: true, value: result.value }
  } catch (error) {
    try { await appendFailureAudit($, source, error, extra) } catch { /* audit is best effort; blocking is not */ }
    return { ok: false }
  }
}

// For values that hold only model-bound text (a string, or strings in arrays): every string of a
// value that failed to scan becomes BLOCKED_TEXT. Pass `block` for values with non-text fields.
async function sanitizeAndAudit($, value, source, extra = {}, block = blockStrings) {
  const scanned = await trySanitize($, value, source, extra)
  return scanned.ok ? scanned.value : block(value)
}

const blockInstructionFiles = files => files?.map(file => ({ ...file, content: BLOCKED_TEXT }))

function blockRow(e) {
  const content = e.message?.content
  if (!UNSANITIZED_DOORS.has(e.door) || !Array.isArray(content)) return e
  return { ...e, message: { ...e.message, content: rebuildRow(content, blockStrings(rowTexts(content))) } }
}

// Backstops for a hook that fails anyway (a bug, an overrun HookBudget): the engine runs the
// registration's `.catch` in its place, and its answer stands. Each refuses what the hook guards.
// `next` there replays a call the hook already made; it never runs beneath twice. The engine reads
// `.catch(...)` statically too: its handler must be a function literal or a function's name.
function catchPromptSubmit($, e, next) { return next.called ? next(e) : next({ ...e, text: BLOCKED_TEXT, context: blockStrings(e.context) }) }
function catchPromptContext($, e, next) { return next.called ? next(e) : next({ ...e, blocks: e.blocks.map(block => ({ ...block, text: BLOCKED_TEXT })), instructionFiles: blockInstructionFiles(e.instructionFiles) }) }
function catchPromptSection($, e, next) { return next.called || e.text === null ? next(e) : next({ ...e, text: BLOCKED_TEXT }) }
// Sanitizes on the way up, so the replayed result is still raw: block every section's text.
async function catchPromptCompose($, e, next) {
  const result = await next(e)
  return { ...result, sections: result.sections.map(section => ({ ...section, text: BLOCKED_TEXT })) }
}
function catchPromptAttachment($, e, next) { return next.called ? next(e) : next({ ...e, text: BLOCKED_TEXT }) }
function catchSkillPrompt($, e, next) { return next.called ? next(e) : next({ ...e, text: BLOCKED_TEXT }) }
function catchAgentSpawn($, e, next) { return next.called ? next(e) : next({ ...e, prompt: BLOCKED_TEXT, description: BLOCKED_TEXT }) }
// Unscanned output never goes back, and a call the hook did not get to start never runs.
function catchToolCall($, e, next) { return e.tool === 'mcp__pgdetector__scan_batch' ? next(e) : { deny: BLOCKED_TEXT } }
function catchSessionCompact() { return { skip: BLOCKED_TEXT } }
function catchSessionAppend($, e, next) { return next.called ? next(e) : next(blockRow(e)) }
// Ends the response here: the rest of the stream is unscanned.
async function* catchTurnStep() {}

function auditTool(tool) {
  if (['Read', 'Grep', 'Bash', 'Agent'].includes(tool)) return tool
  if (typeof tool === 'string' && tool.startsWith('mcp__')) return 'MCP tool'
  return tool ? 'Other tool' : undefined
}

// Only text blocks and a tool_result's text are rewritable; every other block passes through.
function rowTexts(content) {
  return content.map(block => {
    if (block?.type === 'text' && typeof block.text === 'string') return block.text
    if (block?.type === 'tool_result' && typeof block.content === 'string') return block.content
    if (block?.type === 'tool_result' && Array.isArray(block.content)) return block.content.map(item => item?.type === 'text' && typeof item.text === 'string' ? item.text : null)
    return null
  })
}

function rebuildRow(content, texts) {
  return content.map((block, index) => {
    if (block?.type === 'text' && typeof block.text === 'string') return { ...block, text: texts[index] }
    if (block?.type === 'tool_result' && typeof block.content === 'string') return { ...block, content: texts[index] }
    if (block?.type === 'tool_result' && Array.isArray(block.content)) return { ...block, content: block.content.map((item, i) => texts[index][i] === null ? item : { ...item, text: texts[index][i] }) }
    return block
  })
}

function toolSource(e, isError) {
  if (e.tool === 'Read') return 'read_result'
  if (e.tool === 'Grep') return 'grep'
  if (e.tool === 'Bash') return isError ? 'bash_error' : 'bash_stdout'
  if (e.tool === 'Agent') return 'subagent'
  if (String(e.tool).startsWith('mcp__')) return 'mcp'
  return 'tool_result'
}

export function register(on) {
  // Each registration carries its `.catch` backstop (catch* above). The engine reads `on("<event>", hook)`
  // statically, so every call keeps a literal event name.
  on('prompt.submit', async ($, e, next) => {
    if (await $.env.get('PG_MOD_FAILURE_MODE') === 'throw') throw new Error('synthetic Mod failure')
    const text = await sanitizeAndAudit($, e.text, 'user_prompt', { signal: next.signal, hook: 'prompt.submit' })
    const context = await sanitizeAndAudit($, e.context, 'history', { signal: next.signal, hook: 'prompt.submit' })
    return next({ ...e, text, context })
  }).catch(catchPromptSubmit)

  on('prompt.context', async ($, e, next) => {
    const blocks = []
    for (const block of e.blocks) blocks.push({ ...block, text: await sanitizeAndAudit($, block.text, 'claude_md', { signal: next.signal, hook: 'prompt.context' }) })
    // path and kind are scanned too, but on a failure only content is blocked: kind is an enum.
    return next({ ...e, blocks, instructionFiles: (await sanitizeAndAudit($, e.instructionFiles, 'claude_md', { signal: next.signal, hook: 'prompt.context' }, blockInstructionFiles)) })
  }).catch(catchPromptContext)

  on('prompt.section', async ($, e, next) => e.text === null ? next(e) : next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { signal: next.signal, hook: 'prompt.section', name: e.name }) })).catch(catchPromptSection)

  on('prompt.compose', async ($, e, next) => {
    const result = await next(e)
    const sections = []
    for (const section of result.sections) sections.push({ ...section, text: await sanitizeAndAudit($, section.text, 'automatic_context', { signal: next.signal, hook: 'prompt.compose' }) })
    // After sanitizing: the guide is PromptGuard's own text, never sent to the detector or masked.
    if (setting('PG_PLACEHOLDER_GUIDE', await $.env.get('PG_PLACEHOLDER_GUIDE')) === 'on') {
      sections.push({ id: 'promptguard:placeholder-guide', text: placeholderGuide(setting('PG_RESTORE_ESCAPED', await $.env.get('PG_RESTORE_ESCAPED')) === 'on'), scope: 'session' })
    }
    return { ...result, sections }
  }).catch(catchPromptCompose)

  on('prompt.attachment', async ($, e, next) => next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { signal: next.signal, hook: 'prompt.attachment', type: e.type }) })).catch(catchPromptAttachment)
  on('skill.prompt', async ($, e, next) => next({ ...e, text: await sanitizeAndAudit($, e.text, 'automatic_context', { signal: next.signal, hook: 'skill.prompt', skill: e.skill }) })).catch(catchSkillPrompt)
  on('agent.spawn', async ($, e, next) => next({ ...e, prompt: await sanitizeAndAudit($, e.prompt, 'subagent', { signal: next.signal, hook: 'agent.spawn' }), description: (await sanitizeAndAudit($, e.description, 'subagent', { signal: next.signal, hook: 'agent.spawn' })) })).catch(catchAgentSpawn)

  on('tool.call', async ($, e, next) => {
    if (e.tool === 'mcp__pgdetector__scan_batch') return next(e)
    const operation = ++toolOperation
    await loadSettings($)
    const restoreEnabled = RESTORE_TOOLS.has(e.tool) && await $.env.get('PG_RESTORE_PLACEHOLDERS') !== 'off'
    const escaped = restoreEnabled && setting('PG_RESTORE_ESCAPED', await $.env.get('PG_RESTORE_ESCAPED')) === 'on'
    const { input, restoredCount } = restoreEnabled ? restoreToolInput(e, escaped) : { input: e, restoredCount: 0 }
    const lifecycle = { findingCount: null, types: {}, latencyMs: 0, findings: [] }
    const extra = { hook: 'tool.call', tool: e.tool, operation, restored_count: restoredCount }
    const dump = e.tool === 'Bash' ? secretDumpTool(e.command) : { tool: null, paths: [] }
    const dumpTool = dump.tool && setting('PG_SECRET_DUMP_GUARD', await $.env.get('PG_SECRET_DUMP_GUARD')) === 'on' ? dump.tool : null
    // Read too: a secret-looking file Read opens is preloaded before its content reaches the detector, so the re-mask
    // covers what the detector misses (a password file with no key name).
    const preloadPaths = e.tool === 'Read' && typeof e.file_path === 'string' && secretPath(e.file_path) ? [e.file_path] : dump.paths
    if (preloadPaths.length && setting('PG_SECRET_FILE_PRELOAD', await $.env.get('PG_SECRET_FILE_PRELOAD')) === 'on') await preloadSecretFiles($, preloadPaths)
    await appendAudit($, toolSource(e, false), lifecycle, { ...extra, event: 'tool_started' })
    let result
    try { result = await next(input) }
    catch {
      await appendAudit($, toolSource(e, false), lifecycle, { ...extra, event: 'tool_failed' })
      throw new Error('PromptGuard tool execution failure')
    }
    if (result.deny !== undefined) {
      await appendAudit($, toolSource(e, false), lifecycle, { ...extra, event: 'tool_denied' })
      const deny = typeof result.deny === 'string' ? remaskText(result.deny, { count: 0 }) : result.deny
      return deny === result.deny ? result : { ...result, deny }
    }
    if (dumpTool) {
      secretDumpCount++
      await appendAudit($, toolSource(e, result.isError === true), lifecycle, { ...extra, event: 'secret_dump_guarded', is_error: result.isError === true, dump_tool: dumpTool, secret_dump_count: secretDumpCount })
      if (result.isError === true) return { deny: SECRET_DUMP_NOTICE }
      result = guardedResult(result)
    }
    const source = toolSource(e, result.isError === true)
    extra.is_error = result.isError === true
    // A tool result is structured per tool, so a failed scan denies it whole: the model gets
    // BLOCKED_TEXT as the tool's answer. The tool already ran; only its output is withheld.
    const sanitizedResult = await trySanitize($, result.result, source, { ...extra, signal: next.signal })
    const sanitizedText = result.text === undefined ? { ok: true, value: undefined } : await trySanitize($, result.text, source, { ...extra, signal: next.signal, hook: 'tool.call.text' })
    const sanitizedContext = await trySanitize($, result.context, source, { ...extra, signal: next.signal, hook: 'tool.call.context' })
    if (!sanitizedResult.ok || !sanitizedText.ok || !sanitizedContext.ok) return { deny: BLOCKED_TEXT }
    if (result.isError === true) return { deny: String(sanitizedText.value ?? sanitizedResult.value ?? 'Tool call failed') }
    return { ...result, result: sanitizedResult.value, text: sanitizedText.value, context: sanitizedContext.value }
  }).catch(catchToolCall)

  // A failed scan skips the compaction: the conversation stays as it is (its rows were sanitized as
  // they were appended), and neither the compacting model nor the new history gets unscanned text.
  on('session.compact', async ($, e, next) => {
    const strip = messages => messages.map(message => { const { handle, ...built } = message; return built })
    const messages = await trySanitize($, e.messages, 'history', { signal: next.signal, hook: 'session.compact' })
    const instructions = e.instructions === undefined ? { ok: true, value: undefined } : await trySanitize($, e.instructions, 'history', { signal: next.signal, hook: 'session.compact', trigger: e.trigger })
    if (!messages.ok || !instructions.ok) return { skip: BLOCKED_TEXT }
    const result = await next({ ...e, messages: strip(messages.value), instructions: instructions.value })
    if (result.skip !== undefined) return result
    const sanitized = await trySanitize($, result.messages, 'history', { signal: next.signal, hook: 'session.compact' })
    if (!sanitized.ok) return { skip: BLOCKED_TEXT }
    return { ...result, messages: strip(sanitized.value) }
  }).catch(catchSessionCompact)

  // Rewrites the row before it is stored, so neither the model nor the transcript file sees raw values.
  on('session.append', async ($, e, next) => {
    const content = e.message?.content
    if (!UNSANITIZED_DOORS.has(e.door) || !Array.isArray(content)) return next(e)
    const texts = rowTexts(content)
    if (!texts.some(text => text !== null)) return next(e)
    const source = e.door === 'command' ? 'user_command' : 'history'
    const sanitized = await sanitizeAndAudit($, texts, source, { signal: next.signal, hook: 'session.append' })
    return next({ ...e, message: { ...e.message, content: rebuildRow(content, sanitized) } })
  }).catch(catchSessionAppend)

  on('turn.step', async function* ($, e, next) {
    const agentInputs = new Set()
    for await (const chunk of next(e)) {
      if (chunk.kind === 'text') yield { ...chunk, text: await sanitizeAndAudit($, chunk.text, 'history', { signal: next.signal, hook: 'turn.step', agent_id: e.agentId }) }
      else if (chunk.kind === 'tool') { if (chunk.name === 'Agent') agentInputs.add(chunk.index); yield chunk }
      // A blocked fragment may leave the Agent input unparsable; the call then fails, raw-free.
      else if (chunk.kind === 'input' && agentInputs.has(chunk.index)) yield { ...chunk, json: await sanitizeAndAudit($, chunk.json, 'subagent', { signal: next.signal, hook: 'turn.step.agent-input', agent_id: e.agentId }) }
      else yield chunk
    }
  }).catch(catchTurnStep)
}
