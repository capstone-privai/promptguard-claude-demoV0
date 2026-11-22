// What Claude Code 2.1.291 checks before it loads register.mjs, checked here without the engine. The engine refuses
// the whole hooks module when $.env.get is called with anything but a literal name, and a refused module masks
// nothing (release/defaults-1120 first passed a variable and only the real-engine e2e caught it).
// Run: node --test tests/mod/test_engine_shape.mjs
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const source = readFileSync(new URL('../../src/native-mod/hooks/register.mjs', import.meta.url), 'utf8')

test('$.env.get always takes a literal name', () => {
  const calls = [...source.matchAll(/\$\.env\.get\(([^)]*)\)/g)].map(match => match[1].trim())
  assert.ok(calls.length > 0)
  for (const argument of calls) assert.match(argument, /^'[A-Z][A-Z0-9_]*'$/, argument)
})

test('every setting with a default is read by its literal name', () => {
  const block = /const DEFAULTS = Object\.freeze\(\{([\s\S]*?)\n\}\)/.exec(source)[1]
  for (const [, name] of block.matchAll(/(PG_[A-Z_]+):/g)) {
    assert.ok(source.includes(`$.env.get('${name}')`), name)
  }
})

test('$ is only called: $.noun.event(...) at the call site, never read as a value', () => {
  // 2.1.291 refused the hooks module for `typeof $.fs.stat === 'function'` (fix/secret-dump-guard).
  const code = source.replace(/\/\/.*$/gm, '')
  const VALUES = new Set(['$.plugin.root']) // properties the engine gives as values
  const uses = [...code.matchAll(/\$\.[A-Za-z]+\.[A-Za-z]+(?!\w)(\s*\()?/g)]
  assert.ok(uses.length > 0)
  for (const use of uses.filter(u => !VALUES.has(u[0].trim()))) assert.ok(use[1], `${use[0].trim()} is not called`)
})
