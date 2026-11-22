'use strict'

// One table of the release/defaults-1120 defaults, checked against each place that holds one: the detector
// (src/detector/pgdetector/settings.py), the Native Mod (src/native-mod/hooks/register.mjs DEFAULTS) and the Final
// Guard (src/guard/lib.cjs). The README's settings table must show the same values.
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const ROOT = path.resolve(__dirname, '..', '..')
const read = file => fs.readFileSync(path.join(ROOT, file), 'utf8')

const DETECTOR = {
  PG_DETECTOR_FILTERS: 'on',
  PG_DETECTOR_FILTER_DUMMY: 'off',
  PG_RULE_HEX_KEY: 'on',
  PG_SHELL_POSITIONAL_MIN: '4',
  PG_PLACEHOLDER_PUBLIC_PREFIX: 'off',
}
const MOD = {
  PG_REMASK: 'on',
  PG_REMASK_SHORT: 'boundary',
  PG_PLACEHOLDER_GUIDE: 'on',
  PG_RESTORE_ESCAPED: 'on',
  PG_PLACEHOLDER_PUBLIC_PREFIX: 'off',
}
const GUARD = { PG_GUARD_COUNT_TOKENS: 'block' }

function pairs(block, pattern) {
  return Object.fromEntries([...block.matchAll(pattern)].map(match => [match[1], match[2]]))
}

test('the detector defaults', () => {
  const block = /DEFAULTS = \{([\s\S]*?)\n\}/.exec(read('src/detector/pgdetector/settings.py'))[1]
  assert.deepEqual(pairs(block, /"(PG_[A-Z_]+)": "([^"]*)"/g), DETECTOR)
})

test('the Native Mod defaults', () => {
  const block = /const DEFAULTS = Object\.freeze\(\{([\s\S]*?)\n\}\)/.exec(read('src/native-mod/hooks/register.mjs'))[1]
  assert.deepEqual(pairs(block, /(PG_[A-Z_]+): '([^']*)'/g), MOD)
})

test('the Final Guard default', () => {
  const { loadConfig } = require('../../src/guard/lib.cjs')
  const env = { PG_UPSTREAM_BASE_URL: 'http://127.0.0.1:1', PG_GUARD_DETECTOR_URL: 'http://127.0.0.1:2' }
  assert.equal(loadConfig(env).countTokensMode, GUARD.PG_GUARD_COUNT_TOKENS)
  assert.equal(loadConfig({ ...env, PG_GUARD_COUNT_TOKENS: '' }).countTokensMode, GUARD.PG_GUARD_COUNT_TOKENS)
})

test('the PG_PLACEHOLDER_PUBLIC_PREFIX default is the same on both sides', () => {
  assert.equal(DETECTOR.PG_PLACEHOLDER_PUBLIC_PREFIX, MOD.PG_PLACEHOLDER_PUBLIC_PREFIX)
})

test('the README settings table shows the same defaults', () => {
  const readme = read('README.md')
  for (const [name, value] of Object.entries({ ...DETECTOR, ...MOD, ...GUARD })) {
    assert.match(readme, new RegExp(`^\\| \`${name}\` \\| \`${value}\` \\|`, 'm'), name)
  }
})
