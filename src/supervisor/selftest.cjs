'use strict'

const assert = require('assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { loadConfig, validateAndResolve } = require('./config.cjs')
const { parseClaudeVersion, safeServiceEnvironment } = require('./runtime.cjs')
const { sanitizeGuardStatus } = require('./state.cjs')

const root = path.resolve(__dirname, '..', '..')
const configPath = path.join(root, 'promptguard.config.json')
const config = loadConfig(configPath)

assert.equal(config.schemaVersion, 1)
assert.equal(config.claudeVersion, '2.1.291')
assert.notEqual(config.modDetectorPort, config.guardDetectorPort)
assert.notEqual(config.guardPort, config.guardDetectorPort)
assert.equal(parseClaudeVersion('2.1.291 (Claude Code)'), '2.1.291')
assert.equal(parseClaudeVersion('unknown'), null)

const environment = safeServiceEnvironment({ PG_TEST_VALUE: 'safe' })
assert.equal(environment.ANTHROPIC_API_KEY, undefined)
assert.equal(environment.CLAUDE_CODE_OAUTH_TOKEN, undefined)
assert.equal(environment.PG_TEST_VALUE, 'safe')

const sanitized = sanitizeGuardStatus({
  ok: true,
  ready: true,
  requests: 5,
  findings: 4,
  counters: { allowed: 2, blocked: 3, accidentalRawValue: 'must-not-survive' },
  body: 'must-not-survive',
})
assert.deepEqual(sanitized, { ok: true, ready: true, uptimeMs: null, counters: { allowed: 2, blocked: 3, requests: 5, findings: 4 } })

const rawConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'))
assert.throws(() => validateAndResolve({ ...rawConfig, apiKey: 'forbidden' }, path.join(os.tmpdir(), 'promptguard-test.json')), /unknown fields/)
assert.throws(() => validateAndResolve({ ...rawConfig, upstreamBaseUrl: 'https://user:password@example.test' }, path.join(os.tmpdir(), 'promptguard-test.json')), /must not contain credentials/)
assert.throws(() => validateAndResolve({ ...rawConfig, guardDetectorPort: rawConfig.modDetectorPort }, path.join(os.tmpdir(), 'promptguard-test.json')), /must be distinct/)

console.log('PromptGuard supervisor self-test passed.')
