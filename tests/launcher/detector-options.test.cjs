'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const { detectorEnvironment } = require('../../src/launcher/detector-options.cjs')

const clean = {} // an environment with no PG_* detector variables

test('no options keeps the shipped selection and adds nothing', () => {
  const result = detectorEnvironment({}, clean)
  assert.deepEqual(result.env, {})
  assert.deepEqual(result.active, ['credsweeper', 'gitleaks', 'promptguard-rules', 'shell-aware'])
})

test('--enable ml-v9 turns it on and raises the readiness wait', () => {
  const result = detectorEnvironment({ enable: 'ml-v9' }, clean)
  assert.equal(result.env.PG_DETECTOR_ENABLE, 'ml-v9')
  assert.equal(result.env.PG_READINESS_TIMEOUT_MS, '180000')
  assert.equal(result.env.PG_DETECTOR_TIMEOUT_MS, undefined)
  assert.ok(result.active.includes('ml-v9'))
})

test('--enable ml-qwen also raises the detector timeout unless given', () => {
  assert.equal(detectorEnvironment({ enable: 'ml-qwen' }, clean).env.PG_DETECTOR_TIMEOUT_MS, '30000')
  assert.equal(detectorEnvironment({ enable: 'ml-qwen', detectorTimeoutMs: '45000' }, clean).env.PG_DETECTOR_TIMEOUT_MS, '45000')
  assert.equal(detectorEnvironment({ enable: 'ml-qwen' }, { PG_DETECTOR_TIMEOUT_MS: '20000' }).env.PG_DETECTOR_TIMEOUT_MS, undefined)
})

test('--disable wins over --enable and removes the detector', () => {
  const result = detectorEnvironment({ enable: 'ml-v9', disable: 'ml-v9,shell-aware' }, clean)
  assert.equal(result.env.PG_DETECTOR_DISABLE, 'ml-v9,shell-aware')
  assert.ok(!result.active.includes('ml-v9'))
  assert.ok(!result.active.includes('shell-aware'))
  assert.equal(result.env.PG_READINESS_TIMEOUT_MS, undefined, 'no model left on, so no longer wait')
})

test('--policy is validated and passed through', () => {
  assert.equal(detectorEnvironment({ policy: 'majority' }, clean).env.PG_DETECTOR_CANDIDATE_POLICY, 'majority')
  assert.throws(() => detectorEnvironment({ policy: 'any' }, clean), /union or majority/)
})

test('unknown names, all-off and bad numbers are refused', () => {
  assert.throws(() => detectorEnvironment({ enable: 'ml-v8' }, clean), /Unknown detector name/)
  assert.throws(() => detectorEnvironment({ disable: 'credsweeper,gitleaks,promptguard-rules,shell-aware' }, clean), /Every detector is disabled/)
  assert.throws(() => detectorEnvironment({ readinessTimeoutMs: '3m' }, clean), /positive integer/)
})

test('environment variables still work when no option is given', () => {
  const result = detectorEnvironment({}, { PG_DETECTOR_ENABLE: 'ml-v9' })
  assert.ok(result.active.includes('ml-v9'))
  assert.equal(result.env.PG_READINESS_TIMEOUT_MS, '180000')
})
