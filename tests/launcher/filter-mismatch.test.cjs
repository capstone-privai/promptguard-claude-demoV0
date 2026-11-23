'use strict'

// The Native Mod's and the Final Guard's detector workers must run the same detector filter settings. The
// supervisor compares what each worker reports as ready and names the settings that differ (names, no values).
const test = require('node:test')
const assert = require('node:assert/strict')
const { filterSettingsMismatch, modelSettingsMismatch } = require('../../src/supervisor/filter-settings.cjs')

const off = { filter_settings: { PG_DETECTOR_FILTERS: 'off', PG_DETECTOR_FILTER_DUMMY: 'off' } }
const on = { filter_settings: { PG_DETECTOR_FILTERS: 'on', PG_DETECTOR_FILTER_DUMMY: 'off' } }
const all = { filter_settings: { PG_DETECTOR_FILTERS: 'on', PG_DETECTOR_FILTER_DUMMY: 'on' } }

test('same settings: no mismatch', () => {
  assert.deepEqual(filterSettingsMismatch(off, off), [])
  assert.deepEqual(filterSettingsMismatch(all, all), [])
})

test('different settings are named', () => {
  assert.deepEqual(filterSettingsMismatch(off, on), ['PG_DETECTOR_FILTERS'])
  assert.deepEqual(filterSettingsMismatch(off, all), ['PG_DETECTOR_FILTERS', 'PG_DETECTOR_FILTER_DUMMY'])
})

test('the supervisor warns with names only and hands the names to the Final Guard', () => {
  const { RuntimeSupervisor } = require('../../src/supervisor/runtime.cjs')
  for (const [transform, verification, expected] of [[off, on, 'PG_DETECTOR_FILTERS'], [on, on, '']]) {
    const services = new Map([
      ['transformDetector', { readyValue: transform }],
      ['verificationDetector', { readyValue: verification }],
      ['finalGuard', { env: { PG_GUARD_PORT: '1' } }],
    ])
    const logs = []
    const fake = { service: name => services.get(name), log: (level, message) => logs.push([level, message]) }
    RuntimeSupervisor.prototype.checkFilterSettings.call(fake)
    assert.equal(services.get('finalGuard').env.PG_DETECTOR_FILTER_MISMATCH, expected)
    assert.equal(services.get('finalGuard').env.PG_GUARD_PORT, '1')
    assert.equal(logs.length, expected ? 1 : 0)
    if (expected) {
      assert.equal(logs[0][0], 'warn')
      assert.match(logs[0][1], /PG_DETECTOR_FILTERS/)
    }
  }
})

test('a worker that does not report settings counts as off', () => {
  assert.deepEqual(filterSettingsMismatch({}, off), [])
  assert.deepEqual(filterSettingsMismatch({}, on), ['PG_DETECTOR_FILTERS'])
  assert.deepEqual(filterSettingsMismatch(null, undefined), [])
})

// ---- model settings (feat/onprem-profile): the ml-span checkpoint, the verifier bundle and the candidate policy.
// Workers report a digest of each resolved path (pgdetector describe(): model_settings), never the path.
const model = (checkpoint, bundle, policy) => ({ model_settings: { PG_ML_CHECKPOINT: checkpoint, PG_VERIFIER_BUNDLE: bundle, PG_DETECTOR_CANDIDATE_POLICY: policy } })

test('model settings: same digests and policy, no mismatch; any difference is named', () => {
  assert.deepEqual(modelSettingsMismatch(model('aa', null, 'union'), model('aa', null, 'union')), [])
  assert.deepEqual(modelSettingsMismatch(model('aa', null, 'union'), model('bb', null, 'union')), ['PG_ML_CHECKPOINT'])
  assert.deepEqual(modelSettingsMismatch(model(null, 'cc', 'verifier'), model(null, 'dd', 'union')), ['PG_VERIFIER_BUNDLE', 'PG_DETECTOR_CANDIDATE_POLICY'])
  assert.deepEqual(modelSettingsMismatch(model(null, null, 'union'), {}), [], 'a worker that does not report them counts as default')
  assert.deepEqual(modelSettingsMismatch({}, model(null, null, 'verifier')), ['PG_DETECTOR_CANDIDATE_POLICY'])
})

test('the supervisor warns with names only and hands filter and model names to the Final Guard', () => {
  const { RuntimeSupervisor } = require('../../src/supervisor/runtime.cjs')
  const transform = { ...off, ...model('digest-one-0001', 'digest-two-0002', 'union') }
  const verification = { ...on, ...model('digest-three-003', 'digest-two-0002', 'verifier') }
  const services = new Map([
    ['transformDetector', { readyValue: transform }],
    ['verificationDetector', { readyValue: verification }],
    ['finalGuard', { env: {} }],
  ])
  const logs = []
  const fake = { service: name => services.get(name), log: (level, message) => logs.push([level, message]) }
  RuntimeSupervisor.prototype.checkFilterSettings.call(fake)
  assert.equal(services.get('finalGuard').env.PG_DETECTOR_FILTER_MISMATCH, 'PG_DETECTOR_FILTERS,PG_ML_CHECKPOINT,PG_DETECTOR_CANDIDATE_POLICY')
  const text = logs.map(([, message]) => message).join(' ')
  assert.match(text, /PG_ML_CHECKPOINT/)
  assert.match(text, /PG_DETECTOR_CANDIDATE_POLICY/)
  assert.ok(!/digest-/.test(text), 'no digest in the warning')
  assert.ok(logs.every(([level]) => level === 'warn'))
})
