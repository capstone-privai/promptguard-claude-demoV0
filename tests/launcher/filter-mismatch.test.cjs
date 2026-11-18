'use strict'

// The Native Mod's and the Final Guard's detector workers must run the same detector filter settings. The
// supervisor compares what each worker reports as ready and names the settings that differ (names, no values).
const test = require('node:test')
const assert = require('node:assert/strict')
const { filterSettingsMismatch } = require('../../src/supervisor/filter-settings.cjs')

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
