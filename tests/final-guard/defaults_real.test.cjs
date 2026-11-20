'use strict'

// release/defaults-1120: with none of the settings given, the Native Mod's and the Final Guard's detector workers
// (the same pgdetector, started as the supervisor starts them) report the same new defaults, so the supervisor's
// filter settings check warns about nothing; off given to both brings the earlier settings back, still with no
// warning. Skipped when the project's Python is not installed. Synthetic values only.
const assert = require('node:assert/strict')
const fs = require('node:fs')
const net = require('node:net')
const path = require('node:path')
const { spawn } = require('node:child_process')
const { after, describe, test } = require('node:test')
const { RuntimeSupervisor } = require('../../src/supervisor/runtime.cjs')

const ROOT = path.resolve(__dirname, '..', '..')
const PYTHON = process.env.PROMPTGUARD_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const SETTINGS = ['PG_DETECTOR_FILTERS', 'PG_DETECTOR_FILTER_DUMMY', 'PG_RULE_HEX_KEY', 'PG_SHELL_POSITIONAL_MIN', 'PG_PLACEHOLDER_PUBLIC_PREFIX',
  'PG_REMASK', 'PG_REMASK_SHORT', 'PG_PLACEHOLDER_GUIDE', 'PG_RESTORE_ESCAPED', 'PG_GUARD_COUNT_TOKENS']
const children = []

const freePort = () => new Promise((resolve, reject) => {
  const probe = net.createServer()
  probe.once('error', reject)
  probe.listen(0, '127.0.0.1', () => {
    const { port } = probe.address()
    probe.close(() => resolve(port))
  })
})

// The shell's environment without any of the settings, plus `extra`.
function environment(extra) {
  const env = { ...process.env, PG_DETECTOR_DISABLE: 'gitleaks', PYTHONIOENCODING: 'utf-8' }
  for (const name of SETTINGS) delete env[name]
  return { ...env, ...extra }
}

async function worker(role, extra) {
  const port = await freePort()
  const child = spawn(PYTHON, [path.join(ROOT, 'src', 'detector', 'worker.py')], { cwd: ROOT, env: environment({ ...extra, PG_DETECTOR_PORT: String(port), PG_DETECTOR_ROLE: role }), stdio: 'ignore', windowsHide: true })
  children.push(child)
  for (let attempt = 0; attempt < 600; attempt++) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/ready`)
      if (response.ok) return response.json()
    } catch { /* not up yet */ }
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error(`${role} worker not ready`)
}

function check(transform, verification) {
  const services = new Map([
    ['transformDetector', { readyValue: transform }],
    ['verificationDetector', { readyValue: verification }],
    ['finalGuard', { env: {} }],
  ])
  const logs = []
  const mismatch = RuntimeSupervisor.prototype.checkFilterSettings.call({ service: name => services.get(name), log: (level, message) => logs.push(level) })
  return { mismatch, logs, guardEnv: services.get('finalGuard').env }
}

describe('new defaults: the Mod\'s and the Guard\'s workers agree', { skip: !fs.existsSync(PYTHON) }, () => {
  after(() => { for (const child of children) child.kill() })

  test('nothing set: both report FILTERS on and DUMMY off, and the supervisor warns about nothing', { timeout: 120_000 }, async () => {
    const [transform, verification] = await Promise.all([worker('transform', {}), worker('verification', {})])
    const expected = { PG_DETECTOR_FILTERS: 'on', PG_DETECTOR_FILTER_DUMMY: 'off' }
    assert.deepEqual(transform.filter_settings, expected)
    assert.deepEqual(verification.filter_settings, expected)
    const { mismatch, logs, guardEnv } = check(transform, verification)
    assert.deepEqual(mismatch, [])
    assert.deepEqual(logs, [])
    assert.equal(guardEnv.PG_DETECTOR_FILTER_MISMATCH, '')
  })

  test('off given to both: the earlier settings, still no warning', { timeout: 120_000 }, async () => {
    const off = { PG_DETECTOR_FILTERS: 'off' }
    const [transform, verification] = await Promise.all([worker('transform', off), worker('verification', off)])
    assert.deepEqual(transform.filter_settings, { PG_DETECTOR_FILTERS: 'off', PG_DETECTOR_FILTER_DUMMY: 'off' })
    assert.deepEqual(check(transform, verification).mismatch, [])
  })

  test('off given to one worker only is still named', { timeout: 120_000 }, async () => {
    const [transform, verification] = await Promise.all([worker('transform', { PG_DETECTOR_FILTERS: 'off' }), worker('verification', {})])
    const { mismatch, logs } = check(transform, verification)
    assert.deepEqual(mismatch, ['PG_DETECTOR_FILTERS'])
    assert.deepEqual(logs, ['warn'])
  })
})
