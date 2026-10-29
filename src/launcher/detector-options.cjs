'use strict'

// `promptguard run` detector options -> the PG_* environment the detector
// workers already read (src/detector/pgdetector/ensemble.py, supervisor config).
// Kept separate from cli.cjs so it can be tested without starting anything.

const fs = require('fs')
const path = require('path')

const DEFAULT_DETECTOR_CONFIG = path.resolve(__dirname, '..', 'detector', 'detector.json')
const POLICIES = new Set(['union', 'majority'])
const ML_ADAPTERS = new Set(['ml-v9', 'ml-qwen'])
const ML_READINESS_MS = 180000
const QWEN_DETECTOR_TIMEOUT_MS = 30000

function names(value) {
  return String(value || '').split(',').map(item => item.trim()).filter(Boolean)
}

function knownAdapters(env = process.env) {
  const file = env.PG_DETECTOR_CONFIG ? path.resolve(env.PG_DETECTOR_CONFIG) : DEFAULT_DETECTOR_CONFIG
  const config = JSON.parse(fs.readFileSync(file, 'utf8'))
  return (config.adapters || []).map(entry => ({ name: entry.name, enabled: entry.enabled !== false }))
}

function positiveInteger(value, option) {
  if (!/^\d+$/.test(String(value)) || Number(value) <= 0) throw new Error(`${option} must be a positive integer (milliseconds).`)
  return String(Number(value))
}

// Returns the PG_* variables to set; never mutates `env`.
function detectorEnvironment(options, env = process.env) {
  const adapters = knownAdapters(env)
  const valid = new Set(adapters.map(item => item.name))
  const enable = names(options.enable)
  const disable = names(options.disable)
  const unknown = [...enable, ...disable].filter(name => !valid.has(name))
  if (unknown.length) {
    throw new Error(`Unknown detector name(s): ${unknown.join(', ')}. Known: ${[...valid].join(', ')}.`)
  }
  if (options.policy && !POLICIES.has(options.policy)) throw new Error('--policy must be union or majority.')

  const out = {}
  if (options.enable !== undefined) out.PG_DETECTOR_ENABLE = enable.join(',')
  if (options.disable !== undefined) out.PG_DETECTOR_DISABLE = disable.join(',')
  if (options.policy) out.PG_DETECTOR_CANDIDATE_POLICY = options.policy
  if (options.detectorTimeoutMs !== undefined) out.PG_DETECTOR_TIMEOUT_MS = positiveInteger(options.detectorTimeoutMs, '--detector-timeout-ms')
  if (options.readinessTimeoutMs !== undefined) out.PG_READINESS_TIMEOUT_MS = positiveInteger(options.readinessTimeoutMs, '--readiness-timeout-ms')

  // Which adapters will actually run, the same way ensemble.py decides.
  const on = new Set(names(out.PG_DETECTOR_ENABLE ?? env.PG_DETECTOR_ENABLE))
  const off = new Set(names(out.PG_DETECTOR_DISABLE ?? env.PG_DETECTOR_DISABLE))
  const active = adapters.filter(item => (item.enabled || on.has(item.name)) && !off.has(item.name)).map(item => item.name)
  if (!active.length) throw new Error('Every detector is disabled; enable at least one.')

  // Model adapters load slowly and Qwen scans take seconds: raise the waits
  // unless the user (option or environment) already chose them.
  if (active.some(name => ML_ADAPTERS.has(name)) && out.PG_READINESS_TIMEOUT_MS === undefined && !env.PG_READINESS_TIMEOUT_MS) {
    out.PG_READINESS_TIMEOUT_MS = String(ML_READINESS_MS)
  }
  if (active.includes('ml-qwen') && out.PG_DETECTOR_TIMEOUT_MS === undefined && !env.PG_DETECTOR_TIMEOUT_MS) {
    out.PG_DETECTOR_TIMEOUT_MS = String(QWEN_DETECTOR_TIMEOUT_MS)
  }
  const policy = out.PG_DETECTOR_CANDIDATE_POLICY || env.PG_DETECTOR_CANDIDATE_POLICY || 'config default'
  return { env: out, active, summary: `Detectors: ${active.join(', ')} (policy: ${policy})` }
}

module.exports = { detectorEnvironment, knownAdapters, names }
