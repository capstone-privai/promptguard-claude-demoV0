'use strict'

const fs = require('fs')
const path = require('path')

function pidIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error.code === 'EPERM'
  }
}

function readState(filePath) {
  try {
    const value = JSON.parse(fs.readFileSync(filePath, 'utf8'))
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null
  } catch {
    return null
  }
}

class StateStore {
  constructor(runtimeDirectory) {
    this.runtimeDirectory = runtimeDirectory
    this.filePath = path.join(runtimeDirectory, 'runtime-state.json')
    this.value = null
    fs.mkdirSync(runtimeDirectory, { recursive: true, mode: 0o700 })
  }

  assertNotRunning() {
    const existing = readState(this.filePath)
    if (existing && ['starting', 'running', 'degraded', 'recovering'].includes(existing.status) && pidIsAlive(existing.pid)) {
      throw new Error(`PromptGuard runtime is already running (PID ${existing.pid}).`)
    }
  }

  write(value) {
    const safeValue = {
      schemaVersion: 1,
      ...value,
      updatedAt: new Date().toISOString(),
    }
    const temporary = `${this.filePath}.${process.pid}.tmp`
    fs.writeFileSync(temporary, `${JSON.stringify(safeValue, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
    try {
      fs.renameSync(temporary, this.filePath)
    } catch {
      try { fs.unlinkSync(this.filePath) } catch { }
      fs.renameSync(temporary, this.filePath)
    }
    this.value = safeValue
    return safeValue
  }
}

function safeNumericObject(value, depth = 0) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || depth > 3) return {}
  const output = {}
  for (const [key, item] of Object.entries(value)) {
    if (!/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(key)) continue
    if (typeof item === 'number' && Number.isFinite(item)) output[key] = item
    else if (typeof item === 'boolean') output[key] = item
    else if (item && typeof item === 'object' && !Array.isArray(item)) output[key] = safeNumericObject(item, depth + 1)
  }
  return output
}

function sanitizeGuardStatus(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const topLevelCounters = {}
  for (const key of ['requests', 'allowed', 'blocked', 'findings', 'detector_errors', 'upstream_errors', 'active_requests', 'max_body_bytes', 'rss_bytes']) {
    if (typeof value[key] === 'number' && Number.isFinite(value[key])) topLevelCounters[key] = value[key]
  }
  return {
    ok: value.ok === true,
    ready: value.ready === true,
    uptimeMs: Number.isFinite(value.uptime_ms)
      ? value.uptime_ms
      : (Number.isFinite(value.uptimeMs)
          ? value.uptimeMs
          : (Number.isFinite(value.uptime_seconds) ? value.uptime_seconds * 1000 : null)),
    counters: { ...safeNumericObject(value.counters), ...topLevelCounters },
  }
}

module.exports = { StateStore, pidIsAlive, readState, sanitizeGuardStatus }
