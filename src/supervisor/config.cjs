'use strict'

const fs = require('fs')
const path = require('path')
const { spawnSync } = require('child_process')

const PROJECT_ROOT = path.resolve(__dirname, '..', '..')

const REQUIRED_FIELDS = Object.freeze([
  'schemaVersion',
  'claudeBinary',
  'claudeVersion',
  'strictClaudeVersion',
  'pythonBinary',
  'guardHost',
  'guardPort',
  'modDetectorPort',
  'guardDetectorPort',
  'detectorTimeoutMs',
  'maxBodyBytes',
  'workerRestartLimit',
  'restartBackoffMs',
  'restartBackoffMaxMs',
  'healthCheckIntervalMs',
  'healthFailureThreshold',
  'readinessTimeoutMs',
  'shutdownTimeoutMs',
  'auditPath',
  'logLevel',
  'upstreamBaseUrl',
])

const ALLOWED_FIELDS = new Set(REQUIRED_FIELDS)

class ConfigError extends Error {
  constructor(message) {
    super(message)
    this.name = 'ConfigError'
  }
}
function fail(message) {
  throw new ConfigError(`Invalid PromptGuard config: ${message}`)
}

function readJson(filePath) {
  let raw
  try {
    raw = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '')
  } catch (error) {
    throw new ConfigError(`Cannot read PromptGuard config (${error.code || 'READ_ERROR'}).`)
  }
  try {
    return JSON.parse(raw)
  } catch {
    throw new ConfigError('PromptGuard config is not valid JSON.')
  }
}

function requireString(value, name) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) fail(`${name} must be a non-empty string.`)
}

function requireBoolean(value, name) {
  if (typeof value !== 'boolean') fail(`${name} must be a boolean.`)
}

function requireInteger(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    fail(`${name} must be an integer between ${minimum} and ${maximum}.`)
  }
}

function envInteger(name, fallback) {
  const value = process.env[name]
  if (value === undefined || value === '') return fallback
  if (!/^[0-9]+$/.test(value)) fail(`${name} must contain an integer.`)
  return Number(value)
}

function localUrl(host, port) {
  const renderedHost = host.includes(':') ? `[${host}]` : host
  return `http://${renderedHost}:${port}`
}

function validateAndResolve(input, configPath) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('the root value must be an object.')

  const keys = Object.keys(input)
  const unknown = keys.filter(key => !ALLOWED_FIELDS.has(key))
  if (unknown.length) fail('the config contains one or more unknown fields.')
  const missing = REQUIRED_FIELDS.filter(key => !Object.prototype.hasOwnProperty.call(input, key))
  if (missing.length) fail(`missing field(s): ${missing.join(', ')}.`)

  const config = {
    ...input,
    claudeBinary: process.env.PG_CLAUDE_BINARY || input.claudeBinary,
    pythonBinary: process.env.PG_PYTHON || input.pythonBinary,
    guardPort: envInteger('PG_GUARD_PORT', input.guardPort),
    modDetectorPort: envInteger('PG_MOD_DETECTOR_PORT', input.modDetectorPort),
    guardDetectorPort: envInteger('PG_GUARD_DETECTOR_PORT', input.guardDetectorPort),
    detectorTimeoutMs: envInteger('PG_DETECTOR_TIMEOUT_MS', input.detectorTimeoutMs),
    maxBodyBytes: envInteger('PG_MAX_BODY_BYTES', input.maxBodyBytes),
    auditPath: process.env.PG_AUDIT_PATH || input.auditPath,
    upstreamBaseUrl: process.env.PG_UPSTREAM_BASE_URL || input.upstreamBaseUrl,
  }

  if (config.schemaVersion !== 1) fail('schemaVersion must be 1.')
  requireString(config.claudeBinary, 'claudeBinary')
  requireString(config.pythonBinary, 'pythonBinary')
  requireString(config.claudeVersion, 'claudeVersion')
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(config.claudeVersion)) fail('claudeVersion is invalid.')
  requireBoolean(config.strictClaudeVersion, 'strictClaudeVersion')
  if (!['127.0.0.1', 'localhost', '::1'].includes(config.guardHost)) fail('guardHost must be a loopback host.')

  for (const field of ['guardPort', 'modDetectorPort', 'guardDetectorPort']) requireInteger(config[field], field, 1024, 65535)
  if (new Set([config.guardPort, config.modDetectorPort, config.guardDetectorPort]).size !== 3) fail('guard and detector ports must be distinct.')
  requireInteger(config.detectorTimeoutMs, 'detectorTimeoutMs', 50, 60000)
  requireInteger(config.maxBodyBytes, 'maxBodyBytes', 1024, 64 * 1024 * 1024)
  requireInteger(config.workerRestartLimit, 'workerRestartLimit', 0, 100)
  requireInteger(config.restartBackoffMs, 'restartBackoffMs', 10, 60000)
  requireInteger(config.restartBackoffMaxMs, 'restartBackoffMaxMs', 10, 300000)
  if (config.restartBackoffMaxMs < config.restartBackoffMs) fail('restartBackoffMaxMs must be at least restartBackoffMs.')
  requireInteger(config.healthCheckIntervalMs, 'healthCheckIntervalMs', 100, 60000)
  requireInteger(config.healthFailureThreshold, 'healthFailureThreshold', 1, 20)
  requireInteger(config.readinessTimeoutMs, 'readinessTimeoutMs', 1000, 300000)
  requireInteger(config.shutdownTimeoutMs, 'shutdownTimeoutMs', 100, 60000)
  requireString(config.auditPath, 'auditPath')
  if (!['error', 'warn', 'info', 'debug'].includes(config.logLevel)) fail('logLevel must be error, warn, info, or debug.')

  let upstream
  try {
    upstream = new URL(config.upstreamBaseUrl)
  } catch {
    fail('upstreamBaseUrl must be an absolute HTTP(S) URL.')
  }
  if (!['http:', 'https:'].includes(upstream.protocol)) fail('upstreamBaseUrl must use HTTP or HTTPS.')
  if (upstream.username || upstream.password || upstream.search || upstream.hash) {
    fail('upstreamBaseUrl must not contain credentials, query parameters, or fragments.')
  }
  const upstreamPort = Number(upstream.port || (upstream.protocol === 'https:' ? 443 : 80))
  const loopbackNames = new Set(['127.0.0.1', 'localhost', '[::1]', '::1'])
  if (loopbackNames.has(upstream.hostname) && upstreamPort === config.guardPort) fail('upstreamBaseUrl must not point back to Final Guard.')

  const configDirectory = path.dirname(configPath)
  const resolveOptionalPath = value => path.isAbsolute(value) ? path.normalize(value) : path.resolve(configDirectory, value)
  const resolveExecutable = value => {
    if (value === 'auto') return value
    if (path.isAbsolute(value)) return path.normalize(value)
    if (value.includes('/') || value.includes('\\')) return path.resolve(configDirectory, value)
    return value
  }

  config.configPath = configPath
  config.projectRoot = PROJECT_ROOT
  config.auditPath = resolveOptionalPath(config.auditPath)
  config.claudeBinary = resolveExecutable(config.claudeBinary)
  config.pythonBinary = resolveExecutable(config.pythonBinary)
  config.guardUrl = localUrl(config.guardHost, config.guardPort)
  config.modDetectorUrl = localUrl('127.0.0.1', config.modDetectorPort)
  config.guardDetectorUrl = localUrl('127.0.0.1', config.guardDetectorPort)
  config.upstreamBaseUrl = upstream.toString().replace(/\/$/, '')

  return Object.freeze(config)
}

function loadConfig(configPath) {
  const selected = configPath || process.env.PG_CONFIG || path.join(PROJECT_ROOT, 'promptguard.config.json')
  const resolved = path.resolve(selected)
  return validateAndResolve(readJson(resolved), resolved)
}

function pythonVersion(command, prefix) {
  const result = spawnSync(command, [...prefix, '-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")'], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10000,
  })
  if (result.error || result.status !== 0) return null
  const version = String(result.stdout || '').trim()
  return /^3\.(12|14)\.\d+$/.test(version) ? version : null
}

function resolvePython(config) {
  const candidates = []
  if (config.pythonBinary !== 'auto') candidates.push({ command: config.pythonBinary, prefix: [] })
  else {
    candidates.push({ command: path.join(PROJECT_ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'), prefix: [] })
    if (process.platform === 'win32') candidates.push({ command: 'py', prefix: ['-3.12'] }, { command: 'py', prefix: ['-3.14'] })
    candidates.push({ command: 'python3.12', prefix: [] }, { command: 'python3.14', prefix: [] }, { command: 'python3', prefix: [] }, { command: 'python', prefix: [] })
  }

  for (const candidate of candidates) {
    const version = pythonVersion(candidate.command, candidate.prefix)
    if (version) return { ...candidate, version }
  }
  throw new ConfigError('Python 3.12 or 3.14 is unavailable. Run the PromptGuard installer first.')
}

module.exports = {
  ALLOWED_FIELDS,
  ConfigError,
  PROJECT_ROOT,
  loadConfig,
  localUrl,
  resolvePython,
  validateAndResolve,
}
