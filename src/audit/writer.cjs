'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')

const ALLOWED_FIELDS = new Set([
  'timestamp',
  'request_id',
  'session_hash',
  'endpoint',
  'body_size',
  'finding_count',
  'finding_types',
  'decision',
  'reason',
  'scan_latency_ms',
  'upstream_status',
])

const SAFE_DECISIONS = new Set(['allow', 'block'])
const SAFE_TOKEN = /^[A-Z][A-Z0-9_]{0,63}$/

function finiteNumber(value, fallback = null) {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}
function safeToken(value, fallback) {
  return typeof value === 'string' && SAFE_TOKEN.test(value) ? value : fallback
}

function normalizeRecord(input) {
  const record = {
    timestamp: new Date().toISOString(),
    request_id: typeof input.request_id === 'string' ? input.request_id : crypto.randomUUID(),
    session_hash: typeof input.session_hash === 'string' ? input.session_hash : null,
    endpoint: typeof input.endpoint === 'string' && input.endpoint.startsWith('/')
      ? input.endpoint.slice(0, 128)
      : 'UNKNOWN',
    body_size: Math.max(0, Math.trunc(finiteNumber(input.body_size, 0))),
    finding_count: Math.max(0, Math.trunc(finiteNumber(input.finding_count, 0))),
    finding_types: Array.isArray(input.finding_types)
      ? [...new Set(input.finding_types.map(value => safeToken(value, 'UNKNOWN')))].sort()
      : [],
    decision: SAFE_DECISIONS.has(input.decision) ? input.decision : 'block',
    reason: safeToken(input.reason, 'INTERNAL_ERROR'),
    scan_latency_ms: finiteNumber(input.scan_latency_ms),
    upstream_status: Number.isInteger(input.upstream_status) ? input.upstream_status : null,
  }

  for (const key of Object.keys(record)) {
    if (!ALLOWED_FIELDS.has(key)) throw new Error('AUDIT_FIELD_NOT_ALLOWED')
  }
  return record
}

class AuditWriter {
  constructor(filePath) {
    if (typeof filePath !== 'string' || filePath.trim() === '') {
      throw new Error('PG_AUDIT_PATH must be a non-empty file path')
    }
    this.filePath = path.resolve(filePath)
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true })

    // Fail startup if the destination cannot be opened. Nothing written here can
    // contain request content or transport credentials.
    const descriptor = fs.openSync(this.filePath, 'a', 0o600)
    fs.closeSync(descriptor)
  }

  write(input) {
    const record = normalizeRecord(input)
    fs.appendFileSync(this.filePath, `${JSON.stringify(record)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    })
    return record
  }
}

function createSessionHasher() {
  const key = crypto.randomBytes(32)
  return value => {
    if (typeof value !== 'string' || value.length === 0) return null
    return crypto.createHmac('sha256', key).update(value, 'utf8').digest('hex')
  }
}

module.exports = {
  ALLOWED_FIELDS,
  AuditWriter,
  createSessionHasher,
  normalizeRecord,
}
