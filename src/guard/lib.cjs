'use strict'

const http = require('node:http')
const https = require('node:https')
const crypto = require('node:crypto')
const path = require('node:path')

const DEFAULT_MAX_BODY = 8 * 1024 * 1024
const DEFAULT_DETECTOR_TIMEOUT = 5_000
const DEFAULT_UPSTREAM_TIMEOUT = 120_000
const DEFAULT_BODY_TIMEOUT = 15_000
// Bounds the JSON walk only; the detector sees at most DETECTOR_BATCH_SIZE uncached leaves per call.
const MAX_STRING_LEAVES = 65_536
// Each batch has its own detector timeout, so a cold request that needs many batches can finish,
// and the batches that did finish stay cached for the client's retry. Well under the worker's 4096.
const DETECTOR_BATCH_SIZE = 256
const SCAN_CACHE_LIMIT = 100_000
const DETECTOR_RESPONSE_LIMIT = 8 * 1024 * 1024
const SAFE_FINDING_TYPE = /^[A-Z][A-Z0-9_]{0,63}$/

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

class GuardError extends Error {
  constructor(code, statusCode = 422) {
    super(code)
    this.name = 'GuardError'
    this.code = code
    this.statusCode = statusCode
  }
}
function parseInteger(name, raw, fallback, minimum, maximum) {
  if (raw === undefined || raw === '') return fallback
  if (!/^\d+$/.test(String(raw))) throw new Error(`${name} must be an integer`)
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`)
  }
  return value
}

function parseHttpUrl(name, value, { loopbackOnly = false } = {}) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${name} is required`)
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    throw new Error(`${name} must be an absolute http(s) URL`)
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`${name} must use http or https`)
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(`${name} must not contain credentials, query, or fragment`)
  }
  if (loopbackOnly) {
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
    if (!['127.0.0.1', 'localhost', '::1'].includes(hostname)) {
      throw new Error(`${name} must point to a loopback detector`)
    }
  }
  return parsed
}

function parseLoopbackHost(value) {
  const host = String(value || '127.0.0.1').trim().toLowerCase().replace(/^\[|\]$/g, '')
  if (!['127.0.0.1', 'localhost', '::1'].includes(host)) {
    throw new Error('PG_GUARD_HOST must be a loopback address')
  }
  return host
}

function parseSessionHash(value) {
  if (typeof value !== 'string' || value.length === 0) return null
  if (/^[a-fA-F0-9]{32,128}$/.test(value)) return value.toLowerCase()
  // A manually supplied non-hex identifier is never persisted verbatim.
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex')
}

function loadConfig(env = process.env) {
  const detectorValue = env.PG_GUARD_DETECTOR_URL || env.PG_DETECTOR_URL
  const auditDefault = path.join(process.cwd(), '.runtime', 'audit', 'guard.jsonl')
  return Object.freeze({
    host: parseLoopbackHost(env.PG_GUARD_HOST),
    port: parseInteger('PG_GUARD_PORT', env.PG_GUARD_PORT, 18191, 0, 65535),
    upstreamBaseUrl: parseHttpUrl('PG_UPSTREAM_BASE_URL', env.PG_UPSTREAM_BASE_URL),
    detectorBaseUrl: parseHttpUrl('PG_GUARD_DETECTOR_URL', detectorValue, { loopbackOnly: true }),
    detectorTimeoutMs: parseInteger(
      'PG_DETECTOR_TIMEOUT_MS',
      env.PG_DETECTOR_TIMEOUT_MS,
      DEFAULT_DETECTOR_TIMEOUT,
      10,
      120_000,
    ),
    upstreamTimeoutMs: parseInteger(
      'PG_UPSTREAM_TIMEOUT_MS',
      env.PG_UPSTREAM_TIMEOUT_MS,
      DEFAULT_UPSTREAM_TIMEOUT,
      100,
      600_000,
    ),
    bodyTimeoutMs: parseInteger(
      'PG_REQUEST_BODY_TIMEOUT_MS',
      env.PG_REQUEST_BODY_TIMEOUT_MS,
      DEFAULT_BODY_TIMEOUT,
      100,
      120_000,
    ),
    maxBodyBytes: parseInteger(
      'PG_GUARD_MAX_BODY',
      env.PG_GUARD_MAX_BODY || env.PG_MAX_BODY_BYTES,
      DEFAULT_MAX_BODY,
      1024,
      64 * 1024 * 1024,
    ),
    auditPath: env.PG_AUDIT_PATH || auditDefault,
    sessionHash: parseSessionHash(env.PG_SESSION_HASH),
  })
}

function collectStringLeaves(value) {
  const output = []
  const stack = [value]
  while (stack.length > 0) {
    const item = stack.pop()
    if (typeof item === 'string') {
      if (output.length >= MAX_STRING_LEAVES) throw new GuardError('TOO_MANY_STRING_LEAVES', 422)
      output.push({ id: output.length, text: item, source: 'outbound' })
      continue
    }
    if (Array.isArray(item)) {
      for (let index = item.length - 1; index >= 0; index -= 1) stack.push(item[index])
      continue
    }
    if (item && typeof item === 'object') {
      const values = Object.values(item)
      for (let index = values.length - 1; index >= 0; index -= 1) stack.push(values[index])
    }
  }
  return output
}

function utf16Length(value) {
  return value.length
}

function validateFinding(finding, sourceText) {
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) return false
  if (!SAFE_FINDING_TYPE.test(finding.type || '')) return false
  if (!Number.isInteger(finding.start) || !Number.isInteger(finding.end)) return false
  if (finding.start < 0 || finding.end <= finding.start || finding.end > utf16Length(sourceText)) return false
  if (finding.offset_unit !== 'utf16_code_units') return false
  if (typeof finding.value_hash !== 'string' || !/^[a-fA-F0-9]{64}$/.test(finding.value_hash)) return false
  if (typeof finding.confidence !== 'string' || finding.confidence.length > 64) return false
  if (typeof finding.rule_id !== 'string' || finding.rule_id.length > 512) return false
  if (typeof finding.source !== 'string' || finding.source.length > 128) return false
  return true
}

function requestModule(url) {
  return url.protocol === 'https:' ? https : http
}

function childUrl(baseUrl, pathname) {
  const output = new URL(baseUrl.href)
  const prefix = output.pathname === '/' ? '' : output.pathname.replace(/\/$/, '')
  output.pathname = `${prefix}${pathname}`
  output.search = ''
  output.hash = ''
  return output
}

function detectorRequest(baseUrl, pathname, options) {
  const target = childUrl(baseUrl, pathname)
  const payload = options.body === undefined ? null : Buffer.from(JSON.stringify(options.body), 'utf8')
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (callback, value) => {
      if (settled) return
      settled = true
      callback(value)
    }
    const request = requestModule(target).request(target, {
      method: options.method,
      headers: payload
        ? { 'content-type': 'application/json', 'content-length': String(payload.length) }
        : { accept: 'application/json' },
      agent: false,
    }, response => {
      const chunks = []
      let size = 0
      response.on('data', chunk => {
        size += chunk.length
        if (size > DETECTOR_RESPONSE_LIMIT) {
          request.destroy(new Error('DETECTOR_RESPONSE_TOO_LARGE'))
          return
        }
        chunks.push(chunk)
      })
      response.on('end', () => {
        if (response.statusCode !== 200) {
          finish(reject, new GuardError('DETECTOR_HTTP_ERROR', 503))
          return
        }
        let decoded
        try {
          decoded = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        } catch {
          finish(reject, new GuardError('DETECTOR_MALFORMED_RESULT', 503))
          return
        }
        finish(resolve, decoded)
      })
      response.on('error', () => finish(reject, new GuardError('DETECTOR_UNAVAILABLE', 503)))
    })
    request.setTimeout(options.timeoutMs, () => {
      request.destroy(new Error('DETECTOR_TIMEOUT'))
      finish(reject, new GuardError('DETECTOR_TIMEOUT', 503))
    })
    request.on('error', error => {
      const code = error && error.message === 'DETECTOR_TIMEOUT'
        ? 'DETECTOR_TIMEOUT'
        : error && error.message === 'DETECTOR_RESPONSE_TOO_LARGE'
          ? 'DETECTOR_MALFORMED_RESULT'
          : 'DETECTOR_UNAVAILABLE'
      finish(reject, new GuardError(code, 503))
    })
    if (payload) request.end(payload)
    else request.end()
  })
}

class DetectorClient {
  constructor(baseUrl, timeoutMs) {
    this.baseUrl = baseUrl
    this.timeoutMs = timeoutMs
  }

  async health() {
    try {
      const result = await detectorRequest(this.baseUrl, '/health', {
        method: 'GET',
        timeoutMs: this.timeoutMs,
      })
      return Boolean(result && result.ok === true)
    } catch {
      return false
    }
  }

  async scan(items, requestId) {
    const started = process.hrtime.bigint()
    let response
    try {
      response = await detectorRequest(this.baseUrl, '/scan-batch', {
        method: 'POST',
        body: { request_id: requestId, items },
        timeoutMs: this.timeoutMs,
      })
    } catch (error) {
      if (error instanceof GuardError) throw error
      throw new GuardError('DETECTOR_UNAVAILABLE', 503)
    }

    if (!response || typeof response !== 'object' || response.ok !== true || !Array.isArray(response.items)) {
      throw new GuardError('DETECTOR_MALFORMED_RESULT', 503)
    }
    if (response.request_id !== requestId) throw new GuardError('DETECTOR_MALFORMED_RESULT', 503)
    if (response.items.length !== items.length) throw new GuardError('DETECTOR_MALFORMED_RESULT', 503)

    const expected = new Map(items.map(item => [item.id, item]))
    const seen = new Set()
    let findingCount = 0
    const findingTypes = new Set()

    for (const result of response.items) {
      if (!result || typeof result !== 'object' || !expected.has(result.id) || seen.has(result.id)) {
        throw new GuardError('DETECTOR_MALFORMED_RESULT', 503)
      }
      seen.add(result.id)
      if (result.ok !== true || !Array.isArray(result.findings) || !Array.isArray(result.errors)) {
        throw new GuardError('DETECTOR_MALFORMED_RESULT', 503)
      }
      if (result.errors.length !== 0 || result.finding_count !== result.findings.length) {
        throw new GuardError('DETECTOR_MALFORMED_RESULT', 503)
      }
      const source = expected.get(result.id).text
      for (const finding of result.findings) {
        if (!validateFinding(finding, source)) throw new GuardError('DETECTOR_MALFORMED_RESULT', 503)
        findingCount += 1
        findingTypes.add(finding.type)
      }
    }

    const elapsedNs = process.hrtime.bigint() - started
    return {
      findingCount,
      findingTypes: [...findingTypes].sort(),
      findingCounts: new Map(response.items.map(result => [result.id, result.findings.length])),
      latencyMs: Number(elapsedNs) / 1_000_000,
    }
  }
}

// Remembers leaves the detector already found clean. The detector scans every leaf on its own and
// deterministically, so a clean verdict for the same text is exact. Keys are HMACs under a
// per-process key: no text, and no hash comparable across processes, is kept. Leaves with a
// finding are never cached, so they are rescanned and blocked on every request.
class CleanScanCache {
  constructor(limit = SCAN_CACHE_LIMIT) {
    this.key = crypto.randomBytes(32)
    this.limit = limit
    this.entries = new Set()
  }

  digest(text) {
    return crypto.createHmac('sha256', this.key).update(text, 'utf8').digest('base64')
  }

  has(digest) {
    if (!this.entries.has(digest)) return false
    this.entries.delete(digest)
    this.entries.add(digest)
    return true
  }

  add(digest) {
    this.entries.delete(digest)
    this.entries.add(digest)
    if (this.entries.size > this.limit) this.entries.delete(this.entries.values().next().value)
  }
}

// Scans only the distinct leaves not already known clean, in bounded batches. Stops at the first
// batch with a finding: the request is blocked either way, so later batches would only add delay.
async function scanLeaves(detector, cache, leaves, requestId) {
  const pending = new Map()
  for (const leaf of leaves) {
    const digest = cache.digest(leaf.text)
    if (pending.has(digest)) pending.get(digest).occurrences += 1
    else if (!cache.has(digest)) pending.set(digest, { text: leaf.text, occurrences: 1 })
  }

  const unique = [...pending]
  const findingTypes = new Set()
  let findingCount = 0
  let latencyMs = 0
  for (let start = 0; start < unique.length && findingCount === 0; start += DETECTOR_BATCH_SIZE) {
    const batch = unique.slice(start, start + DETECTOR_BATCH_SIZE)
    const items = batch.map(([, entry], id) => ({ id, text: entry.text, source: 'outbound' }))
    const result = await detector.scan(items, `${requestId}.${start / DETECTOR_BATCH_SIZE}`)
    latencyMs += result.latencyMs
    for (const type of result.findingTypes) findingTypes.add(type)
    batch.forEach(([digest, entry], id) => {
      const count = result.findingCounts.get(id)
      if (count === 0) cache.add(digest)
      else findingCount += count * entry.occurrences
    })
  }

  return {
    findingCount,
    findingTypes: [...findingTypes].sort(),
    scannedCount: unique.length,
    cachedCount: leaves.length - unique.reduce((total, [, entry]) => total + entry.occurrences, 0),
    latencyMs,
  }
}

function connectionTokens(headers) {
  const value = headers.connection
  if (typeof value !== 'string') return new Set()
  return new Set(value.split(',').map(item => item.trim().toLowerCase()).filter(Boolean))
}

function forwardRequestHeaders(headers, bodyLength, requestId) {
  const output = {}
  const dynamicHopHeaders = connectionTokens(headers)
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase()
    if (lower === 'host' || lower === 'content-length' || HOP_BY_HOP_HEADERS.has(lower) || dynamicHopHeaders.has(lower)) continue
    if (value !== undefined) output[lower] = value
  }
  output['content-length'] = String(bodyLength)
  output['x-promptguard-request-id'] = requestId
  return output
}

function forwardResponseHeaders(headers) {
  const output = {}
  const dynamicHopHeaders = connectionTokens(headers)
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase()
    if (HOP_BY_HOP_HEADERS.has(lower) || dynamicHopHeaders.has(lower)) continue
    if (value !== undefined) output[lower] = value
  }
  return output
}

function providerUrl(baseUrl, requestUrl) {
  const incoming = new URL(requestUrl, 'http://promptguard.invalid')
  const output = new URL(baseUrl.href)
  const prefix = output.pathname === '/' ? '' : output.pathname.replace(/\/$/, '')
  output.pathname = `${prefix}${incoming.pathname}`
  output.search = incoming.search
  output.hash = ''
  return output
}

module.exports = {
  CleanScanCache,
  DETECTOR_BATCH_SIZE,
  DetectorClient,
  GuardError,
  HOP_BY_HOP_HEADERS,
  collectStringLeaves,
  forwardRequestHeaders,
  forwardResponseHeaders,
  loadConfig,
  providerUrl,
  requestModule,
  scanLeaves,
}
