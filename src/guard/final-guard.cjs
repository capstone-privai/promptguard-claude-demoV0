#!/usr/bin/env node
'use strict'

const crypto = require('node:crypto')
const http = require('node:http')
const { TextDecoder } = require('node:util')

const { AuditWriter, createSessionHasher } = require('../audit/writer.cjs')
const {
  CleanScanCache,
  DetectorClient,
  GuardError,
  collectStringLeaves,
  forwardRequestHeaders,
  forwardResponseHeaders,
  loadConfig,
  providerUrl,
  requestModule,
  scanLeaves,
} = require('./lib.cjs')

const SERVICE = 'promptguard-final-guard'
const VERSION = '1.0.0'
const ALLOWED_ENDPOINTS = new Set(['/v1/messages', '/v1/messages/count_tokens'])
const SESSION_HEADERS = ['x-promptguard-session-id', 'x-claude-session-id', 'x-session-id']

const ERROR_MESSAGES = Object.freeze({
  BODY_TOO_LARGE: 'Request body exceeds the configured PromptGuard limit.',
  BODY_TIMEOUT: 'PromptGuard timed out while receiving the request body.',
  CLIENT_ABORTED: 'The client closed the request before verification completed.',
  DETECTOR_FINDINGS: 'PromptGuard blocked sensitive content before transmission.',
  DETECTOR_HTTP_ERROR: 'PromptGuard verification is temporarily unavailable.',
  DETECTOR_MALFORMED_RESULT: 'PromptGuard could not verify this request safely.',
  DETECTOR_TIMEOUT: 'PromptGuard verification timed out.',
  DETECTOR_UNAVAILABLE: 'PromptGuard verification is temporarily unavailable.',
  INTERNAL_ERROR: 'PromptGuard could not verify this request safely.',
  INVALID_CONTENT_LENGTH: 'The request Content-Length is invalid.',
  MALFORMED_JSON: 'PromptGuard requires a valid JSON request body.',
  METHOD_NOT_ALLOWED: 'This provider endpoint only accepts POST requests.',
  TOO_MANY_STRING_LEAVES: 'The request contains too many independently verifiable fields.',
  UNKNOWN_ENDPOINT: 'PromptGuard does not allow this provider endpoint.',
  UNSUPPORTED_CONTENT_ENCODING: 'PromptGuard does not accept encoded request bodies.',
  UNSUPPORTED_CONTENT_TYPE: 'PromptGuard only accepts application/json provider requests.',
  UPSTREAM_ERROR: 'The upstream provider is temporarily unavailable.',
  UPSTREAM_TIMEOUT: 'The upstream provider timed out.',
})

function errorMessage(code) {
  return ERROR_MESSAGES[code] || ERROR_MESSAGES.INTERNAL_ERROR
}

function sendJson(response, statusCode, value, extraHeaders = {}) {
  if (response.headersSent || response.destroyed) return
  const encoded = Buffer.from(JSON.stringify(value), 'utf8')
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(encoded.length),
    'cache-control': 'no-store',
    ...extraHeaders,
  })
  response.end(encoded)
}

function sendGuardError(response, requestId, error) {
  const code = error instanceof GuardError ? error.code : 'INTERNAL_ERROR'
  const statusCode = error instanceof GuardError ? error.statusCode : 500
  sendJson(response, statusCode, {
    type: 'error',
    error: {
      type: 'promptguard_block',
      code,
      message: errorMessage(code),
      request_id: requestId,
    },
  }, { 'x-promptguard-request-id': requestId })
}

function sendProxyError(response, requestId, code, statusCode) {
  sendJson(response, statusCode, {
    type: 'error',
    error: {
      type: 'promptguard_proxy_error',
      code,
      message: errorMessage(code),
      request_id: requestId,
    },
  }, { 'x-promptguard-request-id': requestId })
}

function contentLength(headers) {
  const value = headers['content-length']
  if (value === undefined) return null
  if (Array.isArray(value) || !/^\d+$/.test(value)) throw new GuardError('INVALID_CONTENT_LENGTH', 400)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed)) throw new GuardError('INVALID_CONTENT_LENGTH', 400)
  return parsed
}

function validateBodyHeaders(request, maxBodyBytes) {
  const length = contentLength(request.headers)
  if (length !== null && length > maxBodyBytes) throw new GuardError('BODY_TOO_LARGE', 413)

  const mediaType = String(request.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase()
  if (mediaType !== 'application/json') throw new GuardError('UNSUPPORTED_CONTENT_TYPE', 415)

  const encoding = String(request.headers['content-encoding'] || 'identity').trim().toLowerCase()
  if (encoding !== 'identity') throw new GuardError('UNSUPPORTED_CONTENT_ENCODING', 415)
}

function readBoundedBody(request, maxBytes, timeoutMs) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    let complete = false

    const cleanup = () => {
      clearTimeout(timer)
      request.removeListener('data', onData)
      request.removeListener('end', onEnd)
      request.removeListener('aborted', onAborted)
      request.removeListener('error', onError)
    }
    const fail = error => {
      if (complete) return
      complete = true
      chunks.length = 0
      cleanup()
      request.resume()
      reject(error)
    }
    const onData = chunk => {
      size += chunk.length
      if (size > maxBytes) {
        fail(new GuardError('BODY_TOO_LARGE', 413))
        return
      }
      chunks.push(chunk)
    }
    const onEnd = () => {
      if (complete) return
      complete = true
      cleanup()
      resolve({ body: Buffer.concat(chunks, size), size })
    }
    const onAborted = () => fail(new GuardError('CLIENT_ABORTED', 400))
    const onError = () => fail(new GuardError('CLIENT_ABORTED', 400))
    const timer = setTimeout(() => fail(new GuardError('BODY_TIMEOUT', 408)), timeoutMs)
    timer.unref?.()

    request.on('data', onData)
    request.once('end', onEnd)
    request.once('aborted', onAborted)
    request.once('error', onError)
  })
}

function decodeJson(body) {
  if (body.length === 0) throw new GuardError('MALFORMED_JSON', 400)
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body)
  } catch {
    throw new GuardError('MALFORMED_JSON', 400)
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new GuardError('MALFORMED_JSON', 400)
  }
}

function sessionHeader(headers) {
  for (const name of SESSION_HEADERS) {
    const value = headers[name]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return null
}

class FinalGuard {
  constructor(config) {
    this.config = config
    this.audit = new AuditWriter(config.auditPath)
    this.detector = new DetectorClient(config.detectorBaseUrl, config.detectorTimeoutMs)
    this.scanCache = new CleanScanCache()
    this.hashSession = createSessionHasher()
    this.startedAt = Date.now()
    this.shuttingDown = false
    this.activeUpstreams = new Set()
    this.stats = {
      requests: 0,
      allowed: 0,
      blocked: 0,
      detectorErrors: 0,
      findings: 0,
      upstreamErrors: 0,
      active: 0,
    }
    this.server = http.createServer((request, response) => {
      this.handle(request, response).catch(() => {
        const requestId = crypto.randomUUID()
        this.stats.blocked += 1
        sendGuardError(response, requestId, new GuardError('INTERNAL_ERROR', 500))
      })
    })
    this.server.requestTimeout = config.bodyTimeoutMs + 5_000
    this.server.headersTimeout = Math.max(10_000, config.bodyTimeoutMs)
    this.server.keepAliveTimeout = 5_000
    this.server.maxRequestsPerSocket = 1_000
    this.server.on('clientError', (_error, socket) => {
      if (socket.writable) {
        socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
      }
    })
  }

  safeAudit(record) {
    try {
      this.audit.write(record)
      return true
    } catch {
      // The message is fixed and contains no request/body/header data.
      process.stderr.write(`[PromptGuard] AUDIT_WRITE_FAILED request=${record.request_id}\n`)
      return false
    }
  }

  block(response, context, error) {
    this.stats.blocked += 1
    if (String(error.code || '').startsWith('DETECTOR_') && error.code !== 'DETECTOR_FINDINGS') {
      this.stats.detectorErrors += 1
    }
    this.safeAudit({
      request_id: context.requestId,
      session_hash: context.sessionHash,
      endpoint: context.endpoint,
      body_size: context.bodySize,
      finding_count: context.findingCount,
      finding_types: context.findingTypes,
      decision: 'block',
      reason: error instanceof GuardError ? error.code : 'INTERNAL_ERROR',
      scan_latency_ms: context.scanLatencyMs,
      upstream_status: null,
    })
    sendGuardError(response, context.requestId, error)
  }

  async readiness() {
    if (this.shuttingDown) return false
    return this.detector.health()
  }

  async handleLocal(pathname, response) {
    if (pathname === '/health') {
      sendJson(response, this.shuttingDown ? 503 : 200, {
        ok: !this.shuttingDown,
        service: SERVICE,
        version: VERSION,
        status: this.shuttingDown ? 'stopping' : 'alive',
      })
      return
    }

    const ready = await this.readiness()
    if (pathname === '/ready') {
      sendJson(response, ready ? 200 : 503, {
        ok: ready,
        ready,
        service: SERVICE,
        detector: ready ? 'ready' : 'unavailable',
        reason: ready ? null : 'DETECTOR_UNAVAILABLE',
      })
      return
    }

    sendJson(response, 200, {
      ok: true,
      ready,
      service: SERVICE,
      version: VERSION,
      uptime_seconds: Math.floor((Date.now() - this.startedAt) / 1000),
      rss_bytes: process.memoryUsage().rss,
      requests: this.stats.requests,
      allowed: this.stats.allowed,
      blocked: this.stats.blocked,
      detector_errors: this.stats.detectorErrors,
      findings: this.stats.findings,
      upstream_errors: this.stats.upstreamErrors,
      active_requests: this.stats.active,
      max_body_bytes: this.config.maxBodyBytes,
      allowed_endpoints: [...ALLOWED_ENDPOINTS],
    })
  }

  async handle(request, response) {
    const parsed = new URL(request.url || '/', 'http://promptguard.invalid')
    const pathname = parsed.pathname

    if (request.method === 'GET' && ['/health', '/ready', '/status'].includes(pathname)) {
      await this.handleLocal(pathname, response)
      return
    }

    const requestId = crypto.randomUUID()
    const knownEndpoint = ALLOWED_ENDPOINTS.has(pathname)
    const incomingSession = sessionHeader(request.headers)
    const context = {
      requestId,
      sessionHash: this.config.sessionHash || (incomingSession ? this.hashSession(incomingSession) : null),
      endpoint: knownEndpoint ? pathname : 'UNKNOWN',
      bodySize: 0,
      findingCount: 0,
      findingTypes: [],
      scanLatencyMs: null,
    }
    this.stats.requests += 1

    if (!knownEndpoint) {
      request.resume()
      this.block(response, context, new GuardError('UNKNOWN_ENDPOINT', 404))
      return
    }
    if (request.method !== 'POST') {
      request.resume()
      this.block(response, context, new GuardError('METHOD_NOT_ALLOWED', 405))
      return
    }
    if (this.shuttingDown) {
      request.resume()
      this.block(response, context, new GuardError('INTERNAL_ERROR', 503))
      return
    }

    try {
      validateBodyHeaders(request, this.config.maxBodyBytes)
      const declaredLength = contentLength(request.headers)
      if (declaredLength !== null) context.bodySize = declaredLength
      const read = await readBoundedBody(request, this.config.maxBodyBytes, this.config.bodyTimeoutMs)
      context.bodySize = read.size
      const value = decodeJson(read.body)
      const items = collectStringLeaves(value)
      const scanStarted = process.hrtime.bigint()
      let scan
      try {
        scan = await scanLeaves(this.detector, this.scanCache, items, context.requestId)
      } finally {
        context.scanLatencyMs = Number(process.hrtime.bigint() - scanStarted) / 1_000_000
      }
      context.findingCount = scan.findingCount
      context.findingTypes = scan.findingTypes
      this.stats.findings += scan.findingCount
      if (scan.findingCount > 0) throw new GuardError('DETECTOR_FINDINGS', 422)
      await this.proxy(request, response, read.body, context)
    } catch (error) {
      if (response.headersSent || response.destroyed) return
      const safeError = error instanceof GuardError ? error : new GuardError('INTERNAL_ERROR', 500)
      this.block(response, context, safeError)
    }
  }

  proxy(clientRequest, clientResponse, body, context) {
    return new Promise(resolve => {
      const target = providerUrl(this.config.upstreamBaseUrl, clientRequest.url || context.endpoint)
      const headers = forwardRequestHeaders(clientRequest.headers, body.length, context.requestId)
      let upstreamResponse = null
      let finalized = false
      let clientClosed = false
      let timedOut = false

      this.stats.active += 1
      const upstreamRequest = requestModule(target).request(target, {
        method: 'POST',
        headers,
        agent: false,
      })
      this.activeUpstreams.add(upstreamRequest)

      const finalize = (reason, upstreamStatus = null) => {
        if (finalized) return
        finalized = true
        this.activeUpstreams.delete(upstreamRequest)
        this.stats.active = Math.max(0, this.stats.active - 1)
        this.stats.allowed += 1
        this.safeAudit({
          request_id: context.requestId,
          session_hash: context.sessionHash,
          endpoint: context.endpoint,
          body_size: context.bodySize,
          finding_count: context.findingCount,
          finding_types: context.findingTypes,
          decision: 'allow',
          reason,
          scan_latency_ms: context.scanLatencyMs,
          upstream_status: upstreamStatus,
        })
        resolve()
      }

      clientResponse.once('close', () => {
        if (clientResponse.writableEnded || finalized) return
        clientClosed = true
        upstreamResponse?.destroy()
        upstreamRequest.destroy()
        finalize('CLIENT_DISCONNECT', upstreamResponse?.statusCode || null)
      })

      upstreamRequest.setTimeout(this.config.upstreamTimeoutMs, () => {
        timedOut = true
        upstreamRequest.destroy(new Error('UPSTREAM_TIMEOUT'))
      })

      upstreamRequest.once('response', response => {
        upstreamResponse = response
        const statusCode = response.statusCode || 502
        if (!clientResponse.headersSent && !clientResponse.destroyed) {
          clientResponse.writeHead(statusCode, {
            ...forwardResponseHeaders(response.headers),
            'x-promptguard-request-id': context.requestId,
          })
          response.pipe(clientResponse)
        } else {
          response.destroy()
        }
        response.once('end', () => finalize('FORWARDED', statusCode))
        response.once('aborted', () => {
          this.stats.upstreamErrors += 1
          if (!clientResponse.destroyed) clientResponse.destroy()
          finalize('UPSTREAM_EARLY_CLOSE', statusCode)
        })
        response.once('error', () => {
          this.stats.upstreamErrors += 1
          if (!clientResponse.destroyed) clientResponse.destroy()
          finalize('UPSTREAM_ERROR', statusCode)
        })
      })

      upstreamRequest.once('error', () => {
        if (clientClosed) return
        this.stats.upstreamErrors += 1
        const code = timedOut ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR'
        if (!clientResponse.headersSent && !clientResponse.destroyed) {
          sendProxyError(clientResponse, context.requestId, code, timedOut ? 504 : 502)
        } else if (!clientResponse.destroyed) {
          clientResponse.destroy()
        }
        finalize(code, upstreamResponse?.statusCode || null)
      })

      upstreamRequest.end(body)
    })
  }

  listen() {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject)
      this.server.listen(this.config.port, this.config.host, () => {
        this.server.removeListener('error', reject)
        resolve(this.server.address())
      })
    })
  }

  async close() {
    if (this.shuttingDown) return
    this.shuttingDown = true
    await new Promise(resolve => {
      const timer = setTimeout(() => {
        for (const request of this.activeUpstreams) request.destroy()
        this.server.closeAllConnections?.()
        resolve()
      }, 2_000)
      timer.unref?.()
      this.server.close(() => {
        clearTimeout(timer)
        resolve()
      })
    })
  }
}

async function main() {
  let config
  try {
    config = loadConfig()
  } catch (error) {
    process.stderr.write(`[PromptGuard] CONFIG_ERROR ${error.message}\n`)
    process.exitCode = 1
    return
  }

  let guard
  try {
    guard = new FinalGuard(config)
    const address = await guard.listen()
    const port = typeof address === 'object' && address ? address.port : config.port
    process.stdout.write(`READY ${port}\n`)
  } catch {
    process.stderr.write('[PromptGuard] STARTUP_ERROR\n')
    process.exitCode = 1
    return
  }

  let stopping = false
  const stop = async () => {
    if (stopping) return
    stopping = true
    await guard.close()
  }
  process.once('SIGTERM', stop)
  process.once('SIGINT', stop)
}

if (require.main === module) {
  main().catch(() => {
    process.stderr.write('[PromptGuard] FATAL_ERROR\n')
    process.exitCode = 1
  })
}

module.exports = { FinalGuard }
