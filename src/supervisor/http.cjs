'use strict'

const http = require('http')
const https = require('https')

function getJson(urlValue, timeoutMs = 1000) {
  return new Promise((resolve, reject) => {
    let url
    try {
      url = new URL(urlValue)
    } catch {
      reject(new Error('INVALID_URL'))
      return
    }
    const client = url.protocol === 'https:' ? https : http
    const request = client.request(url, {
      method: 'GET',
      headers: { accept: 'application/json', connection: 'close' },
      timeout: timeoutMs,
    }, response => {
      const chunks = []
      let size = 0
      response.on('data', chunk => {
        size += chunk.length
        if (size > 1024 * 1024) request.destroy(new Error('RESPONSE_TOO_LARGE'))
        else chunks.push(chunk)
      })
      response.on('end', () => {
        let value
        try {
          value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        } catch {
          reject(new Error('MALFORMED_JSON'))
          return
        }
        resolve({ statusCode: response.statusCode || 0, value })
      })
    })
    request.once('timeout', () => request.destroy(new Error('TIMEOUT')))
    request.once('error', reject)
    request.end()
  })
}

async function waitForJson(url, predicate, options = {}) {
  const timeoutMs = options.timeoutMs || 30000
  const intervalMs = options.intervalMs || 100
  const requestTimeoutMs = options.requestTimeoutMs || Math.min(1000, timeoutMs)
  const isAlive = options.isAlive || (() => true)
  const deadline = Date.now() + timeoutMs
  let lastReason = 'NOT_READY'

  while (Date.now() < deadline) {
    if (!isAlive()) throw new Error('PROCESS_EXITED')
    try {
      const response = await getJson(url, requestTimeoutMs)
      if (predicate(response)) return response.value
      lastReason = `HTTP_${response.statusCode}`
    } catch (error) {
      lastReason = error.message || 'HEALTH_ERROR'
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs))
  }
  throw new Error(`READINESS_TIMEOUT:${lastReason}`)
}

module.exports = { getJson, waitForJson }
