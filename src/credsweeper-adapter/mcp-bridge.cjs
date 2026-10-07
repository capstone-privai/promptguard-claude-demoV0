const http = require('http')
const readline = require('readline')

const detectorUrl = new URL(process.env.PG_DETECTOR_URL || 'http://127.0.0.1:18771')
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })

function send(value) {
  process.stdout.write(JSON.stringify(value) + '\n')
}

function scanBatch(items) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify({ items }), 'utf8')
    const request = http.request({
      hostname: detectorUrl.hostname,
      port: detectorUrl.port,
      path: '/scan-batch',
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': body.length },
      timeout: 5000,
    }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.on('end', () => {
        if (response.statusCode !== 200) return reject(new Error(`detector HTTP ${response.statusCode}`))
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))) }
        catch { reject(new Error('detector malformed JSON')) }
      })
    })
    request.on('timeout', () => request.destroy(new Error('detector timeout')))
    request.on('error', reject)
    request.end(body)
  })
}

rl.on('line', async line => {
  let message
  try { message = JSON.parse(line) } catch { return }
  if (message.method === 'initialize') {
    send({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'pgdetector', version: '0.1.0' } } })
    return
  }
  if (message.method === 'notifications/initialized') return
  if (message.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: message.id, result: { tools: [{
      name: 'scan_batch',
      description: 'PromptGuard internal local detector transport. Do not call directly.',
      inputSchema: {
        type: 'object',
        properties: { items: { type: 'array', items: { type: 'object' } } },
        required: ['items'],
        additionalProperties: false,
      },
    }] } })
    return
  }
  if (message.method !== 'tools/call') return
  if (message.params?.name !== 'scan_batch') {
    send({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } })
    return
  }
  try {
    const items = message.params?.arguments?.items
    if (!Array.isArray(items)) throw new Error('invalid items')
    const value = await scanBatch(items)
    send({ jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: JSON.stringify(value) }], isError: false } })
  } catch {
    send({ jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: 'DETECTOR_FAILURE' }], isError: true } })
  }
})
