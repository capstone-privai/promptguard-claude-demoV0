#!/usr/bin/env node
'use strict'
// Minimal stdio MCP server for tests/e2e/contexts.mjs: no tools, and server instructions from PG_PROBE_MCP_INSTRUCTIONS.
const readline = require('node:readline')

const send = message => process.stdout.write(`${JSON.stringify(message)}\n`)
readline.createInterface({ input: process.stdin }).on('line', line => {
  let request
  try { request = JSON.parse(line) } catch { return }
  if (request.id === undefined) return
  if (request.method === 'initialize') {
    send({ jsonrpc: '2.0', id: request.id, result: {
      protocolVersion: request.params?.protocolVersion || '2025-06-18',
      capabilities: { tools: {} },
      serverInfo: { name: 'probe-instructions', version: '1.0.0' },
      instructions: process.env.PG_PROBE_MCP_INSTRUCTIONS || '',
    } })
  } else if (request.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: request.id, result: { tools: [] } })
  } else if (request.method === 'ping') {
    send({ jsonrpc: '2.0', id: request.id, result: {} })
  } else {
    send({ jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'method not found' } })
  }
})
