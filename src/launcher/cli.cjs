#!/usr/bin/env node
'use strict'

const path = require('path')
const { loadConfig, resolvePython } = require('../supervisor/config.cjs')
const { getJson } = require('../supervisor/http.cjs')
const { RuntimeSupervisor } = require('../supervisor/runtime.cjs')
const { detectorEnvironment } = require('./detector-options.cjs')
const { pidIsAlive, readState, sanitizeGuardStatus } = require('../supervisor/state.cjs')

function usage() {
  console.log(`PromptGuard Runtime V1

Usage:
  promptguard run [--config FILE] [--runtime-dir DIR] [--no-claude]
                  [--enable NAMES] [--disable NAMES] [--policy union|majority]
                  [--detector-timeout-ms N] [--readiness-timeout-ms N] [-- CLAUDE_ARGS...]
  promptguard status [--config FILE] [--runtime-dir DIR] [--json]
  promptguard version

Commands:
  run       Start two independent detectors, Final Guard, then Claude Code.
  status    Show raw-free runtime health and Guard counters.

Options:
  --no-claude    Start and supervise the protection services without Claude login.
  --config       Use a specific strict PromptGuard JSON config.
  --runtime-dir  Store runtime metadata in a specific directory.
  --json         Emit machine-readable status output.

Detector options (run):
  --enable NAMES             Turn detectors on, comma-separated (e.g. ml-v9,ml-qwen).
  --disable NAMES            Turn detectors off; wins over --enable.
  --policy union|majority    union: any detector's span is masked (default in detector.json).
                             majority: the original vote of the non-candidate-only detectors.
  --detector-timeout-ms N    How long Native Mod and Final Guard wait for a scan.
  --readiness-timeout-ms N   How long startup waits for the detector workers.
  Names: credsweeper, gitleaks, promptguard-rules, shell-aware, ml-v9, ml-qwen.
  With ml-v9 or ml-qwen on, readiness defaults to 180000 ms; with ml-qwen on,
  the detector timeout defaults to 30000 ms. Same as PG_DETECTOR_ENABLE/DISABLE.

Examples:
  promptguard run --enable ml-v9
  promptguard run --enable ml-qwen --disable shell-aware
  promptguard run --policy majority
`)
}

function requireValue(args, index, option) {
  const value = args[index + 1]
  if (!value || value === '--') throw new Error(`${option} requires a value.`)
  return value
}

function parseRun(args) {
  const options = { noClaude: false, configPath: null, runtimeDirectory: null, claudeArgs: [], detector: {} }
  for (let index = 0; index < args.length; index += 1) {
    const item = args[index]
    if (item === '--') {
      options.claudeArgs = args.slice(index + 1)
      break
    }
    if (item === '--no-claude') options.noClaude = true
    else if (item === '--config') options.configPath = requireValue(args, index++, item)
    else if (item === '--runtime-dir') options.runtimeDirectory = requireValue(args, index++, item)
    else if (item === '--enable') options.detector.enable = requireValue(args, index++, item)
    else if (item === '--disable') options.detector.disable = requireValue(args, index++, item)
    else if (item === '--policy') options.detector.policy = requireValue(args, index++, item)
    else if (item === '--detector-timeout-ms') options.detector.detectorTimeoutMs = requireValue(args, index++, item)
    else if (item === '--readiness-timeout-ms') options.detector.readinessTimeoutMs = requireValue(args, index++, item)
    else if (item === '--help' || item === '-h') options.help = true
    else throw new Error(`An unknown run option was provided (${String(item).slice(0, 40)}). See promptguard --help.`)
  }
  return options
}

function parseStatus(args) {
  const options = { configPath: null, runtimeDirectory: null, json: false }
  for (let index = 0; index < args.length; index += 1) {
    const item = args[index]
    if (item === '--config') options.configPath = requireValue(args, index++, item)
    else if (item === '--runtime-dir') options.runtimeDirectory = requireValue(args, index++, item)
    else if (item === '--json') options.json = true
    else if (item === '--help' || item === '-h') options.help = true
    else throw new Error('An unknown status option was provided.')
  }
  return options
}

function conciseError(error) {
  return String(error?.message || error || 'Unknown error').replace(/[\r\n]+/g, ' ').slice(0, 400)
}

function runtimeDirectory(config, selected) {
  return path.resolve(selected || process.env.PG_RUNTIME_DIR || path.join(config.projectRoot, '.promptguard'))
}

async function runCommand(args) {
  const options = parseRun(args)
  if (options.help) {
    usage()
    return 0
  }

  let supervisor
  const signalHandlers = new Map()
  try {
    // Detector options become PG_* variables before the config is read, so the
    // supervisor and both detector workers see the same selection.
    const selection = detectorEnvironment(options.detector)
    Object.assign(process.env, selection.env)
    console.error(selection.summary)
    const config = loadConfig(options.configPath)
    const python = resolvePython(config)
    supervisor = new RuntimeSupervisor(config, python, {
      noClaude: options.noClaude,
      claudeArgs: options.claudeArgs,
      runtimeDirectory: options.runtimeDirectory,
    })

    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
      const handler = () => { void supervisor.shutdown(signal, 0) }
      signalHandlers.set(signal, handler)
      process.on(signal, handler)
    }

    await supervisor.start()
    const result = await supervisor.wait()
    return result.exitCode
  } catch (error) {
    if (supervisor) await supervisor.shutdown('startup_failure', 1)
    console.error('PromptGuard runtime not ready.')
    console.error('Claude Code was not started.')
    console.error(`Reason: ${conciseError(error)}`)
    return 1
  } finally {
    for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler)
  }
}

function flattenCounters(value, prefix = '', output = []) {
  if (!value || typeof value !== 'object') return output
  for (const [key, item] of Object.entries(value)) {
    const name = prefix ? `${prefix}.${key}` : key
    if (typeof item === 'number' || typeof item === 'boolean') output.push([name, item])
    else flattenCounters(item, name, output)
  }
  return output
}

async function statusCommand(args) {
  const options = parseStatus(args)
  if (options.help) {
    usage()
    return 0
  }
  const config = loadConfig(options.configPath)
  const statePath = path.join(runtimeDirectory(config, options.runtimeDirectory), 'runtime-state.json')
  const saved = readState(statePath)
  const processAlive = saved ? pidIsAlive(saved.pid) : false
  let guardStatus = null
  if (processAlive) {
    try {
      const savedGuardUrl = typeof saved?.guard?.url === 'string' && /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d+$/.test(saved.guard.url)
        ? saved.guard.url
        : config.guardUrl
      const response = await getJson(`${savedGuardUrl}/status`, Math.min(1500, config.detectorTimeoutMs))
      if (response.statusCode === 200) guardStatus = sanitizeGuardStatus(response.value)
    } catch { }
  }

  const result = {
    schemaVersion: 1,
    running: processAlive,
    stale: Boolean(saved && !processAlive && ['starting', 'running', 'degraded', 'recovering'].includes(saved.status)),
    runtime: saved ? {
      status: processAlive ? saved.status : 'stopped',
      pid: processAlive ? saved.pid : null,
      startedAt: saved.startedAt || null,
      uptimeMs: processAlive && saved.startedAt ? Math.max(0, Date.now() - Date.parse(saved.startedAt)) : (saved.uptimeMs || 0),
      services: saved.services || {},
      claude: saved.claude || null,
      protection: saved.protection || null,
    } : null,
    guard: guardStatus,
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2))
    return 0
  }

  console.log('PromptGuard Runtime Status')
  if (!saved) {
    console.log('Runtime: NOT STARTED')
    return 0
  }
  console.log(`Runtime: ${result.running ? String(saved.status || 'unknown').toUpperCase() : 'STOPPED'}`)
  console.log(`PID: ${result.runtime.pid || '-'}`)
  console.log(`Uptime: ${Math.round(result.runtime.uptimeMs / 1000)}s`)
  for (const [name, label] of [
    ['transformDetector', 'Transform detector'],
    ['verificationDetector', 'Verification detector'],
    ['finalGuard', 'Final Guard'],
  ]) {
    const service = result.runtime.services[name]
    console.log(`${label}: ${String(service?.status || 'unknown').toUpperCase()} (restarts: ${service?.restarts || 0})`)
    if (service?.metrics && typeof service.metrics.scan_count === 'number') {
      console.log(`  scans: ${service.metrics.scan_count}, errors: ${service.metrics.error_count || 0}, last latency: ${service.metrics.last_latency_ms || 0}ms`)
    }
  }
  if (result.runtime.claude) {
    const current = result.runtime.claude.currentVersion || 'not checked'
    console.log(`Claude Code: ${String(result.runtime.claude.status || 'unknown').toUpperCase()} (${current})`)
  }
  console.log(`Guard readiness: ${guardStatus?.ready === true ? 'READY' : 'NOT READY'}`)
  const counters = flattenCounters(guardStatus?.counters)
  if (counters.length) {
    console.log('Guard counters:')
    for (const [name, value] of counters) console.log(`  ${name}: ${value}`)
  }
  if (result.stale) console.log('Note: stale runtime metadata was found; no live supervisor process exists.')
  return 0
}

async function main(argv) {
  const [command, ...args] = argv
  if (!command || command === '--help' || command === '-h' || command === 'help') {
    usage()
    return 0
  }
  if (command === 'version' || command === '--version' || command === '-v') {
    console.log('PromptGuard Runtime 1.0.0')
    return 0
  }
  if (command === 'run') return runCommand(args)
  if (command === 'status') return statusCommand(args)
  throw new Error('An unknown PromptGuard command was provided.')
}

main(process.argv.slice(2)).then(code => {
  process.exitCode = code
}).catch(error => {
  console.error(`PromptGuard command failed: ${conciseError(error)}`)
  process.exitCode = 1
})
