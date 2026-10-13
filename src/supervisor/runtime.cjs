'use strict'

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const { spawn, spawnSync } = require('child_process')
const { ManagedProcess, delay, stopProcessTree } = require('./process.cjs')
const { getJson, waitForJson } = require('./http.cjs')
const { StateStore } = require('./state.cjs')

const LOG_RANK = Object.freeze({ error: 0, warn: 1, info: 2, debug: 3 })
const SENSITIVE_SERVICE_ENV = Object.freeze([
  'ANTHROPIC_API_KEY',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'AZURE_API_KEY',
  'GOOGLE_API_KEY',
  'GOOGLE_APPLICATION_CREDENTIALS',
])
const ALTERNATE_PROVIDER_FLAGS = Object.freeze([
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
  'CLAUDE_CODE_USE_FOUNDRY',
])

function truthy(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase())
}

function safeServiceEnvironment(extra) {
  const environment = { ...process.env }
  for (const name of SENSITIVE_SERVICE_ENV) delete environment[name]
  delete environment.ANTHROPIC_BASE_URL
  delete environment.ANTHROPIC_BEDROCK_BASE_URL
  delete environment.ANTHROPIC_VERTEX_BASE_URL
  Object.assign(environment, extra)
  return environment
}

function addNoProxy(environment) {
  const entries = String(environment.NO_PROXY || environment.no_proxy || '').split(',').map(value => value.trim()).filter(Boolean)
  for (const value of ['127.0.0.1', 'localhost', '::1']) if (!entries.includes(value)) entries.push(value)
  environment.NO_PROXY = entries.join(',')
  environment.no_proxy = environment.NO_PROXY
}

function parseClaudeVersion(output) {
  const match = String(output || '').match(/(?:^|\s)(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?:\s|$)/)
  return match ? match[1] : null
}

function sanitizeReason(error) {
  const message = String(error?.message || error || 'RUNTIME_FAILURE')
  if (message.startsWith('READINESS_TIMEOUT')) return 'READINESS_TIMEOUT'
  if (message === 'PROCESS_EXITED') return 'PROCESS_EXITED'
  if (message.includes('Claude Code')) return 'CLAUDE_VERSION_OR_LAUNCH'
  if (message.includes('already running')) return 'ALREADY_RUNNING'
  if (message.includes('unavailable')) return 'DEPENDENCY_UNAVAILABLE'
  return 'RUNTIME_FAILURE'
}

function updateDetectorMetrics(service, value) {
  if (!service || !value || typeof value !== 'object') return
  const output = {}
  for (const key of ['uptime_ms', 'rss_bytes', 'scan_count', 'error_count', 'in_flight', 'last_latency_ms']) {
    if (typeof value[key] === 'number' && Number.isFinite(value[key])) output[key] = value[key]
  }
  service.metrics = output
}

class RuntimeSupervisor {
  constructor(config, python, options = {}) {
    this.config = config
    this.python = python
    this.noClaude = options.noClaude === true
    this.claudeArgs = Array.isArray(options.claudeArgs) ? options.claudeArgs : []
    this.runtimeDirectory = path.resolve(options.runtimeDirectory || process.env.PG_RUNTIME_DIR || path.join(config.projectRoot, '.promptguard'))
    this.state = new StateStore(this.runtimeDirectory)
    this.services = new Map()
    this.recoveries = new Map()
    this.startedAt = null
    this.status = 'created'
    this.guardReady = false
    this.guardReadinessFailures = 0
    this.currentClaudeVersion = null
    this.claude = null
    this.claudeStatus = this.noClaude ? 'skipped' : 'not_started'
    this.monitorTimer = null
    this.monitorBusy = false
    this.runtimeActive = false
    this.shuttingDown = false
    this.shutdownPromise = null
    this.exitCode = 0
    this.sessionHash = crypto.randomBytes(32).toString('hex')
    this.completion = new Promise(resolve => { this.resolveCompletion = resolve })
  }

  log(level, message) {
    if (LOG_RANK[level] <= LOG_RANK[this.config.logLevel]) {
      const writer = level === 'error' ? console.error : (level === 'warn' ? console.warn : console.log)
      writer(message)
    }
  }

  paths() {
    return {
      worker: path.join(this.config.projectRoot, 'src', 'detector', 'worker.py'),
      bridge: path.join(this.config.projectRoot, 'src', 'detector', 'mcp-bridge.cjs'),
      guard: path.join(this.config.projectRoot, 'src', 'guard', 'final-guard.cjs'),
      plugin: path.join(this.config.projectRoot, 'src', 'native-mod'),
      pluginManifest: path.join(this.config.projectRoot, 'src', 'native-mod', '.claude-plugin', 'plugin.json'),
      mcpConfig: path.join(this.runtimeDirectory, 'mcp-config.json'),
      modAudit: path.join(this.config.auditPath, 'mod-audit.json'),
      guardAudit: path.join(this.config.auditPath, 'guard-audit.jsonl'),
    }
  }

  preflight() {
    const paths = this.paths()
    for (const [name, target] of Object.entries({
      'detector worker': paths.worker,
      'detector bridge': paths.bridge,
      'Final Guard': paths.guard,
      'Native Mod manifest': paths.pluginManifest,
    })) {
      if (!fs.existsSync(target)) throw new Error(`${name} is unavailable.`)
    }
    if (!this.noClaude) {
      const activeAlternate = ALTERNATE_PROVIDER_FLAGS.find(name => truthy(process.env[name]))
      if (activeAlternate) throw new Error(`Alternate provider mode ${activeAlternate} is not supported by this guarded runtime.`)
    }
    fs.mkdirSync(this.runtimeDirectory, { recursive: true, mode: 0o700 })
    fs.mkdirSync(this.config.auditPath, { recursive: true, mode: 0o700 })
  }

  writeMcpConfig() {
    const paths = this.paths()
    const value = {
      mcpServers: {
        pgdetector: {
          command: process.execPath,
          args: [paths.bridge],
          env: {
            PG_MOD_DETECTOR_URL: this.config.modDetectorUrl,
            PG_DETECTOR_URL: this.config.modDetectorUrl,
            PG_DETECTOR_TIMEOUT_MS: String(this.config.detectorTimeoutMs),
          },
        },
      },
    }
    fs.writeFileSync(paths.mcpConfig, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
  }

  createServices() {
    const paths = this.paths()
    const commonWorker = {
      command: this.python.command,
      cwd: this.config.projectRoot,
      args: [...this.python.prefix, paths.worker],
      readyPredicate: response => response.statusCode === 200 && response.value?.ok === true && response.value?.ready === true,
    }

    const transform = new ManagedProcess({
      ...commonWorker,
      name: 'transformDetector',
      displayName: 'Transform detector',
      healthUrl: `${this.config.modDetectorUrl}/ready`,
      env: safeServiceEnvironment({
        PG_DETECTOR_PORT: String(this.config.modDetectorPort),
        PG_DETECTOR_ROLE: 'transform',
        PG_DETECTOR_MODE: process.env.PG_MOD_DETECTOR_MODE || 'normal',
        PG_DETECTOR_DELAY_MS: process.env.PG_MOD_DETECTOR_DELAY_MS || '0',
        PG_DETECTOR_MAX_BODY: String(this.config.maxBodyBytes),
      }),
    })

    const verification = new ManagedProcess({
      ...commonWorker,
      name: 'verificationDetector',
      displayName: 'Verification detector',
      healthUrl: `${this.config.guardDetectorUrl}/ready`,
      env: safeServiceEnvironment({
        PG_DETECTOR_PORT: String(this.config.guardDetectorPort),
        PG_DETECTOR_ROLE: 'verification',
        PG_DETECTOR_MODE: process.env.PG_GUARD_DETECTOR_MODE || 'normal',
        PG_DETECTOR_DELAY_MS: process.env.PG_GUARD_DETECTOR_DELAY_MS || '0',
        PG_DETECTOR_MAX_BODY: String(this.config.maxBodyBytes),
      }),
    })

    const guard = new ManagedProcess({
      name: 'finalGuard',
      displayName: 'Final Guard',
      command: process.execPath,
      args: [paths.guard],
      cwd: this.config.projectRoot,
      env: safeServiceEnvironment({
        PG_GUARD_HOST: this.config.guardHost,
        PG_GUARD_PORT: String(this.config.guardPort),
        PG_GUARD_DETECTOR_URL: this.config.guardDetectorUrl,
        PG_DETECTOR_TIMEOUT_MS: String(this.config.detectorTimeoutMs),
        PG_GUARD_MAX_BODY: String(this.config.maxBodyBytes),
        PG_MAX_BODY_BYTES: String(this.config.maxBodyBytes),
        PG_AUDIT_PATH: paths.guardAudit,
        PG_UPSTREAM_BASE_URL: this.config.upstreamBaseUrl,
        PG_SESSION_HASH: this.sessionHash,
        PG_LOG_LEVEL: this.config.logLevel,
      }),
      healthUrl: `${this.config.guardUrl}/health`,
      readyUrl: `${this.config.guardUrl}/ready`,
      readyPredicate: response => response.statusCode === 200 && response.value?.ok === true && response.value?.ready === true,
    })

    for (const service of [transform, verification, guard]) {
      service.on('exit', event => {
        if (this.runtimeActive && !this.shuttingDown && !event.expected) void this.recoverService(service, 'PROCESS_EXITED')
      })
      this.services.set(service.name, service)
    }
  }

  service(name) {
    return this.services.get(name)
  }

  snapshot() {
    const services = {}
    for (const [name, service] of this.services) services[name] = service.snapshot()
    const uptimeMs = this.startedAt ? Math.max(0, Date.now() - this.startedAt.getTime()) : 0
    return {
      runtimeVersion: '1.0.0',
      pid: process.pid,
      status: this.status,
      startedAt: this.startedAt?.toISOString() || null,
      uptimeMs,
      noClaude: this.noClaude,
      services,
      guard: {
        url: this.config.guardUrl,
        ready: this.guardReady,
      },
      claude: {
        expectedVersion: this.config.claudeVersion,
        currentVersion: this.currentClaudeVersion,
        strictVersion: this.config.strictClaudeVersion,
        status: this.claudeStatus,
        pid: this.claude?.pid || null,
      },
      protection: {
        directProviderFallback: false,
        outboundAllowedOnlyThroughGuard: true,
      },
    }
  }

  writeState() {
    try { this.state.write(this.snapshot()) } catch (error) { this.log('warn', 'Warning: runtime status could not be updated.') }
  }

  async waitUntilReady(service) {
    const value = await waitForJson(service.readyUrl, service.readyPredicate, {
      timeoutMs: this.config.readinessTimeoutMs,
      intervalMs: Math.min(250, this.config.healthCheckIntervalMs),
      requestTimeoutMs: Math.min(1000, this.config.detectorTimeoutMs),
      isAlive: () => service.isAlive(),
    })
    updateDetectorMetrics(service, value)
    service.markReady()
  }

  restartDelay(restartNumber) {
    return Math.min(this.config.restartBackoffMaxMs, this.config.restartBackoffMs * (2 ** Math.max(0, restartNumber - 1)))
  }

  async startServiceWithRecovery(service) {
    for (;;) {
      try {
        await service.spawn()
        await this.waitUntilReady(service)
        this.writeState()
        return
      } catch (error) {
        await service.stop(this.config.shutdownTimeoutMs)
        if (service.restartCount >= this.config.workerRestartLimit) throw new Error(`${service.displayName} unavailable after bounded restart attempts.`)
        service.restartCount += 1
        service.phase = 'recovering'
        this.status = 'recovering'
        this.writeState()
        this.log('warn', `${service.displayName} temporarily unavailable. Restarting (${service.restartCount}/${this.config.workerRestartLimit})...`)
        await delay(this.restartDelay(service.restartCount))
      }
    }
  }

  async verifyClaudeVersion() {
    const result = spawnSync(this.config.claudeBinary, ['--version'], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 15000,
      env: process.env,
    })
    if (result.error || result.status !== 0) throw new Error('Claude Code is unavailable.')
    const current = parseClaudeVersion(`${result.stdout || ''}\n${result.stderr || ''}`)
    if (!current) throw new Error('Claude Code version could not be determined.')
    this.currentClaudeVersion = current
    if (current !== this.config.claudeVersion) {
      const message = `PromptGuard validated for Claude Code ${this.config.claudeVersion}. Current version: ${current}.`
      if (this.config.strictClaudeVersion) throw new Error(message)
      this.log('warn', `Warning: ${message}`)
    }
    this.writeState()
  }

  async verifyStartupGate() {
    const checks = [
      [this.service('transformDetector'), `${this.config.modDetectorUrl}/ready`],
      [this.service('verificationDetector'), `${this.config.guardDetectorUrl}/ready`],
      [this.service('finalGuard'), `${this.config.guardUrl}/ready`],
    ]
    for (const [service, url] of checks) {
      if (!service?.isAlive()) throw new Error(`${service?.displayName || 'dependency'} unavailable.`)
      const response = await getJson(url, Math.min(2000, this.config.detectorTimeoutMs))
      if (response.statusCode !== 200 || response.value?.ok !== true || response.value?.ready !== true) {
        throw new Error(`${service.displayName} unavailable.`)
      }
    }
    this.guardReady = true
  }

  async launchClaude() {
    const paths = this.paths()
    const environment = { ...process.env }
    for (const flag of ALTERNATE_PROVIDER_FLAGS) delete environment[flag]
    delete environment.ANTHROPIC_BEDROCK_BASE_URL
    delete environment.ANTHROPIC_VERTEX_BASE_URL
    environment.ANTHROPIC_BASE_URL = this.config.guardUrl
    environment.PG_MOD_DETECTOR_URL = this.config.modDetectorUrl
    environment.PG_DETECTOR_URL = this.config.modDetectorUrl
    environment.PG_DETECTOR_TIMEOUT_MS = String(this.config.detectorTimeoutMs)
    environment.PG_MOD_AUDIT = paths.modAudit
    environment.PG_SESSION_HASH = this.sessionHash
    environment.PG_RUNTIME_ACTIVE = '1'
    addNoProxy(environment)

    const args = ['--plugin-dir', paths.plugin, '--mcp-config', paths.mcpConfig, ...this.claudeArgs]
    const child = spawn(this.config.claudeBinary, args, {
      cwd: process.cwd(),
      env: environment,
      detached: process.platform !== 'win32',
      stdio: 'inherit',
      windowsHide: false,
    })
    this.claude = child
    this.claudeStatus = 'starting'
    await new Promise((resolve, reject) => {
      let settled = false
      const finish = callback => value => {
        if (settled) return
        settled = true
        child.removeListener('spawn', onSpawn)
        child.removeListener('error', onError)
        callback(value)
      }
      const onSpawn = finish(resolve)
      const onError = finish(reject)
      child.once('spawn', onSpawn)
      child.once('error', onError)
    })
    this.claudeStatus = 'running'
    child.once('exit', (code, signal) => {
      if (this.shuttingDown) return
      this.claudeStatus = 'exited'
      const exitCode = Number.isInteger(code) ? code : (signal ? 1 : 0)
      void this.shutdown('claude_exit', exitCode)
    })
  }

  async start() {
    this.state.assertNotRunning()
    this.preflight()
    this.writeMcpConfig()
    this.createServices()
    this.startedAt = new Date()
    this.status = 'starting'
    this.writeState()

    try {
      console.log('PromptGuard Runtime')
      await this.startServiceWithRecovery(this.service('transformDetector'))
      console.log('✓ Transform detector ready')
      await this.startServiceWithRecovery(this.service('verificationDetector'))
      console.log('✓ Verification detector ready')
      await this.startServiceWithRecovery(this.service('finalGuard'))
      this.guardReady = true
      console.log('✓ Final Guard ready')

      if (this.noClaude) {
        await this.verifyStartupGate()
        this.runtimeActive = true
        this.status = 'running'
        this.startMonitor()
        this.writeState()
        console.log('• Claude Code launch skipped (--no-claude)')
        console.log('Protection services active (test mode)')
        return
      }

      await this.verifyClaudeVersion()
      console.log(`✓ Claude Code ${this.currentClaudeVersion}`)
      await this.verifyStartupGate()
      this.runtimeActive = true
      await this.launchClaude()
      this.status = 'running'
      this.startMonitor()
      this.writeState()
      console.log('Protection active')
    } catch (error) {
      this.status = 'failed'
      this.writeState()
      await this.shutdown('startup_failure', 1)
      throw error
    }
  }

  startMonitor() {
    this.monitorTimer = setInterval(() => { void this.monitor() }, this.config.healthCheckIntervalMs)
    this.monitorTimer.unref?.()
  }

  async monitor() {
    if (this.monitorBusy || this.shuttingDown || !this.runtimeActive) return
    this.monitorBusy = true
    try {
      for (const service of this.services.values()) {
        if (service.phase !== 'ready' || this.recoveries.has(service.name)) continue
        try {
          const response = await getJson(service.healthUrl, Math.min(1000, this.config.healthCheckIntervalMs))
          if (response.statusCode !== 200 || response.value?.ok !== true) throw new Error('NOT_HEALTHY')
          updateDetectorMetrics(service, response.value)
          service.healthFailures = 0
        } catch {
          service.healthFailures += 1
          if (service.healthFailures >= this.config.healthFailureThreshold) void this.recoverService(service, 'HEALTH_CHECK_FAILED')
        }
      }

      if (!this.recoveries.has('finalGuard') && this.service('finalGuard')?.phase === 'ready') {
        try {
          const response = await getJson(`${this.config.guardUrl}/ready`, Math.min(1000, this.config.detectorTimeoutMs))
          if (response.statusCode !== 200 || response.value?.ready !== true || response.value?.ok !== true) throw new Error('NOT_READY')
          if (!this.guardReady) this.log('info', 'Final Guard recovered.')
          this.guardReady = true
          this.guardReadinessFailures = 0
        } catch {
          this.guardReady = false
          this.guardReadinessFailures += 1
          if (this.guardReadinessFailures >= this.config.healthFailureThreshold && !this.recoveries.has('verificationDetector')) {
            void this.recoverService(this.service('finalGuard'), 'READINESS_CHECK_FAILED')
          }
        }
      }
      if (!this.shuttingDown) {
        this.status = this.guardReady && this.recoveries.size === 0 ? 'running' : 'degraded'
        this.writeState()
      }
    } finally {
      this.monitorBusy = false
    }
  }

  async recoverService(service, reason) {
    if (!service || this.shuttingDown || this.recoveries.has(service.name)) return
    const recovery = (async () => {
      service.phase = 'recovering'
      this.status = 'recovering'
      if (service.name === 'finalGuard' || service.name === 'verificationDetector') this.guardReady = false
      this.writeState()
      this.log('warn', `${service.displayName} temporarily unavailable.`)
      this.log('warn', 'Outbound requests remain blocked. Restarting dependency...')

      await service.stop(this.config.shutdownTimeoutMs)
      while (!this.shuttingDown) {
        if (service.restartCount >= this.config.workerRestartLimit) {
          await this.fatal(`${service.displayName} exceeded its restart limit.`, reason)
          return
        }
        service.restartCount += 1
        service.phase = 'recovering'
        this.writeState()
        await delay(this.restartDelay(service.restartCount))
        if (this.shuttingDown) return
        try {
          await service.spawn()
          await this.waitUntilReady(service)
          if (service.name === 'finalGuard' || (service.name === 'verificationDetector' && !this.recoveries.has('finalGuard'))) {
            await waitForJson(`${this.config.guardUrl}/ready`, response => response.statusCode === 200 && response.value?.ok === true && response.value?.ready === true, {
              timeoutMs: this.config.readinessTimeoutMs,
              intervalMs: Math.min(250, this.config.healthCheckIntervalMs),
              requestTimeoutMs: Math.min(1000, this.config.detectorTimeoutMs),
              isAlive: () => this.service('finalGuard')?.isAlive() === true,
            })
            this.guardReady = true
            this.guardReadinessFailures = 0
          }
          this.status = 'running'
          this.writeState()
          this.log('info', `${service.displayName} recovered.`)
          return
        } catch {
          await service.stop(this.config.shutdownTimeoutMs)
          this.log('warn', `${service.displayName} restart did not become ready.`)
        }
      }
    })()
    this.recoveries.set(service.name, recovery)
    try { await recovery } finally { this.recoveries.delete(service.name) }
  }

  async fatal(message, reason) {
    if (this.shuttingDown) return
    this.log('error', message)
    this.status = 'failed'
    this.failureReason = sanitizeReason(reason)
    this.writeState()
    await this.shutdown('dependency_failure', 1)
  }

  async shutdown(reason = 'normal', exitCode = 0) {
    if (this.shutdownPromise) return this.shutdownPromise
    this.shutdownPromise = (async () => {
      this.shuttingDown = true
      this.runtimeActive = false
      this.exitCode = exitCode
      if (this.monitorTimer) clearInterval(this.monitorTimer)
      this.status = 'stopping'
      this.guardReady = false
      this.writeState()

      if (this.claude && this.claude.exitCode === null && this.claude.signalCode === null) {
        this.claudeStatus = 'stopping'
        await stopProcessTree(this.claude, this.config.shutdownTimeoutMs)
      }
      this.claudeStatus = this.noClaude ? 'skipped' : 'stopped'

      for (const name of ['finalGuard', 'verificationDetector', 'transformDetector']) {
        const service = this.service(name)
        if (service) await service.stop(this.config.shutdownTimeoutMs)
      }
      this.status = exitCode === 0 ? 'stopped' : 'failed'
      this.writeState()
      this.resolveCompletion({ reason, exitCode })
    })()
    return this.shutdownPromise
  }

  wait() {
    return this.completion
  }
}

module.exports = { RuntimeSupervisor, parseClaudeVersion, safeServiceEnvironment }
