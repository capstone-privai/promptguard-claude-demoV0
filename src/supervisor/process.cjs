'use strict'

const { EventEmitter } = require('events')
const { spawn } = require('child_process')

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
}

function waitForExit(child, timeoutMs) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true)
  return new Promise(resolve => {
    let settled = false
    const finish = value => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      child.removeListener('exit', onExit)
      resolve(value)
    }
    const onExit = () => finish(true)
    const timer = setTimeout(() => finish(false), timeoutMs)
    child.once('exit', onExit)
  })
}

function runTaskkill(pid, force) {
  return new Promise(resolve => {
    const args = ['/PID', String(pid), '/T']
    if (force) args.push('/F')
    const killer = spawn('taskkill.exe', args, { stdio: 'ignore', windowsHide: true })
    killer.once('error', () => resolve())
    killer.once('exit', () => resolve())
  })
}

async function stopProcessTree(child, timeoutMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return
  if (process.platform === 'win32') {
    try { child.kill('SIGTERM') } catch { }
  } else {
    try { process.kill(-child.pid, 'SIGTERM') } catch {
      try { child.kill('SIGTERM') } catch { }
    }
  }
  const graceful = await waitForExit(child, timeoutMs)
  if (!graceful) {
    if (process.platform === 'win32') await runTaskkill(child.pid, true)
    else {
      try { process.kill(-child.pid, 'SIGKILL') } catch {
        try { child.kill('SIGKILL') } catch { }
      }
    }
    await waitForExit(child, Math.min(2000, timeoutMs))
  } else if (process.platform === 'win32') {
    await runTaskkill(child.pid, false)
  }
}

class ManagedProcess extends EventEmitter {
  constructor(options) {
    super()
    this.name = options.name
    this.displayName = options.displayName || options.name
    this.command = options.command
    this.args = options.args || []
    this.cwd = options.cwd
    this.env = options.env
    this.healthUrl = options.healthUrl
    this.readyUrl = options.readyUrl || options.healthUrl
    this.readyPredicate = options.readyPredicate || (response => response.statusCode === 200 && response.value?.ok === true)
    this.child = null
    this.phase = 'stopped'
    this.restartCount = 0
    this.healthFailures = 0
    this.lastReadyAt = null
    this.lastExit = null
    this.metrics = {}
    this.stopping = false
    this.generation = 0
  }

  get pid() {
    return this.child?.pid || null
  }

  isAlive() {
    return Boolean(this.child && this.child.exitCode === null && this.child.signalCode === null && !this.stopping)
  }

  async spawn() {
    if (this.isAlive()) throw new Error(`${this.name} is already running`)
    this.stopping = false
    this.phase = 'starting'
    this.healthFailures = 0
    const generation = ++this.generation
    const child = spawn(this.command, this.args, {
      cwd: this.cwd,
      env: this.env,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })
    this.child = child

    // Service output is intentionally drained, not copied into runtime logs. This
    // keeps dependency diagnostics from accidentally becoming a raw-content log.
    child.stdout?.resume()
    child.stderr?.resume()

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

    child.once('exit', (code, signal) => {
      if (generation !== this.generation) return
      const expected = this.stopping
      this.lastExit = { code: Number.isInteger(code) ? code : null, signal: signal || null, at: new Date().toISOString() }
      this.phase = expected ? 'stopped' : 'unavailable'
      this.emit('exit', { expected, code, signal, generation })
    })
  }

  markReady() {
    this.phase = 'ready'
    this.healthFailures = 0
    this.lastReadyAt = new Date().toISOString()
  }

  async stop(timeoutMs = 5000) {
    const child = this.child
    this.stopping = true
    this.phase = 'stopping'
    if (!child || child.exitCode !== null || child.signalCode !== null) {
      this.phase = 'stopped'
      this.child = null
      return
    }

    await stopProcessTree(child, timeoutMs)
    this.phase = 'stopped'
    this.child = null
  }

  snapshot() {
    return {
      status: this.phase,
      pid: this.pid,
      restarts: this.restartCount,
      healthFailures: this.healthFailures,
      lastReadyAt: this.lastReadyAt,
      lastExit: this.lastExit,
      metrics: { ...this.metrics },
    }
  }
}

module.exports = { ManagedProcess, delay, stopProcessTree, waitForExit }
