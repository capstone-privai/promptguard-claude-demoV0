import http from 'node:http'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { projectAudit, projectGuardAudit } from './model.mjs'

const root = path.dirname(fileURLToPath(import.meta.url))
const legacyAuditDir = process.env.PG_AUDIT_DIR || path.resolve(root, '../../.runtime/audit')
const runtimeAuditDir = process.env.PG_OBSERVABILITY_AUDIT_DIR || process.env.PG_AUDIT_PATH || path.resolve(root, '../../.promptguard/audit')
const auditFile = process.env.PG_MOD_AUDIT
const configuredGuardFile = process.env.PG_GUARD_AUDIT
const guardFile = configuredGuardFile || path.join(runtimeAuditDir, 'guard-audit.jsonl')
const assets = new Map([['/', ['index.html', 'text/html']], ['/app.mjs', ['app.mjs', 'text/javascript']], ['/styles.css', ['styles.css', 'text/css']], ['/view.mjs', ['view.mjs', 'text/javascript']], ['/demo.mjs', ['demo.mjs', 'text/javascript']]])
const maxAuditBytes = 16 * 1024 * 1024

async function readJson(file) {
  if ((await fs.stat(file)).size > maxAuditBytes) throw new Error('AUDIT_TOO_LARGE')
  return JSON.parse(await fs.readFile(file, 'utf8'))
}

async function readJsonLines(file) {
  if ((await fs.stat(file)).size > maxAuditBytes) throw new Error('AUDIT_TOO_LARGE')
  const text = await fs.readFile(file, 'utf8')
  const lines = text.split(/\r?\n/)
  if (!text.endsWith('\n')) lines.pop()
  return lines.filter(Boolean).map(line => JSON.parse(line))
}

async function firstReadable(candidates) {
  for (const candidate of candidates) {
    try { return await readJson(candidate) } catch (error) { if (error.code !== 'ENOENT') throw error }
  }
  return []
}

async function readModAudit() {
  if (auditFile) return readJson(auditFile)
  let legacyFiles = []
  try {
    legacyFiles = (await fs.readdir(legacyAuditDir)).filter(name => /^mod-audit-[\d-]+\.json$/.test(name)).sort().reverse().map(name => path.join(legacyAuditDir, name))
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  return firstReadable([path.join(runtimeAuditDir, 'mod-audit.json'), ...legacyFiles])
}

async function readGuardAudit() {
  try {
    return { guards: projectGuardAudit(await readJsonLines(guardFile)), guardUnavailable: false }
  } catch (error) {
    if (error.code === 'ENOENT' && !configuredGuardFile) return { guards: [], guardUnavailable: false }
    return { guards: [], guardUnavailable: true }
  }
}

export function createServer() {
  return http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    const host = req.headers.host || ''
    if (!/^(127\.0\.0\.1|localhost)(:\d+)?$/.test(host) || req.method !== 'GET' || (req.headers.origin && ![`http://${host}`].includes(req.headers.origin))) {
      res.writeHead(403); res.end(); return
    }
    try {
      if (req.url === '/api/events') {
        const rows = await readModAudit()
        const guardState = await readGuardAudit()
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ mode: 'LIVE', events: projectAudit(rows), ...guardState, truncated: rows.length > 2000 })); return
      }
      const asset = assets.get(req.url)
      if (!asset) { res.writeHead(404); res.end(); return }
      res.setHeader('Content-Type', `${asset[1]}; charset=utf-8`)
      res.end(await fs.readFile(path.join(root, 'public', asset[0])))
    } catch {
      res.setHeader('Content-Type', 'application/json')
      res.writeHead(503); res.end(JSON.stringify({ error: 'AUDIT_UNAVAILABLE' }))
    }
  })
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PG_OBSERVABILITY_PORT || 18880)
  createServer().listen(port, '127.0.0.1', () => process.stdout.write(`PromptGuard Observability: http://127.0.0.1:${port}\n`))
}
