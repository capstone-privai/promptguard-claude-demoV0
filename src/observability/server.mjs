import http from 'node:http'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { projectAudit, projectGuard } from './model.mjs'
const root = path.dirname(fileURLToPath(import.meta.url))
const auditDir = process.env.PG_AUDIT_DIR || path.resolve(root, '../../.runtime/audit')
const auditFile = process.env.PG_MOD_AUDIT
const guardFile = process.env.PG_OBSERVABILITY_GUARD_RECORD
const assets = new Map([['/', ['index.html', 'text/html']], ['/app.mjs', ['app.mjs', 'text/javascript']], ['/styles.css', ['styles.css', 'text/css']], ['/view.mjs', ['view.mjs', 'text/javascript']], ['/demo.mjs', ['demo.mjs', 'text/javascript']]])
async function readJson(file) {
  if ((await fs.stat(file)).size > 16 * 1024 * 1024) throw new Error('AUDIT_TOO_LARGE')
  return JSON.parse(await fs.readFile(file, 'utf8'))
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
        let file = auditFile
        if (!file) {
          const names = (await fs.readdir(auditDir)).filter(name => /^mod-audit-[\d-]+\.json$/.test(name)).sort()
          if (names.length) file = path.join(auditDir, names.at(-1))
        }
        const rows = file ? await readJson(file) : []
        let guard = null
        let guardUnavailable = false
        if (guardFile) { try { guard = projectGuard(await readJson(guardFile)) } catch { guardUnavailable = true } }
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ mode: 'LIVE', events: projectAudit(rows), guard, guardUnavailable, truncated: rows.length > 2000 })); return
      }
      const asset = assets.get(req.url)
      if (!asset) { res.writeHead(404); res.end(); return }
      res.setHeader('Content-Type', `${asset[1]}; charset=utf-8`)
      res.end(await fs.readFile(path.join(root, 'public', asset[0])))
    } catch (error) {
      res.setHeader('Content-Type', 'application/json')
      if (error.code === 'ENOENT' && !auditFile) res.end(JSON.stringify({ mode: 'LIVE', events: [], guard: null }))
      else { res.writeHead(503); res.end(JSON.stringify({ error: 'AUDIT_UNAVAILABLE' })) }
    }
  })
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PG_OBSERVABILITY_PORT || 18880)
  createServer().listen(port, '127.0.0.1', () => process.stdout.write(`PromptGuard Observability: http://127.0.0.1:${port}\n`))
}
