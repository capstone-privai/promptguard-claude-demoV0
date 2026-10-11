import { cp, mkdir, readFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
for (const file of ['server.mjs', 'model.mjs', 'public/app.mjs', 'public/view.mjs', 'public/demo.mjs']) execFileSync(process.execPath, ['--check', `src/observability/${file}`])
for (const file of ['index.html', 'styles.css']) await readFile(`src/observability/public/${file}`)
await mkdir('dist', { recursive: true })
await cp('src/observability', 'dist/observability', { recursive: true })
process.stdout.write('Observability build verified: dist/observability\n')
