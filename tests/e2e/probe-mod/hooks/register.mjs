// Probe Mod for tests/e2e/contexts.mjs: records which hooks carry which tag (PG_PROBE_TAGS, comma separated) in their
// input or output. It records hook names and tags only, never text, and changes nothing.
const seen = new Set()
const tagsIn = (tags, value) => {
  let text = ''
  try { text = JSON.stringify(value) ?? '' } catch { text = String(value) }
  return tags.filter(tag => text.includes(tag))
}

async function record($, hook, input, output) {
  const tags = String((await $.env.get('PG_PROBE_TAGS')) || '').split(',').filter(Boolean)
  const before = seen.size
  for (const tag of tagsIn(tags, input)) seen.add(`${hook}|in|${tag}`)
  for (const tag of tagsIn(tags, output)) seen.add(`${hook}|out|${tag}`)
  seen.add(`${hook}|called|`)
  const file = await $.env.get('PG_PROBE_LOG')
  if (file && seen.size !== before) await $.fs.write(file, JSON.stringify([...seen].sort()))
}

export function register(on) {
  on('prompt.submit', async ($, e, next) => { const r = await next(e); await record($, 'prompt.submit', e, r); return r }).catch(() => {})
  on('prompt.context', async ($, e, next) => { const r = await next(e); await record($, 'prompt.context', e, r); return r }).catch(() => {})
  on('prompt.section', async ($, e, next) => { const r = await next(e); await record($, 'prompt.section', e, r); return r }).catch(() => {})
  on('prompt.compose', async ($, e, next) => { const r = await next(e); await record($, 'prompt.compose', e, r); return r }).catch(() => {})
  on('prompt.attachment', async ($, e, next) => { const r = await next(e); await record($, 'prompt.attachment', e, r); return r }).catch(() => {})
  on('skill.prompt', async ($, e, next) => { const r = await next(e); await record($, 'skill.prompt', e, r); return r }).catch(() => {})
  on('agent.spawn', async ($, e, next) => { const r = await next(e); await record($, 'agent.spawn', e, r); return r }).catch(() => {})
  on('tool.call', async ($, e, next) => { const r = await next(e); await record($, 'tool.call', e, r); return r }).catch(() => {})
  on('session.append', async ($, e, next) => { const r = await next(e); await record($, 'session.append', e, r); return r }).catch(() => {})
}
