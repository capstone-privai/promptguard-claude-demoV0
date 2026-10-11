export function toolActivities(events) {
  const rows = []
  const operations = new Map()
  for (const e of events.filter(e => ['tool.call', 'tool.call.text', 'tool.call.context'].includes(e.hook) && e.tool)) {
    if (e.operation !== null && e.operation !== undefined && operations.has(e.operation)) {
      const index = operations.get(e.operation)
      const previous = rows[index]
      const sum = key => previous.event === 'tool_started' ? e[key] : previous[key] === null || e[key] === null ? null : previous[key] + e[key]
      rows[index] = { ...e, started: previous.started,
        scanned: sum('scanned'), detected: sum('detected'), masked: sum('masked') }
    } else {
      if (e.operation !== null && e.operation !== undefined) operations.set(e.operation, rows.length)
      rows.push({ ...e, started: e.event === 'tool_started' ? e.timestamp : null })
    }
  }
  return rows
}
export function summarize(events) {
  const scans = events.filter(e => !['tool_started', 'tool_failed', 'tool_denied'].includes(e.event))
  const total = key => scans.length && scans.every(e => Number.isSafeInteger(e[key])) ? scans.reduce((n, e) => n + e[key], 0) : null
  const tools = toolActivities(events)
  return { scanned: total('scanned'), detected: total('detected'), masked: total('masked'), tools: tools.length, reads: tools.filter(e => e.tool === 'Read' && ['scan_completed', 'audit_record'].includes(e.event)).length, failed: events.some(e => e.failed) }
}
export const escape = value => String(value ?? 'Unavailable').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
export const metric = value => value === null || value === undefined ? 'Unavailable' : String(value)
export function findingMarkup(f, source) {
  const location = f.unit && f.start !== null && f.end !== null ? `Payload ${metric(f.payload)} · offsets ${f.start}–${f.end} (${f.unit}, end exclusive)` : 'Location unavailable'
  return `<article class="finding"><strong>${escape(f.type)}</strong><span class="tag">${escape(source)}</span><dl><dt>Detector</dt><dd>${escape(f.detector)}</dd><dt>Rule</dt><dd>${escape(f.rule)}</dd><dt>Action</dt><dd>${escape(f.action)}</dd><dt>Location</dt><dd>${escape(location)}</dd></dl><p class="muted">${f.rule ? 'Rule reported by detector; MASK records the applied action.' : 'Reason metadata unavailable.'}</p></article>`
}
export function pipeline(events, demoDecision = null) {
  const activities = toolActivities(events)
  const toolStatus = activities.some(e => e.event === 'tool_started') ? 'running' : activities.some(e => e.event === 'tool_denied') ? 'blocked' : activities.some(e => e.failed || e.event === 'tool_failed') ? 'error' : activities.length ? 'success' : 'pending'
  const has = source => events.some(e => e.source === source && !e.failed)
  const stage = (name, status, detail) => ({ name, status, detail })
  return [stage('User Prompt', has('USER_PROMPT') ? 'success' : 'pending', 'Audited prompt scan'), stage('Agent / Tool', toolStatus, 'Observed tool lifecycle'), stage('Detector', events.some(e => e.failureStage === 'detector') ? 'error' : events.some(e => e.scanned > 0) ? 'success' : 'pending', 'Local scan evidence'), stage('Masking', events.some(e => e.failureStage === 'sanitizer') ? 'error' : events.some(e => e.masked > 0) ? 'success' : 'pending', 'Applied replacements'), stage('Egress Check', demoDecision === 'SAFE' ? 'success' : demoDecision === 'BLOCKED' ? 'blocked' : 'pending', demoDecision ? 'DEMO only' : 'NOT VERIFIED'), stage('Cloud Model', 'pending', 'No provider-send evidence')]
}
