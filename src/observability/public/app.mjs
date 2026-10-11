import { summarize, escape, metric, findingMarkup, pipeline, toolActivities } from './view.mjs'
import { demo } from './demo.mjs'
const $ = id => document.getElementById(id)
const select = id => /** @type {HTMLSelectElement} */ ($(id))
let data = { mode: 'LIVE', events: [], guard: null }
let selected = null
let session = ''
const cells = entries => `<dl>${entries.map(([key, value]) => `<dt>${escape(key)}</dt><dd>${escape(value)}</dd>`).join('')}</dl>`
function render() {
  const sessions = [...new Set(data.events.map(e => e.session))]
  if (!sessions.includes(session)) session = sessions.at(-1) || ''
  $('session').innerHTML = sessions.length ? sessions.map(s => `<option ${s === session ? 'selected' : ''} value="${escape(s)}">${escape(s === 'DEMO SESSION' ? s : s.slice(0, 12))}</option>`).join('') : '<option>No session</option>'
  const events = data.events.filter(e => e.session === session).sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || '') || a.id - b.id)
  if (!events.some(e => e.id === selected)) selected = events.at(-1)?.id ?? null
  const stats = summarize(events)
  $('badge').textContent = data.mode
  $('identity').textContent = `Session hash: ${session || 'Unavailable'} · Turn ID: Unavailable · ${data.truncated ? 'Partial: latest 2,000 audit records' : 'Counts cover loaded audit records, not unique secrets'}`
  $('pipeline').innerHTML = pipeline(events, data.mode === 'DEMO' ? data.guard?.decision : null).map(s => `<div class="stage ${s.status}"><span class="status ${s.status}">${s.status.toUpperCase()}</span><strong>${s.name}</strong><small>${s.detail}</small></div>`).join('')
  $('summary').innerHTML = [['Scanned payloads', stats.scanned], ['Detected occurrences', stats.detected], ['Masked occurrences', stats.masked], ['Read operations', stats.reads], ['Observed tool calls', stats.tools]].map(([label, value]) => `<div><strong>${metric(value)}</strong><span>${label}</span></div>`).join('')
  $('timeline').innerHTML = events.length ? events.map(e => `<button class="event ${e.failed ? 'failure' : ''}" data-event="${e.id}" aria-pressed="${e.id === selected}"><time>${escape(e.timestamp?.slice(11, 23))}</time><span><strong>${escape(e.event)}</strong><small>${e.source} · detected ${metric(e.detected)} · masked ${metric(e.masked)}</small></span><b>${e.failed ? 'ERROR' : 'OBSERVED'}</b></button>`).join('') : '<p>No audit events yet. Run the existing PromptGuard launcher.</p>'
  for (const button of $('timeline').querySelectorAll('button')) button.addEventListener('click', () => { selected = Number(button.dataset.event); render() })
  const event = events.find(e => e.id === selected) || events.at(-1)
  $('detail').innerHTML = event ? cells([['Event', event.event], ['Source', event.source], ['Hook', event.hook], ['Tool', event.tool], ['Timestamp (UTC)', event.timestamp], ['Scanned payloads', metric(event.scanned)], ['Failure stage', event.failureStage], ['Hook outcome', event.failed ? 'Failed — provider blocking unverified' : 'Audit recorded']]) : '<p>Select an event to inspect safe metadata.</p>'
  const findings = events.flatMap(e => e.findings.map(f => ({ f, source: e.source })))
  $('findings').innerHTML = findings.length ? findings.map(({ f, source }) => findingMarkup(f, source)).join('') : `<p>${stats.detected > 0 ? 'Findings counted, but detailed metadata is unavailable in this audit.' : 'No detailed findings recorded.'}</p>`
  const tools = toolActivities(events)
  const activity = e => `<article class="activity"><strong>${escape(e.tool)}</strong><span>${e.event === 'tool_started' ? 'Running' : e.event === 'tool_denied' ? 'Denied' : e.event === 'tool_failed' || e.failed ? 'Failed' : e.toolError ? 'Tool error result' : 'Result observed'} · ${e.failed ? 'Scan failed' : e.scanned === null ? 'Scan count unavailable' : `${e.scanned} payloads scanned`}</span><small>Detected ${metric(e.detected)} · Masked ${metric(e.masked)}<br>Started: ${escape(e.started?.slice(11, 23))} · Latest: ${escape(e.timestamp?.slice(11, 23))}</small></article>`
  $('tools').innerHTML = tools.length ? tools.map(activity).join('') : '<p>No tool results recorded.</p>'
  $('files').innerHTML = tools.some(e => e.tool === 'Read' && ['scan_completed', 'audit_record'].includes(e.event)) ? tools.filter(e => e.tool === 'Read' && ['scan_completed', 'audit_record'].includes(e.event)).map(activity).join('') : '<p>No file reads recorded.</p>'
  $('preview').innerHTML = findings.length ? '<div class="columns"><div><h3>Before · secret hidden</h3><pre>' + findings.map(() => '[DETECTED_SECRET]').join('\n') + '</pre></div><div><h3>After · replacement</h3><pre>' + findings.map(({ f }) => escape(f.placeholder)).join('\n') + '</pre></div></div>' : '<p>No replacement preview available.</p>'
  if (data.mode === 'DEMO' && findings.length) $('preview').innerHTML += '<p class="tag">DEMO STRUCTURE EXAMPLE · not a captured payload</p><div class="columns"><pre>DB_HOST=localhost\nDB_PASSWORD=[DETECTED_SECRET]\nDB_PORT=5432</pre><pre>DB_HOST=localhost\nDB_PASSWORD=[PASSWORD_1]\nDB_PORT=5432</pre></div>'
  const guard = data.guard
  $('egress').innerHTML = guard ? `<div class="mock"><h3>${escape(guard.scope)}</h3><strong class="status ${guard.decision === 'SAFE' ? 'success' : guard.decision === 'BLOCKED' ? 'blocked' : 'pending'}">${escape(guard.decision)}</strong>${cells([['Payloads scanned', metric(guard.scanned)], ['Remaining detected secrets', metric(guard.remaining)], ['Observed placeholders (not masking count)', metric(guard.placeholders)], ['Reason code', guard.reason]])}<p>Separate evidence; not correlated to the selected live session. No Cloud transmission is attested.</p></div>` : `<p>${data.guardUnavailable ? 'Configured mock Guard record unavailable.' : 'Egress Check Unavailable · no final request verification data.'}</p>`
}
let generation = 0
async function refresh() {
  const current = ++generation
  if (select('mode').value === 'DEMO') {
    data = demo(select('scenario').value)
    $('notice').textContent = 'DEMO / MOCK — synthetic events, not backend execution.'
    render(); return
  }
  try {
    const response = await fetch('/api/events', { cache: 'no-store' })
    if (!response.ok) throw new Error('AUDIT_UNAVAILABLE')
    const next = await response.json()
    if (current !== generation) return
    data = next
    $('notice').textContent = 'LIVE · localhost audit · refreshes every 2 seconds · provider egress NOT VERIFIED'
    render()
  } catch {
    if (current !== generation) return
    data = { mode: 'LIVE', events: [], guard: null }
    $('notice').textContent = 'Audit unavailable. Waiting for a complete readable audit file; no safety claim can be made.'
    render()
  }
}
$('mode').addEventListener('change', () => { selected = null; $('scenario-label').hidden = select('mode').value !== 'DEMO'; refresh() })
$('scenario').addEventListener('change', () => { selected = null; refresh() })
$('session').addEventListener('change', () => { session = select('session').value; selected = null; render() })
await refresh()
setInterval(() => { if (select('mode').value === 'LIVE') refresh() }, 2000)
