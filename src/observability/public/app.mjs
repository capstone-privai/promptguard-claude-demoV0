import { summarize, escape, metric, findingMarkup, pipeline, toolActivities, label, sortRows } from './view.mjs'
import { demo } from './demo.mjs'
const $ = id => document.getElementById(id)
const select = id => /** @type {HTMLSelectElement} */ ($(id))
let data = { mode: 'LIVE', events: [], guards: [], guard: null }
let selected = null
let session = ''
const cells = entries => `<dl>${entries.map(([key, value]) => `<dt>${escape(key)}</dt><dd>${escape(value)}</dd>`).join('')}</dl>`
function render() {
  const liveGuards = Array.isArray(data.guards) ? data.guards : []
  const sessions = [...new Set([...data.events.map(e => e.session), ...liveGuards.map(e => e.session)])]
  if (!sessions.includes(session)) session = sessions.at(-1) || ''
  $('session').innerHTML = sessions.length ? sessions.map(s => `<option ${s === session ? 'selected' : ''} value="${escape(s)}">${escape(s === 'DEMO SESSION' || s === 'unavailable' ? label(s) : s.slice(0, 12))}</option>`).join('') : '<option>세션 없음</option>'
  const events = data.events.filter(e => e.session === session)
  const guard = data.mode === 'DEMO' ? data.guard : sortRows(liveGuards.filter(e => e.session === session), 'newest').at(0) || null
  const datedEvents = events.some(e => typeof e.timestamp === 'string' && !Number.isNaN(Date.parse(e.timestamp)))
  if (!events.some(e => e.id === selected)) selected = sortRows(events, 'newest').at(0)?.id ?? null
  const stats = summarize(events)
  $('badge').textContent = label(data.mode)
  $('identity').textContent = `세션 해시: ${label(session || 'unavailable')} · 턴 ID: 정보 없음 · ${data.truncated ? '일부 기록: 최근 감사 기록 2,000개' : '불러온 감사 기록의 누적 횟수이며, 같은 비밀정보의 반복 탐지를 포함합니다'}`
  $('pipeline').innerHTML = pipeline(events, guard).map(s => `<div class="stage ${s.status}"><span class="status ${s.status}">${label(s.status)}</span><strong>${s.name}</strong><small>${s.detail}</small></div>`).join('')
  $('summary').innerHTML = [['검사한 입력 수', stats.scanned], ['탐지 횟수', stats.detected], ['마스킹 횟수', stats.masked], ['파일 읽기 횟수', stats.reads], ['관찰된 도구 호출 수', stats.tools]].map(([label, value]) => `<div><strong>${metric(value)}</strong><span>${label}</span></div>`).join('')
  const timelineControls = /** @type {HTMLElement} */ ($('timeline-sort').closest('.list-controls'))
  timelineControls.hidden = !datedEvents
  const timelineEvents = sortRows(events, select('timeline-sort').value === 'oldest' ? 'oldest' : 'newest')
  $('timeline').innerHTML = events.length ? timelineEvents.map(e => `<button class="event ${e.failed ? 'failure' : ''}" data-event="${e.id}" aria-pressed="${e.id === selected}"><time>${escape(e.timestamp?.slice(11, 23))}</time><span><strong>${escape(label(e.event))}</strong><small>${escape(label(e.source))} · 탐지 ${metric(e.detected)} · 마스킹 ${metric(e.masked)}</small></span><b>${e.failed ? '오류' : '관찰됨'}</b></button>`).join('') : '<p>아직 감사 이벤트가 없습니다. 기존 PromptGuard 실행 도구를 실행해 주세요.</p>'
  for (const button of $('timeline').querySelectorAll('button')) button.addEventListener('click', () => { selected = Number(button.dataset.event); render() })
  const event = events.find(e => e.id === selected) || events.at(-1)
  $('detail').innerHTML = event ? cells([['이벤트', label(event.event)], ['출처', label(event.source)], ['훅', event.hook], ['도구', label(event.tool)], ['발생 시각 (UTC)', event.timestamp], ['검사한 입력 수', metric(event.scanned)], ['실패 단계', label(event.failureStage)], ['훅 처리 결과', event.failed ? '실패 — 실제 모델 전송 차단 여부는 미검증' : '감사 기록 저장됨']]) : '<p>이벤트를 선택하면 원문 없는 메타데이터를 확인할 수 있습니다.</p>'
  const findings = events.flatMap(e => e.findings.map((f, index) => ({ f, source: e.source, timestamp: e.timestamp, type: f.type, detector: f.detector, action: f.action, order: e.id * 1000 + index })))
  const filterFields = [['filter-type', findings.map(row => row.f.type)], ['filter-source', findings.map(row => row.source)], ['filter-detector', findings.map(row => row.f.detector)], ['filter-action', findings.map(row => row.f.action)]]
  for (const [id, values] of filterFields) {
    const control = select(id)
    const current = control.value || '*'
    const options = [...new Set((Array.isArray(values) ? values : []).filter(value => typeof value === 'string' && value.length))].sort((a, b) => a.localeCompare(b, 'ko'))
    control.innerHTML = `<option value="*">전체</option>${options.map(value => `<option value="${escape(value)}">${escape(label(value))}</option>`).join('')}`
    control.value = options.includes(current) ? current : '*'
  }
  const findingSort = select('finding-sort')
  const hasFindingTimestamps = findings.some(row => typeof row.timestamp === 'string' && !Number.isNaN(Date.parse(row.timestamp)))
  const previousSort = findingSort.value
  findingSort.innerHTML = `${hasFindingTimestamps ? '<option value="newest">최신 탐지순</option><option value="oldest">오래된 탐지순</option>' : ''}<option value="type">유형순</option><option value="source">출처순</option><option value="detector">탐지기순</option>`
  findingSort.value = [...findingSort.options].some(option => option.value === previousSort) ? previousSort : hasFindingTimestamps ? 'newest' : 'type'
  const filterIds = ['filter-type', 'filter-source', 'filter-detector', 'filter-action']
  const filtered = findings.filter(row => filterIds.every((id, i) => select(id).value === '*' || select(id).value === [row.f.type, row.source, row.f.detector, row.f.action][i]))
  const sortBy = findingSort.value
  const sortedFindings = sortBy === 'newest' || sortBy === 'oldest' ? sortRows(filtered, sortBy) : sortRows(filtered, 'asc', ({ type: 'type', source: 'source', detector: 'detector' })[sortBy] || 'type')
  $('finding-count').textContent = `탐지 결과 ${findings.length}개 · 필터 결과 ${filtered.length}개`
  $('findings').innerHTML = findings.length ? filtered.length ? sortedFindings.map(({ f, source, timestamp }) => findingMarkup(f, source, timestamp)).join('') : '<p class="empty-state">조건에 맞는 탐지 결과가 없습니다.</p>' : `<p>${stats.detected > 0 ? '탐지 횟수는 기록되어 있으나 상세 메타데이터는 제공되지 않았습니다.' : '기록된 상세 탐지 결과가 없습니다.'}</p>`
  const tools = toolActivities(events)
  const activity = e => `<article class="activity"><strong>${escape(label(e.tool))}</strong><span>${e.event === 'tool_started' ? '실행 중' : e.event === 'tool_denied' ? '거부됨' : e.event === 'tool_failed' || e.failed ? '실패' : e.toolError ? '도구 오류 결과' : '결과 수신됨'} · ${e.failed ? '검사 실패' : e.scanned === null ? '검사 횟수 정보 없음' : `입력 ${e.scanned}개 검사`}</span><small>탐지 ${metric(e.detected)} · 마스킹 ${metric(e.masked)}<br>시작: ${escape(e.started?.slice(11, 23))} · 최근: ${escape(e.timestamp?.slice(11, 23))}</small></article>`
  $('tools').innerHTML = tools.length ? tools.map(activity).join('') : '<p>기록된 도구 결과가 없습니다.</p>'
  $('files').innerHTML = tools.some(e => e.tool === 'Read' && ['scan_completed', 'audit_record'].includes(e.event)) ? tools.filter(e => e.tool === 'Read' && ['scan_completed', 'audit_record'].includes(e.event)).map(activity).join('') : '<p>기록된 파일 읽기가 없습니다.</p>'
  $('preview').innerHTML = findings.length ? `<div class="preview-rows"><div class="preview-row preview-heading"><span>유형 · 출처</span><span>변경 전 · 원문 비공개</span><span aria-hidden="true">→</span><span>변경 후</span></div>${findings.map(({ f, source }) => `<div class="preview-row"><span class="preview-meta">${escape(label(f.type))}<small>${escape(label(source))}</small></span><code>[DETECTED_SECRET]</code><span class="preview-arrow" aria-hidden="true">→</span><code>${escape(f.placeholder)}</code></div>`).join('')}</div><p class="muted">원문은 마스킹 이후 감사 기록에 저장되지 않아 이 화면에서도 복원하거나 표시할 수 없습니다.</p>` : '<p>표시할 마스킹 미리보기가 없습니다.</p>'
  if (data.mode === 'DEMO' && findings.length) $('preview').innerHTML += '<p class="tag">DEMO 구조 예시 · 실제 수집한 입력이 아닙니다</p><div class="columns"><pre>DB_HOST=localhost\nDB_PASSWORD=[DETECTED_SECRET]\nDB_PORT=5432</pre><pre>DB_HOST=localhost\nDB_PASSWORD=[PASSWORD_1]\nDB_PORT=5432</pre></div>'
  const statusClass = guard?.decision === 'SAFE' ? 'success' : guard?.decision === 'BLOCKED' ? 'blocked' : 'pending'
  const statusText = guard ? label(guard.decision) : label('NOT VERIFIED')
  for (const id of ['header-egress-status', 'egress-status']) {
    $(id).className = `status ${statusClass}`
    $(id).textContent = statusText
  }
  $('egress-summary').textContent = guard
    ? data.mode === 'DEMO' ? '가상 Final Guard 시나리오입니다.' : '선택한 세션과 동일한 session hash의 실제 Final Guard 감사 기록입니다.'
    : 'Final Guard 감사 기록이 없어 모델 전송 직전 검사 결과를 확인할 수 없습니다.'
  const guardDetails = data.mode === 'DEMO'
    ? [['검사한 입력 수', metric(guard?.scanned)], ['남아 있는 탐지 비밀정보 수', metric(guard?.remaining)], ['확인된 치환 토큰 수', metric(guard?.placeholders)], ['사유 코드', label(guard?.reason)]]
    : [['Endpoint', guard?.endpoint], ['요청 본문 크기', guard?.bodySize === null || guard?.bodySize === undefined ? '정보 없음' : `${guard.bodySize} bytes`], ['최종 탐지 수', metric(guard?.findingCount)], ['탐지 유형', guard?.findingTypes?.length ? guard.findingTypes.map(label).join(', ') : '없음'], ['검사 지연', guard?.scanLatencyMs === null || guard?.scanLatencyMs === undefined ? '정보 없음' : `${guard.scanLatencyMs} ms`], ['사유 코드', label(guard?.reason)], ['Upstream 상태', metric(guard?.upstreamStatus)], ['검사 시각 (UTC)', guard?.timestamp]]
  const guardNote = data.mode === 'DEMO'
    ? 'DEMO 데이터이며 실제 provider 전송을 증명하지 않습니다.'
    : '요청 원문, credential, authorization header는 이 화면이나 Guard audit에 포함되지 않습니다.'
  $('egress').innerHTML = guard ? `<div class="guard-card"><h3>${escape(label(guard.scope))}</h3><strong class="status ${statusClass}">${escape(statusText)}</strong>${cells(guardDetails)}<p>${escape(guardNote)}</p></div>` : `<p>${data.guardUnavailable ? 'Final Guard 감사 기록을 읽을 수 없습니다.' : '아직 연결된 Final Guard 감사 기록이 없습니다.'}</p>`
}
let generation = 0
async function refresh() {
  const current = ++generation
  if (select('mode').value === 'DEMO') {
    data = demo(select('scenario').value)
    $('notice').textContent = 'DEMO / MOCK — 가상 이벤트이며 실제 백엔드 실행 기록이 아닙니다.'
    render(); return
  }
  try {
    const response = await fetch('/api/events', { cache: 'no-store' })
    if (!response.ok) throw new Error('AUDIT_UNAVAILABLE')
    const next = await response.json()
    if (current !== generation) return
    data = next
    $('notice').textContent = '실제 기록 · Native Mod와 Final Guard의 raw-free 로컬 감사 기록 · 2초마다 갱신'
    render()
  } catch {
    if (current !== generation) return
    data = { mode: 'LIVE', events: [], guards: [], guard: null }
    $('notice').textContent = '감사 기록을 읽을 수 없습니다. 완전한 기록 파일을 기다리는 중이며 안전 여부를 판정할 수 없습니다.'
    render()
  }
}
$('mode').addEventListener('change', () => { selected = null; $('scenario-label').hidden = select('mode').value !== 'DEMO'; refresh() })
$('scenario').addEventListener('change', () => { selected = null; refresh() })
$('session').addEventListener('change', () => { session = select('session').value; selected = null; render() })
for (const id of ['timeline-sort', 'finding-sort', 'filter-type', 'filter-source', 'filter-detector', 'filter-action']) $(id).addEventListener('change', render)
$('clear-filters').addEventListener('click', () => {
  for (const id of ['filter-type', 'filter-source', 'filter-detector', 'filter-action']) select(id).value = '*'
  select('finding-sort').value = [...select('finding-sort').options].some(option => option.value === 'newest') ? 'newest' : 'type'
  render()
})
await refresh()
setInterval(() => { if (select('mode').value === 'LIVE') refresh() }, 2000)
