import { summarize, escape, metric, findingMarkup, pipeline, toolActivities, label } from './view.mjs'
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
  $('session').innerHTML = sessions.length ? sessions.map(s => `<option ${s === session ? 'selected' : ''} value="${escape(s)}">${escape(s === 'DEMO SESSION' || s === 'unavailable' ? label(s) : s.slice(0, 12))}</option>`).join('') : '<option>세션 없음</option>'
  const events = data.events.filter(e => e.session === session).sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || '') || a.id - b.id)
  if (!events.some(e => e.id === selected)) selected = events.at(-1)?.id ?? null
  const stats = summarize(events)
  $('badge').textContent = label(data.mode)
  $('identity').textContent = `세션 해시: ${label(session || 'unavailable')} · 턴 ID: 정보 없음 · ${data.truncated ? '일부 기록: 최근 감사 기록 2,000개' : '불러온 감사 기록의 누적 횟수이며, 같은 비밀정보의 반복 탐지를 포함합니다'}`
  $('pipeline').innerHTML = pipeline(events, data.mode === 'DEMO' ? data.guard?.decision : null).map(s => `<div class="stage ${s.status}"><span class="status ${s.status}">${label(s.status)}</span><strong>${s.name}</strong><small>${s.detail}</small></div>`).join('')
  $('summary').innerHTML = [['검사한 입력 수', stats.scanned], ['탐지 횟수', stats.detected], ['마스킹 횟수', stats.masked], ['파일 읽기 횟수', stats.reads], ['관찰된 도구 호출 수', stats.tools]].map(([label, value]) => `<div><strong>${metric(value)}</strong><span>${label}</span></div>`).join('')
  $('timeline').innerHTML = events.length ? events.map(e => `<button class="event ${e.failed ? 'failure' : ''}" data-event="${e.id}" aria-pressed="${e.id === selected}"><time>${escape(e.timestamp?.slice(11, 23))}</time><span><strong>${escape(label(e.event))}</strong><small>${escape(label(e.source))} · 탐지 ${metric(e.detected)} · 마스킹 ${metric(e.masked)}</small></span><b>${e.failed ? '오류' : '관찰됨'}</b></button>`).join('') : '<p>아직 감사 이벤트가 없습니다. 기존 PromptGuard 실행 도구를 실행해 주세요.</p>'
  for (const button of $('timeline').querySelectorAll('button')) button.addEventListener('click', () => { selected = Number(button.dataset.event); render() })
  const event = events.find(e => e.id === selected) || events.at(-1)
  $('detail').innerHTML = event ? cells([['이벤트', label(event.event)], ['출처', label(event.source)], ['훅', event.hook], ['도구', label(event.tool)], ['발생 시각 (UTC)', event.timestamp], ['검사한 입력 수', metric(event.scanned)], ['실패 단계', label(event.failureStage)], ['훅 처리 결과', event.failed ? '실패 — 실제 모델 전송 차단 여부는 미검증' : '감사 기록 저장됨']]) : '<p>이벤트를 선택하면 원문 없는 메타데이터를 확인할 수 있습니다.</p>'
  const findings = events.flatMap(e => e.findings.map(f => ({ f, source: e.source })))
  $('findings').innerHTML = findings.length ? findings.map(({ f, source }) => findingMarkup(f, source)).join('') : `<p>${stats.detected > 0 ? '탐지 횟수는 기록되어 있으나 상세 메타데이터는 제공되지 않았습니다.' : '기록된 상세 탐지 결과가 없습니다.'}</p>`
  const tools = toolActivities(events)
  const activity = e => `<article class="activity"><strong>${escape(label(e.tool))}</strong><span>${e.event === 'tool_started' ? '실행 중' : e.event === 'tool_denied' ? '거부됨' : e.event === 'tool_failed' || e.failed ? '실패' : e.toolError ? '도구 오류 결과' : '결과 수신됨'} · ${e.failed ? '검사 실패' : e.scanned === null ? '검사 횟수 정보 없음' : `입력 ${e.scanned}개 검사`}</span><small>탐지 ${metric(e.detected)} · 마스킹 ${metric(e.masked)}<br>시작: ${escape(e.started?.slice(11, 23))} · 최근: ${escape(e.timestamp?.slice(11, 23))}</small></article>`
  $('tools').innerHTML = tools.length ? tools.map(activity).join('') : '<p>기록된 도구 결과가 없습니다.</p>'
  $('files').innerHTML = tools.some(e => e.tool === 'Read' && ['scan_completed', 'audit_record'].includes(e.event)) ? tools.filter(e => e.tool === 'Read' && ['scan_completed', 'audit_record'].includes(e.event)).map(activity).join('') : '<p>기록된 파일 읽기가 없습니다.</p>'
  $('preview').innerHTML = findings.length ? '<div class="columns"><div><h3>변경 전 · 비밀정보 숨김</h3><pre>' + findings.map(() => '[DETECTED_SECRET]').join('\n') + '</pre></div><div><h3>변경 후 · 치환 토큰</h3><pre>' + findings.map(({ f }) => escape(f.placeholder)).join('\n') + '</pre></div></div>' : '<p>표시할 마스킹 미리보기가 없습니다.</p>'
  if (data.mode === 'DEMO' && findings.length) $('preview').innerHTML += '<p class="tag">DEMO 구조 예시 · 실제 수집한 입력이 아닙니다</p><div class="columns"><pre>DB_HOST=localhost\nDB_PASSWORD=[DETECTED_SECRET]\nDB_PORT=5432</pre><pre>DB_HOST=localhost\nDB_PASSWORD=[PASSWORD_1]\nDB_PORT=5432</pre></div>'
  const guard = data.guard
  $('egress').innerHTML = guard ? `<div class="mock"><h3>${escape(label(guard.scope))}</h3><strong class="status ${guard.decision === 'SAFE' ? 'success' : guard.decision === 'BLOCKED' ? 'blocked' : 'pending'}">${escape(label(guard.decision))}</strong>${cells([['검사한 입력 수', metric(guard.scanned)], ['남아 있는 탐지 비밀정보 수', metric(guard.remaining)], ['확인된 치환 토큰 수 (마스킹 횟수와 다름)', metric(guard.placeholders)], ['사유 코드', label(guard.reason)]])}<p>별도 검증 기록으로, 선택한 실제 세션과 연결된 결과가 아닙니다. 클라우드 전송 여부를 증명하지 않습니다.</p></div>` : `<p>${data.guardUnavailable ? '지정한 모의 Guard 기록을 읽을 수 없습니다.' : '외부 전송 검사 정보 없음 · 최종 요청 검증 데이터가 없습니다.'}</p>`
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
    $('notice').textContent = '실제 기록 · 로컬 감사 기록 · 2초마다 갱신 · 모델 제공자에게 보내는 외부 전송은 미검증'
    render()
  } catch {
    if (current !== generation) return
    data = { mode: 'LIVE', events: [], guard: null }
    $('notice').textContent = '감사 기록을 읽을 수 없습니다. 완전한 기록 파일을 기다리는 중이며 안전 여부를 판정할 수 없습니다.'
    render()
  }
}
$('mode').addEventListener('change', () => { selected = null; $('scenario-label').hidden = select('mode').value !== 'DEMO'; refresh() })
$('scenario').addEventListener('change', () => { selected = null; refresh() })
$('session').addEventListener('change', () => { session = select('session').value; selected = null; render() })
await refresh()
setInterval(() => { if (select('mode').value === 'LIVE') refresh() }, 2000)
