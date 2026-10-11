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
export const escape = value => String(value ?? '정보 없음').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
export const metric = value => value === null || value === undefined ? '정보 없음' : String(value)
export function findingMarkup(f, source, timestamp = null) {
  const location = f.unit && f.start !== null && f.end !== null ? `입력 ${metric(f.payload)} · 위치 ${f.start}–${f.end} (UTF-16 코드 단위, 끝 위치 제외)` : '위치 정보 없음'
  return `<article class="finding"><strong>${escape(label(f.type))}</strong><span class="tag">${escape(label(source))}</span><dl><dt>탐지기</dt><dd>${escape(f.detector)}</dd><dt>탐지 규칙</dt><dd>${escape(f.rule)}</dd><dt>적용 조치</dt><dd>${escape(label(f.action))}</dd><dt>발견 위치</dt><dd>${escape(location)}</dd><dt>검사 기록 시각</dt><dd>${escape(timestamp)}</dd></dl><p class="muted">${f.rule ? '탐지기가 보고한 규칙입니다. MASK는 실제 적용된 마스킹 조치를 뜻합니다.' : '사유 메타데이터가 제공되지 않았습니다.'}</p></article>`
}

export function sortRows(rows, direction = 'newest', key = 'timestamp') {
  const sign = direction === 'oldest' ? 1 : -1
  return rows.map((row, index) => ({ row, index })).sort((a, b) => {
    const av = a.row[key]
    const bv = b.row[key]
    const aTime = typeof av === 'string' && !Number.isNaN(Date.parse(av)) ? Date.parse(av) : null
    const bTime = typeof bv === 'string' && !Number.isNaN(Date.parse(bv)) ? Date.parse(bv) : null
    if (key === 'timestamp') {
      if (aTime === null || bTime === null) return aTime === bTime ? a.index - b.index : aTime === null ? 1 : -1
      return (aTime - bTime) * sign || a.index - b.index
    }
    const result = String(av ?? '').localeCompare(String(bv ?? ''), 'ko') * (direction === 'desc' ? -1 : 1)
    return result || a.index - b.index
  }).map(item => item.row)
}
export function pipeline(events, demoDecision = null) {
  const activities = toolActivities(events)
  const toolStatus = activities.some(e => e.event === 'tool_started') ? 'running' : activities.some(e => e.event === 'tool_denied') ? 'blocked' : activities.some(e => e.failed || e.event === 'tool_failed') ? 'error' : activities.length ? 'success' : 'pending'
  const has = source => events.some(e => e.source === source && !e.failed)
  const stage = (name, status, detail) => ({ name, status, detail })
  return [stage('사용자 프롬프트', has('USER_PROMPT') ? 'success' : 'pending', '프롬프트 검사 기록'), stage('에이전트 / 도구', toolStatus, '도구 실행 과정'), stage('탐지기', events.some(e => e.failureStage === 'detector') ? 'error' : events.some(e => e.scanned > 0) ? 'success' : 'pending', '로컬 검사 기록'), stage('마스킹', events.some(e => e.failureStage === 'sanitizer') ? 'error' : events.some(e => e.masked > 0) ? 'success' : 'pending', '실제 적용한 치환'), stage('외부 전송 검사', demoDecision === 'SAFE' ? 'success' : demoDecision === 'BLOCKED' ? 'blocked' : 'pending', demoDecision ? '데모 결과' : '미검증 (NOT VERIFIED)'), stage('클라우드 모델', 'pending', '실제 전송 기록 없음')]
}

// Display labels only: audit codes, rule IDs and replacement tokens stay unchanged.
const labels = {
  pending: '대기', running: '실행 중', success: '완료', blocked: '차단', error: '오류',
  SAFE: '안전 (SAFE)', BLOCKED: '차단 (BLOCKED)', 'NOT VERIFIED': '미검증 (NOT VERIFIED)',
  LIVE: '실제 기록', DEMO: '데모 (DEMO)', unavailable: '정보 없음', 'DEMO SESSION': '데모 세션',
  USER_PROMPT: '사용자 프롬프트 (USER_PROMPT)', FILE_READ: '파일 읽기 (FILE_READ)',
  TOOL_OUTPUT: '도구 출력 (TOOL_OUTPUT)', HISTORY: '대화 이력 (HISTORY)',
  AGENTS_CONTEXT: '에이전트 문맥 (AGENTS_CONTEXT)', FINAL_REQUEST: '최종 요청 (FINAL_REQUEST)', UNKNOWN: '알 수 없음 (UNKNOWN)',
  scan_completed: '검사 완료 (scan_completed)', scan_failed: '검사 실패 (scan_failed)',
  tool_started: '도구 실행 시작 (tool_started)', tool_failed: '도구 실행 실패 (tool_failed)',
  tool_denied: '도구 실행 거부 (tool_denied)', audit_record: '감사 기록 (audit_record)',
  PASSWORD: '비밀번호 (PASSWORD)', API_KEY: 'API 키 (API_KEY)', TOKEN: '토큰 (TOKEN)',
  PRIVATE_KEY: '개인 키 (PRIVATE_KEY)', AWS_KEY: 'AWS 키 (AWS_KEY)', GITHUB_TOKEN: 'GitHub 토큰 (GITHUB_TOKEN)',
  SLACK_TOKEN: 'Slack 토큰 (SLACK_TOKEN)', JWT: 'JWT 토큰', SECRET: '비밀정보 (SECRET)', CREDENTIAL: '인증정보 (CREDENTIAL)',
  MASK: '마스킹 (MASK)', detector: '탐지기 (detector)', sanitizer: '마스킹 처리 (sanitizer)',
  Read: 'Read · 파일 읽기', Grep: 'Grep · 내용 검색', Bash: 'Bash · 셸 실행', Agent: 'Agent · 에이전트',
  'MCP tool': 'MCP 도구', 'Other tool': '기타 도구',
  'VALIDATION MOCK — not a Cloud provider': '검증용 모의 Guard — 실제 클라우드 모델이 아닙니다',
  'DEMO — synthetic UI scenario': 'DEMO — 가상 화면 시나리오',
  'Synthetic failure scenario': '가상 실패 시나리오',
}
export const label = value => labels[value] ?? value ?? '정보 없음'
