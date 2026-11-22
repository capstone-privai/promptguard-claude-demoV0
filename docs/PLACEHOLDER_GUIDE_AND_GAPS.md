# 자리표시자 안내, 이스케이프 복원, count_tokens·시스템 프롬프트 빈틈

정우의 지표 2 gold 결과(161개 과제, Claude Code 2.1.319, PromptGuard cca44c4, 과제당 1회)에서 나온 문제를 다룬다.

- **마스킹 때문에 멈춘 과제:**
  - g29: 붙여 넣은 키가 `[SECRET_1]`로 도착해 모델이 멈췄다.
  - t14: Grep 패턴에 `\[TOKEN_1\]`을 써서 복원이 0건이었다.
  - t12: 비밀번호의 `$`가 버그 원인인데 모델이 볼 수 없었다.
- **성공했지만 잘못 보고한 과제:** 10건이 자리표시자를 "파일에 적힌 가짜 문자열"이라고 사용자에게 보고했다.
- **gold에서도 서버로 간 비밀 27/595:** 두 경로가 있었다.
  - (가) count_tokens 요청
  - (나) `--append-system-prompt`

## (가) count_tokens: Mod 훅으로 잡을 수 없다

Claude Code 2.1.291(고정 버전), 2.1.312, 2.1.319(정우의 측정 엔진)의 엔진 코드를 확인했다.

- **Read 도구:** 파일 내용을 돌려주기 전에 크기를 검사한다. 추정 토큰이 한도(`CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS`, 기본 25,000)의 1/4을 넘으면, **원본 내용 그대로** `/v1/messages/count_tokens`를 보내 정확한 수를 센다. 3만~4만 자 출력이 이 구간이다.
- **MCP 도구:** 큰 출력도 같은 방식으로 센다.
- **Mod가 못 잡는 이유:** 이 요청은 도구 실행 안에서 나간다. 즉 Mod의 `tool.call` 훅이 결과를 받기 전이다. Mod API에는 API 요청 전체를 바꾸는 훅이 없다. `session.measure`는 사용량을 알려 주기만 하고, `session.send`는 에이전트끼리의 메시지다. 그래서 Mod로는 이 요청을 가릴 수 없다.
- **막을 수 있는 곳:** Final Guard다(`promptguard run`). Guard는 count_tokens 본문도 검사하고, 비밀이 있으면 422로 막는다.
  - 엔진은 count_tokens가 실패하면 로컬 추정값으로 넘어간다.
  - 실제 엔진에서 Guard가 count_tokens를 막아도 세션이 계속되고, 가린 파일이 모델에 도착하는 것을 확인했다(`tests/e2e/gaps.mjs`).
- **metric-task:** `m2.py`는 Final Guard 없이 Mod만으로 돌리므로, 이 경로는 측정에서 계속 새어 나간다.

### count_tokens가 막힌 뒤 Read가 하는 일

Read의 크기 검사는 이렇게 동작한다. 2.1.319 코드를 읽었고, 2.1.291과 2.1.319 모두 실제 엔진으로 확인했다.

1. 로컬 추정 토큰 수가 한도(25,000)의 1/4 이하이면 count_tokens를 보내지 않는다.
2. 그보다 크면 count_tokens를 보낸다. 실패하면(Guard의 422 포함) 오류 없이 **로컬 추정값을 대신 쓴다**.
3. 그 수가 한도 이하이면 파일 전체를 돌려준다.
4. 한도를 넘으면 거절하지 않는다. 한도에 맞춰 앞부분만 돌려주고 "PARTIAL view … showing N of M lines" 안내를 붙인다. 오류("exceeds maximum allowed tokens")로 거절하는 것은 count_tokens 전에, 파일이 한도 × 128자(약 320만 자)를 넘을 때뿐이다.

| 파일 | Mod만 | Guard block | Guard mask |
|---|---|---|---|
| 3만 6천 자 (한도 아래) | 전체 | 전체 (로컬 추정값으로 판단) | 전체 |
| 13만 자 (한도 위) | 1,398 / 2,177줄 + 안내 | 1,422 / 2,177줄 + 안내 | 1,398 / 2,177줄 + 안내 |

- 줄 수의 차이는 어떤 수로 판단했느냐에서 나온다. block은 엔진의 로컬 추정값을, Mod만·mask는 서버가 센 수를 쓴다. 이 시험의 서버 수는 가짜(본문 글자 수 / 4)다. 실제 API에서는 차이의 크기와 방향이 다를 수 있다.
- 어느 경우든 Read 결과는 `tool.call` 훅에서 Mod가 가린 뒤 본 요청에 들어갔다. 본 요청의 Read 결과에는 자리표시자만 있었고 원래 값은 없었다.
- `tests/e2e/gaps.mjs`가 확인한다. 2.1.291과 2.1.319가 같았다.

### `PG_GUARD_COUNT_TOKENS=block|mask` (기본 block)

- **block:** 지금까지처럼 count_tokens에서 비밀이 나오면 422로 막는다. 엔진은 로컬 추정값을 쓴다.
- **mask:** count_tokens 요청에 한해 탐지한 값을 자리표시자로 바꿔 보낸다. 응답이 토큰 수뿐이라 내용은 돌아오지 않는다.
  - 탐지기의 span으로 값을 `[TYPE_N]`으로 바꾼다. 같은 값은 같은 자리표시자가 되고, 번호는 요청 안 문서 순서를 따른다. 다른 문자열과 JSON 모양은 그대로다.
  - 바꾼 본문을 다시 검사한다. 다시 검사할 때 새로 나온 값도 같은 방식으로 가리고, 세 번 안에 깨끗해지지 않으면 422로 막는다.
  - 감사 로그: `decision: allow`, `reason: COUNT_TOKENS_MASKED`, `finding_count`는 가린 값 수. 스키마는 바뀌지 않는다.
  - `/v1/messages`는 mask여도 지금처럼 막는다.
  - 다른 값이면 Guard가 시작하지 않는다.
- **차이:**
  - block에서는 엔진이 로컬 추정값으로 판단하고, mask에서는 서버가 센 수(가린 본문 기준)로 판단한다.
  - 가린 본문은 원래보다 조금 짧다(값 길이와 자리표시자 길이의 차이만큼).
  - 두 설정 모두 세션은 계속된다. 다만 한도 근처에서 로컬 추정값과 서버 수가 한도의 다른 쪽에 있으면, 한쪽은 전체를 읽고 다른 쪽은 부분만 읽는다. 한도를 넘은 파일은 부분 읽기의 줄 수가 달라진다(위 표: 1,422줄과 1,398줄).
  - 토큰 수(가짜 서버 수): 3만 6천 자 파일은 Mod만 9,208, mask 9,203이었다. 13만 자 파일은 Mod만 33,087, mask 33,081이었다. block에서는 서버가 세지 않는다.

## (다) 엔진이 직접 조립하는 다른 컨텍스트

`tests/e2e/contexts.mjs`가 소스마다 합성 비밀 하나를 넣고 네 번 돌린다: 실험용 Mod(훅에 보이는지, 기록만 함), Mod만, Mod+Guard, Guard만(Mod 없음).

| 소스 | 요청에서 들어가는 곳 | (a) 값을 실은 훅 | (b) Mod만: 서버로 감 | Mod+Guard | (c) Guard만: 세션 계속 |
|---|---|---|---|---|---|
| CLAUDE.md (프로젝트) | `messages` | prompt.context, prompt.attachment | 안 감 | 계속, 차단 0 | 멈춤 |
| CLAUDE.md (사용자, `CLAUDE_CONFIG_DIR`) | `messages` | prompt.context, prompt.attachment | 안 감 | 계속, 차단 0 | 멈춤 |
| CLAUDE.local.md | `messages` | prompt.context, prompt.attachment | 안 감 | 계속, 차단 0 | 멈춤 |
| CLAUDE.md의 `@파일` import | `messages` | prompt.context, prompt.attachment | 안 감 | 계속, 차단 0 | 멈춤 |
| 출력 스타일 (`outputStyle`) | `messages` | prompt.attachment | 안 감 | 계속, 차단 0 | 멈춤 |
| 스킬 본문 (Skill 도구 호출) | `messages` | skill.prompt | 안 감 | 계속, 차단 0 | 멈춤 |
| 스킬 설명 (목록) | `messages` | prompt.attachment | 안 감 | 계속, 차단 0 | 멈춤 |
| 슬래시 명령 파일 | `messages` | prompt.attachment, skill.prompt | 안 감 | 계속, 차단 0 | 멈춤 |
| MCP 서버 instructions | `messages` | prompt.attachment | 안 감 | 계속, 차단 0 | 멈춤 |

(모든 소스가 `session.append`에도 실린다.) 2.1.291과 2.1.319가 같았다.

- 아홉 소스 모두 훅에 보이고 Mod가 가린다. 그래서 런처에서 따로 가릴 경로는 없다. 훅에 안 보이는 것은 지금까지 확인한 `--system-prompt`·`--append-system-prompt`(와 `-file` 형태)뿐이다.
- Mod 없이 Guard만 있으면 매 요청이 같은 값을 실어 모두 막히고, 세션은 첫 응답을 받지 못한 채 "API Error: 422 PromptGuard blocked sensitive content before transmission."으로 끝난다. 2.1.291은 한 번, 2.1.319는 같은 요청을 다섯 번 더 보낸 뒤 끝난다(6번 차단).

## (라) 런처 없이 `--append-system-prompt`로 띄웠을 때

`claude --append-system-prompt "<비밀>"`을 런처 없이 Guard 앞에서 띄우면 매 요청이 막힌다. 고치기 전에는 사용자가 "API Error: 422 PromptGuard blocked sensitive content before transmission."만 보았다. 무엇을 해야 하는지 알 수 없었다.

이제 막힌 값이 요청의 `system`에 있으면 다음 메시지를 보낸다(오류 코드와 감사 로그의 `reason`은 그대로 `DETECTOR_FINDINGS`).

> PromptGuard blocked sensitive content in the system prompt before transmission. If it came from --system-prompt, --append-system-prompt or their -file forms, start Claude Code with `promptguard run -- <claude arguments>` so those values are masked before Claude Code starts.

Guard는 `system` 아래 문자열을 먼저 검사한다. 그래서 다른 곳에도 비밀이 있어 검사를 일찍 멈추더라도, `system`에서 나온 것은 놓치지 않는다.

## (나) 시스템 프롬프트: 런처에서 가린다

- **훅에 보이지 않는다:** 실험용 Mod로 2.1.291과 2.1.312를 확인했다. `--append-system-prompt`와 `--system-prompt`의 내용은 어떤 Mod 훅(`prompt.compose`, `prompt.section`, `prompt.context`, `prompt.submit`, `prompt.attachment`)에도 보이지 않고, API 요청의 `system`에만 들어간다. `--system-prompt`를 주면 `prompt.compose` 자체가 불리지 않는다.
- **런처가 대신 가린다:** Claude Code를 띄우기 전에 `src/launcher/system-prompt.cjs`가 아래 네 옵션의 값을 탐지기로 검사해 Mod와 같은 형식의 자리표시자로 바꾼다.
  - `--system-prompt`, `--append-system-prompt`, `--system-prompt-file`, `--append-system-prompt-file`
  - `-file` 옵션은 사용자 파일을 바꾸지 않는다. 가린 사본을 런타임 폴더에 만들어 그 경로를 넘긴다.
- **대응표:** 자리표시자, 원래 값, 값 해시를 시드 파일(권한 0600)에 적는다. Mod는 첫 검사 때 이것을 읽고 비운다.
  - 같은 값이 다른 곳에 나와도 같은 자리표시자가 된다.
  - 번호가 이어지고, 도구 입력에서 복원된다.
- **실패하면 막는다:** 검사가 실패하면 Claude Code를 띄우지 않는다. Mod가 시드 파일을 읽지 못해도 막는다. 시스템 프롬프트가 이미 쓴 번호를 다른 값에 줄 수 있기 때문이다.
- **사용:** `promptguard run`은 자동으로 거친다. Claude Code를 직접 띄우는 실행기(metric-task `m2.py`)는 명령줄로 부를 수 있다.

```bash
node src/launcher/system-prompt.cjs --detector-url http://127.0.0.1:PORT --seed-file RUN_DIR/seed.json -- <claude 인자...>
# 가린 인자를 JSON 배열로 출력한다. 시드를 썼으면 Claude Code에 PG_MOD_SEED_FILE=RUN_DIR/seed.json을 준다.
```

이 두 빈틈은 보안 수정이라 설정 없이 항상 켜져 있다.

## `PG_PLACEHOLDER_GUIDE=on|off` (기본 on, release/defaults-1120부터): 자리표시자 안내

켜면 `prompt.compose` 훅이 시스템 프롬프트 끝에 짧은 안내(`promptguard:placeholder-guide`, scope `session`)를 붙인다.

**내용:**
- `[TYPE_N]`은 PromptGuard가 가린 실제 값이다.
- Bash, PowerShell, Edit, MultiEdit, Write, NotebookEdit, Grep 입력에 쓰면 실행 직전에 실제 값으로 바뀐다. 다른 도구에는 적은 그대로 간다.
- 값을 다시 달라고 하거나, 파일에 가짜 문자열이 있다고 보고하지 않는다.
- 값의 속성이 필요하면 자리표시자를 넣은 로컬 명령으로 확인하되, 값을 출력하지 않는다.

**작성 원칙:**
- 도구 목록은 코드의 `RESTORE_TOOLS`에서 만든다. 그래서 복원하지 않는 도구를 안내할 일이 없다.
- 예시에는 숫자를 쓰지 않는다(`[PASSWORD_N]`). 그래서 안내문이 자리표시자로 복원되지 않는다.
- 안내문은 탐지기에 보내지 않아 가려지지 않는다.

**`prompt.compose`에 넣은 이유:**
- **매 요청에 정확히 한 번 들어간다:** 시스템 프롬프트는 매 요청 다시 만들어지기 때문이다. 첫 사용자 메시지에 넣으면 대화 기록과 대화록에 남고, 압축(compaction)될 때 사라질 수 있다.
- **캐시된다:** 시스템 프롬프트는 프롬프트 캐시에 들어가므로, 같은 세션의 두 번째 요청부터는 캐시 읽기로 계산된다.

**토큰 비용:**
- 안내문은 998자(약 240토큰)이고, `PG_RESTORE_ESCAPED=on`(기본)이면 1,134자(약 270토큰)다. fix/secret-dump-guard에서 덤프하지 말라는 문장(371자, 약 90토큰)이 늘었다. 토큰은 글자 수로 어림한 값이다(실제 토크나이저로 세지 않음).
- 요청마다 반복된다. 대부분 캐시 읽기(입력 단가의 약 10%)로 계산되고, 첫 요청과 캐시가 만료된 뒤에만 캐시 쓰기로 계산된다.

**한계:** `--system-prompt`를 쓰면 `prompt.compose`가 불리지 않아 안내문도 들어가지 않는다.

## `PG_RESTORE_ESCAPED=on|off` (기본 on, release/defaults-1120부터): 이스케이프 복원

정규식으로 이스케이프한 자리표시자 `\[TYPE_N\]`을, 같은 정규식 문법으로 이스케이프한 실제 값으로 복원한다.

| 자리 | 정규식 문법 |
|---|---|
| Grep 도구의 `pattern` | ripgrep (ERE) |
| Bash의 `grep` | BRE. `-E`·`-P`면 ERE, `-F`면 이스케이프 없이 그대로 |
| Bash의 `egrep` / `fgrep` | ERE / 그대로 |
| Bash의 `rg` | ERE. `-F`면 그대로 |
| Bash의 `sed` | BRE. `-E`·`-r`이면 ERE. 기본 구분자 `/`도 이스케이프 |

- **셸 따옴표:** Bash에서는 자리표시자가 놓인 셸 따옴표에 맞춰 한 번 더 이스케이프한다.
  - 작은따옴표 안의 `'`
  - 큰따옴표 안의 `\` `$` `` ` `` `"`
  - 따옴표 밖의 특수문자
- **복원하지 않는 것:**
  - 대괄호 없는 `TYPE_N`. 코드 식별자와 겹치기 때문이다.
  - grep·rg·sed가 아닌 명령 안의 `\[TYPE_N\]`
- **감사 로그:** 복원 수는 기존처럼 `tool_started` 행의 `restored_count`에 더한다. 값은 남기지 않는다.
- **한계:**
  - 셸 해석은 따옴표와 `|` `;` `&` 줄바꿈 구분만 보는 작은 검사기다.
  - sed의 `s|...|` 같은 다른 구분자와 치환 쪽(`s/x/\[T\]/`)의 이스케이프는 다루지 않는다.

## 다음 과제

- 값 속성 조회 도구(정우 수정안 3)는 이번 범위가 아니다.
