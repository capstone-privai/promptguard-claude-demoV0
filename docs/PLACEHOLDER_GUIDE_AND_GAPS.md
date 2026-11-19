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

Claude Code 2.1.291(고정 버전)과 2.1.312의 엔진 코드를 확인했다. 2.1.319는 이 PC에 없고, 외부에서 받지 않았다.

- **Read 도구:** 파일 내용을 돌려주기 전에 크기를 검사한다. 추정 토큰이 한도(`CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS`, 기본 25,000)의 1/4을 넘으면, **원본 내용 그대로** `/v1/messages/count_tokens`를 보내 정확한 수를 센다. 3만~4만 자 출력이 이 구간이다.
- **MCP 도구:** 큰 출력도 같은 방식으로 센다.
- **Mod가 못 잡는 이유:** 이 요청은 도구 실행 안에서 나간다. 즉 Mod의 `tool.call` 훅이 결과를 받기 전이다. Mod API에는 API 요청 전체를 바꾸는 훅이 없다. `session.measure`는 사용량을 알려 주기만 하고, `session.send`는 에이전트끼리의 메시지다. 그래서 Mod로는 이 요청을 가릴 수 없다.
- **막을 수 있는 곳:** Final Guard다(`promptguard run`). Guard는 count_tokens 본문도 검사하고, 비밀이 있으면 422로 막는다.
  - 엔진은 count_tokens가 실패하면 로컬 추정값으로 넘어간다.
  - 실제 엔진에서 Guard가 count_tokens를 막아도 세션이 계속되고, 가린 파일이 모델에 도착하는 것을 확인했다(`tests/e2e/gaps.mjs`).
- **metric-task:** `m2.py`는 Final Guard 없이 Mod만으로 돌리므로, 이 경로는 측정에서 계속 새어 나간다.

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

## `PG_PLACEHOLDER_GUIDE=on|off` (기본 off): 자리표시자 안내

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
- 안내문은 627자(약 150토큰)이고, `PG_RESTORE_ESCAPED=on`이면 763자(약 180토큰)다.
- 요청마다 반복된다. 대부분 캐시 읽기(입력 단가의 약 10%)로 계산되고, 첫 요청과 캐시가 만료된 뒤에만 캐시 쓰기로 계산된다.

**한계:** `--system-prompt`를 쓰면 `prompt.compose`가 불리지 않아 안내문도 들어가지 않는다.

## `PG_RESTORE_ESCAPED=on|off` (기본 off): 이스케이프 복원

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
