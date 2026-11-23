# PromptGuard Claude Demo V0

Claude Code 2.1.291 Native Mod와 여러 detector 모듈(CredSweeper 1.19.0, Gitleaks, 자체 룰)의 합의 판정을 이용해 prompt/context/tool output의 credential **값만** placeholder로 바꾸는 Windows/macOS용 portable demo입니다. 기본 설정(`candidate_policy: "union"`)에서는 Shell-aware adapter를 포함한 모든 모듈의 합집합을 마스킹합니다.

> 이 저장소의 password, API key, token, PEM은 모두 비기능 synthetic fixture입니다. 실제 credential은 포함하지 않습니다.

## 준비물

- Windows PowerShell 5.1 이상 또는 macOS의 Bash
- Python 3.12 또는 3.14 (PATH 등록). Windows 설치 스크립트(`install.ps1`)는 3.12와 3.14를 모두 찾고, macOS `install.sh`는 3.12를 찾습니다. `promptguard run`은 둘 중 어느 버전으로 만든 `.venv`도 사용합니다.
- Node.js LTS
- macOS: Xcode Command Line Tools (`xcode-select --install`)
- Claude Code 2.1.291 (기본 설정은 이 버전만 허용합니다. 다른 버전은 아래 [버전 고정](#claude-code-버전-고정) 참고)
- 선택: Gitleaks 8.x (`brew install gitleaks`, Windows는 `scoop install gitleaks` 또는 GitHub release). 없으면 gitleaks 모듈만 건너뜁니다.
- Claude Pro/Max/Team/Enterprise 계정 또는 Anthropic Console billing

Claude Code가 없다면:

```powershell
npm install -g @anthropic-ai/claude-code@2.1.291
```

## 1. 설치

### Windows

저장소를 clone한 뒤 실행합니다. `.cmd` wrapper가 현재 PowerShell execution policy를 영구 변경하지 않고 설치 스크립트를 실행합니다.

```powershell
git clone https://github.com/capstone-privai/promptguard-claude-demoV0.git
cd promptguard-claude-demoV0
.\install.cmd
```

설치 시 repository-local `.venv`에 `credsweeper==1.19.0`을 고정 설치합니다.
`py -3.12`, `py -3.14` 또는 PATH의 `python`을 자동 탐색합니다. 별도 Python 경로를 써야 한다면 `PROMPTGUARD_PYTHON` 환경 변수에 `python.exe` 경로를 지정할 수 있습니다.

### macOS

```bash
git clone https://github.com/capstone-privai/promptguard-claude-demoV0.git
cd promptguard-claude-demoV0
chmod +x install.sh
./install.sh
```

Python 3.12나 Node.js가 없다면 Homebrew를 사용하는 환경에서는 `brew install python@3.12 node`로 설치할 수 있습니다. 별도 Python 경로를 사용하려면 `PROMPTGUARD_PYTHON=/path/to/python3.12 ./install.sh`처럼 지정합니다. 설치 스크립트가 `promptguard`와 기존 launcher에 실행 권한을 설정합니다.

## 2. 권장 실행: Runtime V1 + Final Guard

Runtime V1은 아래 순서로 보호 서비스를 준비한 뒤에만 Claude Code를 실행합니다.

1. Native Mod 변환용 detector worker
2. Final Guard 검증용 독립 detector worker
3. loopback Final Transmission Guard
4. `ANTHROPIC_BASE_URL`이 Guard로 고정된 Claude Code

Windows:

```powershell
cd sample-protected-project
..\promptguard.cmd run
```

macOS:

```bash
cd sample-protected-project
../promptguard run
```

> PromptGuard 훅과 Final Guard는 `promptguard run`이 Claude Code를 띄울 때 실행 옵션(`--plugin-dir`, `--mcp-config`, `ANTHROPIC_BASE_URL`)으로 붙입니다. 보호 프로젝트 폴더에서 `claude`를 직접 실행하면 아무 보호도 적용되지 않습니다. 보호 중이면 시작할 때 `✓ Final Guard ready`와 `Protection active`가 출력됩니다.

Claude 인수를 넘길 때는 `--` 뒤에 적습니다. 예: `../promptguard run -- --resume`. Claude 로그인 없이 서비스만 검증하려면 `--no-claude`를 사용하고, 다른 터미널에서 `../promptguard status` 또는 `..\promptguard.cmd status`로 raw-free 상태와 차단 counter를 확인할 수 있습니다.

기본 설정은 repository의 `promptguard.config.json`이며 `--config FILE`로 바꿀 수 있습니다. strict schema이므로 오타나 알 수 없는 필드는 시작 전에 거부합니다.

### Claude Code 버전 고정

기본 설정은 Claude Code 버전이 `2.1.291`과 정확히 일치해야 Claude를 시작합니다. 다른 버전(예: 2.1.296)으로 실행하려면 `promptguard.config.json`을 복사해 `"strictClaudeVersion": false`로 바꾸고 `--config`로 지정합니다. 이 경우 시작할 때 버전 경고만 출력합니다. 설정 파일 안의 상대 경로(`auditPath` 등)는 설정 파일 위치 기준으로 해석되므로, 복사본을 다른 폴더에 둘 때는 `auditPath`를 절대 경로로 적습니다.

Final Guard는 실제 Anthropic upstream으로 전달되는 `/v1/messages`와 `/v1/messages/count_tokens` JSON의 모든 문자열 leaf를 다시 검사합니다. finding뿐 아니라 detector timeout, crash, malformed response, body 제한 위반과 알 수 없는 endpoint도 provider 전송 전에 차단합니다. 요청 원문, credential, authorization header는 audit에 남기지 않습니다.

`PG_GUARD_COUNT_TOKENS=mask`이면 count_tokens 요청에 한해 422 대신 탐지한 값을 자리표시자로 바꿔 보냅니다(기본 `block`). count_tokens의 응답은 토큰 수뿐이라 내용이 돌아오지 않습니다. 시스템 프롬프트에서 비밀이 나와 막을 때는 `promptguard run`으로 실행하라는 안내를 오류 메시지에 붙입니다. 자세한 내용은 [자리표시자 안내와 빈틈](docs/PLACEHOLDER_GUIDE_AND_GAPS.md)에 있습니다.

이미 깨끗하다고 판정된 문자열은 다시 검사하지 않으므로, 매 turn 반복되는 system prompt와 tool 정의는 세션의 첫 요청에서만 검사됩니다. 그래서 첫 요청은 오래 걸릴 수 있고(claude.ai 커넥터가 많으면 10~20초), 이후 요청은 새로 추가된 대화만 검사합니다.

> 두 worker는 process와 lifecycle이 독립적이지만 같은 최신 detector ensemble 설정을 사용합니다. 따라서 Mod 장애, 변환 뒤 재노출, worker 하나의 장애를 최종 전송 지점에서 막는 의미가 있습니다. 반면 모든 adapter가 공통으로 놓치는 패턴은 Guard도 놓칠 수 있으므로, detector 다양성과 coverage 검증은 별도 과제입니다.

[Runtime V1 구조·보안 경계·운영 설명](docs/RUNTIME_V1.md)

## 3. 기존 Mod-only 체험 경로

아래 `start-promptguard.*` launcher는 팀의 기존 데모 및 회귀 테스트 호환을 위해 유지합니다. Native Mod 동작을 빠르게 볼 수 있지만 provider-bound Final Guard는 포함하지 않습니다. 실제 보호 흐름을 확인하려면 위 Runtime V1을 사용하세요.

Windows:

```powershell
cd sample-protected-project
..\start-promptguard.cmd
```

macOS:

```bash
cd sample-protected-project
../start-promptguard.sh
```

## 4. 체험 질문과 기대 결과

두 실행 경로 모두 같은 방법으로 확인합니다. Claude 로그인 화면이 처음 나오면 구독 계정 사용자는 `Claude account with subscription`을 선택합니다. 계정이나 token을 팀원끼리 공유하지 마세요.

Claude에 다음을 입력합니다.

```text
DB 연결이 실패하는 원인을 찾아줘.
.env, config/database.json, logs/app.log를 확인하고
필요하면 src/diagnose.js도 실행해줘.
```

기대 결과:

- password/API key/token은 `[PASSWORD_n]`, `[API_KEY_n]`, `[TOKEN_n]`으로 전달
- `demo-db.internal`, `orders`, `5440`, expected `5432`, `E_PORT_MISMATCH`는 보존
- Claude가 port mismatch를 원인으로 진단
- `!cat .env`처럼 직접 실행한 명령의 출력도 placeholder로만 전달
- raw-free audit은 Runtime V1이면 `.promptguard/audit/`, 기존 launcher면 `.runtime/audit/`에 생성

## `!` 셸 모드 입력 마스킹

Claude Code에서 `!`로 직접 실행한 명령과 그 출력은 `prompt.submit`·`tool.call` 훅을 거치지 않고 `session.append`(door `command`)로만 세션에 들어갑니다. Mod는 `session.append`에서 다른 훅이 다루지 않는 행(`command`, `tool-message`, `delivery`, `hook-context`, `note`, `notice`)의 text와 tool_result text를 저장·전송 전에 마스킹합니다. 따라서 `!cat .env`의 값은 모델 요청과 로컬 transcript(`.jsonl`) 모두에 placeholder로만 남습니다. 화면에는 rewrite 직전 형태가 잠깐 보일 수 있습니다.

## Placeholder 원복 (실행 직전 복원)

모델은 `[PASSWORD_1]` 같은 placeholder만 보기 때문에, 모델이 만든 명령에도 placeholder가 들어갑니다. 그대로 실행하면 `psql` 접속이나 `.env` 수정이 실패하므로, Mod가 `tool.call` 훅에서 **실제 실행 직전에만** placeholder를 원래 값으로 되돌립니다.

1. 마스킹할 때 `placeholder → 원래 값`을 Mod 프로세스 메모리(vault)에만 기록합니다. 파일, audit, 모델로는 내보내지 않습니다.
2. 로컬에서 실행되는 도구(`Bash`, `PowerShell`, `Edit`, `MultiEdit`, `Write`, `NotebookEdit`, `Grep`)의 입력에서 알려진 placeholder를 원래 값으로 바꿔 실행합니다. 모르는 placeholder는 그대로 둡니다.
3. `Agent`, `WebFetch`, MCP 도구처럼 입력이 다른 모델이나 외부로 나가는 도구는 원복하지 않습니다.
4. 실행 결과에 원래 값이 다시 나오면(예: `echo`로 출력), detector 검사 뒤에 vault 기준으로 한 번 더 확인해 탐지기가 놓친 값을 같은 placeholder로 다시 가립니다(re-mask).
5. audit에는 값 없이 `restored_count`, `remasked_count` 개수만 남습니다.

원래 값의 **일부**만 출력돼도 가립니다(`sed`, `cut`, `head -c`로 잘라 출력한 경우). 원래 값의 연속된 `max(8, 길이의 절반)`자 이상이 출력에 있으면 `[PASSWORD_1_PART]`처럼 `_PART`를 붙인 표시로 바꿉니다. 이 표시는 원래 값으로 복원되지 않습니다. 8자보다 짧은 값은 전체가 나올 때만 가립니다. 일치한 부분이 흔한 단어로만 되어 있으면(`password123!`의 `password`, `localhost1234`의 `localhos`처럼 소문자·대문자·첫 글자만 대문자인 단어와 `-_. `) 부분으로는 가리지 않습니다. 사람이 고른 비밀번호의 단어가 이후 코드와 로그의 같은 단어를 모두 가려 읽기·수정을 망가뜨리지 않게 하기 위해서입니다. 값 전체나 숫자·기호가 섞인 부분은 그대로 가립니다. 비밀 50개, 출력 100KB에서 한 번에 약 10ms가 더 듭니다(`node tests/performance/remask_bench.mjs`).

원복을 끄려면 `PG_RESTORE_PLACEHOLDERS=off`를 지정합니다. re-mask는 그대로 동작합니다.

> **`PG_REMASK=off`는 끄지 마세요.** 측정용 설정입니다. 끄면 전체 값 재마스킹과 부분 재마스킹(`_PART`)을 모두 하지 않습니다. 자리표시자 복원은 그대로 되므로, 복원한 값이 실행 결과에 다시 나오면 탐지기가 그 자리에서 잡지 못하는 한 **원래 값이 그대로 모델에 갑니다.** audit의 `remasked_count`는 0이 됩니다.

`PG_PLACEHOLDER_PUBLIC_PREFIX=on`이면 공개된 접두어가 있는 값을 `sk_live_[STRIPE_SECRET_KEY_1]`처럼 접두어를 남겨 가립니다. 기본은 꺼짐이고, 적용 대상은 [접두어 표](docs/PLACEHOLDER_PUBLIC_PREFIXES.md)에 있습니다.

탐지기 거르기(`PG_DETECTOR_FILTERS`)는 기본으로 켜져 있습니다. 구조상 비밀일 수 없는 값(HTML 조각, 코드 호출, CSS 값, 템플릿, `secret-assignment`의 참조·코드 값)을 합집합 전에 거릅니다. `PG_DETECTOR_FILTER_DUMMY=on`은 예시·더미 값을 따로 거르며 기본은 꺼짐입니다. 기준은 [탐지기 거르기](docs/DETECTOR_FILTERS.md)에 있습니다.

8자 미만 값은 기본으로 단어 경계가 맞는 곳에서만 다시 가리고(`PG_REMASK_SHORT=boundary`), shell-aware는 함수 이름 단서로 잡는 4자 미만 위치 인자를 내지 않습니다(`PG_SHELL_POSITIONAL_MIN=4`). 이전 동작은 `substring`과 `1`입니다. 기준은 [짧은 값 재마스킹](docs/REMASK_FLOOR.md)에 있습니다.

시스템 프롬프트의 자리표시자 안내(`PG_PLACEHOLDER_GUIDE`)와 Grep 패턴·Bash의 grep·rg·sed 인자의 `\[TYPE_N\]` 복원(`PG_RESTORE_ESCAPED`)도 기본으로 켜져 있습니다. 비밀 파일을 od·xxd·base64·글자 쪼개기 같은 방식으로 출력한 Bash 결과는 통째로 안내 문구로 바뀝니다(`PG_SECRET_DUMP_GUARD`, [비밀 파일 덤프 가드](docs/SECRET_DUMP_GUARD.md)). `promptguard run`은 `--append-system-prompt`·`--system-prompt`(와 `-file` 형태)의 비밀을 Claude Code를 띄우기 전에 가립니다. 내용과 count_tokens 빈틈은 [자리표시자 안내와 빈틈](docs/PLACEHOLDER_GUIDE_AND_GAPS.md)에 있습니다.

### 설정 한눈에 보기 (release/defaults-1120)

PR #23~#27의 변경에 새 기본값을 더한 릴리스 브랜치입니다. 기본값은 정우 측정(노션 "측정 요청 (11-19)" v3)으로 정했습니다. 모든 설정은 환경변수이고, "이전 동작" 열의 값을 주면 그 설정만 #23~#26 이전으로 돌아갑니다. 빈 값은 기본값으로 봅니다. on/off 설정은 `on`일 때만 켜지므로 `off`(또는 그 밖의 값)는 끔입니다.

Mod와 Guard의 탐지기 worker는 같은 `pgdetector`(`src/detector/pgdetector/settings.py`)에서 기본값을 읽으므로, 아무것도 주지 않으면 필터 설정 불일치 경고가 나지 않습니다. 한쪽에만 값을 주면 지금처럼 경고합니다.

| 설정 | 기본값 | 이전 동작 | 기본값일 때 하는 일 | 근거 | 출처 |
|---|---|---|---|---|---|
| `PG_DETECTOR_FILTERS` | `on` | `off` | 탐지기가 합집합 전에 구조상 비밀일 수 없는 후보를 거릅니다(HTML 조각, 코드 호출·색인, CSS 값, 템플릿). `secret-assignment`는 참조·호출·코드·템플릿 값을 내지 않습니다. 고신뢰 규칙(`src/detector/high-confidence-rules.json`)은 거르지 않습니다. Mod와 Guard의 설정이 다르면 Guard의 차단 메시지가 알려 줍니다 | 실제 트래픽 오탐 약 −30%, 새로 놓친 정답 0 | #23 |
| `PG_DETECTOR_FILTER_DUMMY` | `off` | `off` | `on`이면 예시·더미 값(`<password>`, `your_*_here`, `xxx`, `***`, `placeholder` 등)을 따로 거릅니다. `changeme` 같은 약한 기본값은 거르지 않습니다 | 효과가 측정 오차 수준이라 그대로 | #23 |
| `PG_REMASK` | `on` | `on` | 복원했던 값이 다시 나오면 전체·부분 재마스킹으로 가립니다. **`off`는 측정용입니다.** 끄면 탐지기가 잡지 못한 재등장은 원래 값 그대로 나갑니다. 복원은 그대로 됩니다 | 측정용 스위치(지표 1의 8번, 지표 2의 promptguard 조건) | 이 PR |
| `PG_REMASK_SHORT` | `boundary` | `substring` | 8자 미만 값은 앞뒤에 `[A-Za-z0-9_]`가 붙지 않은 곳에서만 다시 가립니다 | 재마스킹 오탐 −91%, 새로 놓친 정답 0 | #24 |
| `PG_SHELL_POSITIONAL_MIN` | `4` | `1` | shell-aware가 함수 이름 단서로 잡는 위치 인자 중 4자 미만은 내지 않습니다 | 위와 같은 묶음 | #24 |
| `PG_RULE_HEX_KEY` | `on` | `off` | 키 이름(`key`, `api_key`, `secret_key` 등) 옆 따옴표 안의 32~64자 16진수를 `hex-key`로 찾습니다. Go의 `Key: String("…")`도 포함합니다. hash·sha·commit 같은 이름은 뺍니다 | recall +2.2%p, 실제 트래픽 오탐 증가 0 | #26 |
| `PG_PLACEHOLDER_GUIDE` | `on` | `off` | 시스템 프롬프트 끝에 자리표시자 안내를 요청마다 한 번 넣습니다(`PG_RESTORE_ESCAPED`가 켜져 있으면 1,134자, 꺼져 있으면 998자). 비밀 파일이나 가려진 값을 od·xxd·hexdump·base64, 글자 쪼개기, 일부 자르기로 출력하지 말고 속성은 값을 출력하지 않는 명령으로 확인하라는 문장이 들어 있습니다 | 지표 2 멈춤 4→0, placeholder 잘못 보고 15→0 | #25 |
| `PG_RESTORE_ESCAPED` | `on` | `off` | Grep의 `pattern`과 Bash의 grep·rg·sed 인자에서 `\[TYPE_N\]`을 같은 문법으로 이스케이프한 실제 값으로 복원합니다 | 위와 같은 묶음 | #25 |
| `PG_SECRET_DUMP_GUARD` | `on` | `off` | Bash 명령이 비밀 파일로 보이는 경로(`.env`, `secrets/`, `*password*`, `*.pem` 등)를 변형·덤프 도구(od, xxd, hexdump, base64, base32, fold, `cut -c`, rev, `head -c`·`tail -c`·dd, `cat -A`·`-v`·`-e`·`-t`, `sed -n l`, 한 글자씩 뽑는 `grep -o`, 글자 사이에 넣는 sed, 글자 단위로 쪼개거나 `substr`로 자르는 awk·python·node·perl)로 읽으면, 그 명령의 출력 전체를 안내 문구 하나로 바꿉니다. `cat`·Read처럼 그대로 읽으면 지금처럼 탐지기와 placeholder로 가립니다 | 지표 2 g16·g20·t14에서 `od -c` 출력으로 비밀이 서버에 감 | #30 |
| `PG_SECRET_FILE_PRELOAD` | `off` | `off` | `on`이면 위 경로를 이름에 담은 Bash 명령을 실행하기 전과 Read가 그런 경로를 열 때, 256바이트 이하 한 줄 파일의 앞뒤 공백을 뺀 내용(`secrets/` 안·정확한 이름 등은 3자 이상, 이름으로만 고른 파일은 8자 이상)을 금고에 미리 넣어 이후 어디에 나오든 재마스킹으로 가립니다 | 측정 전이라 끔 | #30 |
| `PG_GUARD_COUNT_TOKENS` | `block` | `block` | `mask`이면 Final Guard가 count_tokens 요청에 한해 422 대신 탐지한 값을 자리표시자로 바꿔 보냅니다. `/v1/messages`는 그대로 막습니다 | 빈틈 확인 측정 전이라 그대로 | #25 |
| `PG_PLACEHOLDER_PUBLIC_PREFIX` | `off` | `off` | `on`이면 공개 접두어를 남겨 가립니다(`sk_live_[STRIPE_SECRET_KEY_1]`) | 측정 안 함이라 그대로 | #21 |

기본값이 들어 있는 곳은 `src/detector/pgdetector/settings.py`(탐지기), `src/native-mod/hooks/register.mjs`의 `DEFAULTS`(Mod), `src/guard/lib.cjs`(Guard) 세 곳이고, `tests/launcher/defaults.test.cjs`가 이 표와 함께 맞춰 봅니다.

**설정 없이 항상 켜진 변경**

| 출처 | 변경 |
|---|---|
| #23 | 조회 호출 기본값: `os.getenv("KEY", "<기본값>")`, `os.environ.get(…, default="…")`, `process.env.X \|\| "…"`의 따옴표 기본값을 후보로 냅니다(첫 인자는 키 이름이어야 함) |
| #23 | .env 리터럴: 줄 맨 앞(또는 `export` 뒤)의 대문자 `KEY=value`는 따옴표가 없어도 리터럴로 봅니다 |
| #26 | `basic-auth`: `Authorization: Basic <base64>`를 엄격히 디코드해 `user:pass`일 때 |
| #26 | `sql-password`: `IDENTIFIED BY '…'`, `WITH PASSWORD '…'`, `CREATE/ALTER USER\|ROLE … PASSWORD '…'`, `SET PASSWORD … = '…'` (3자 이상) |
| #26 | 이스케이프: 따옴표 값에 `\"` `\'` `\\`가 있으면 진짜 닫는 따옴표까지(`secret-assignment`, shell-aware 함수 인자·`send(...)`) |
| #26 | 타입 표기 대입: `db_password: str = "…"`, `DB_PASSWORD: Final = "…"`. 매개변수 기본값과 `name: Type` 선언은 값으로 보지 않습니다 |
| #26 | 줄인 이름: `pw`, `db_pw`, `pass_word`. `pwd` 하나뿐인 이름은 뺍니다 |
| #26 | PEM 패딩: CredSweeper의 base64 PEM span이 뒤의 `=`까지 덮습니다 |
| #25 | 런처의 시스템 프롬프트 가리기: `promptguard run`이 `--system-prompt`·`--append-system-prompt`(와 `-file`)의 비밀을 Claude Code를 띄우기 전에 가리고 Mod에 대응표를 넘깁니다 |
| #25 | Guard 안내 메시지: 시스템 프롬프트에서 비밀이 나와 막을 때 `promptguard run`으로 실행하라고 알려 줍니다 |

### 원복한 값이 모델로 다시 실려 가는가? (E2E 검증)

실제 Claude Code CLI + Native Mod + detector worker를 가짜 Anthropic API에 연결해, provider로 나가는 요청을 전부 기록하고 확인했습니다 (Claude Code 2.1.296에서 확인).

- Claude Code는 대화 기록에 **모델이 쓴 원래 입력**(`[PASSWORD_1]`이 든 명령)을 남기고, 훅이 바꾼 입력(원래 값)은 실행에만 씁니다. 같은 turn의 후속 요청, `--resume`한 다음 turn 요청, 로컬 transcript(`.jsonl`) 어디에도 원래 값이 없습니다.
- 다만 원복된 명령이 원래 값을 **출력**하면(예: `printf`로 값만 출력) `key=value` 같은 문맥이 없어 detector가 탐지하지 못할 수 있습니다(검증 당시 CredSweeper는 탐지하지 못했습니다). 이 경우는 re-mask가 막습니다. re-mask를 끄고 돌리면 원래 값이 provider 요청과 transcript에 그대로 실려 가는 것을 확인했습니다.

테스트:

```bash
node --test tests/mod/test_restore.mjs   # 단위 테스트 (가짜 detector)
node tests/e2e/restore_history.mjs       # E2E (설치 후, Claude Code와 .venv 필요)
```

E2E 증거(기록된 provider 요청, audit)는 `.runtime/e2e-restore/`에 남습니다.

### 탐지기가 실패하면? (fail-closed)

탐지기 호출이 실패하면(`scan_batch` 권한 거부, 브리지 타임아웃, 8MB 초과, 형식 오류) Mod는 검사하지 못한 텍스트를 `[PROMPTGUARD_BLOCKED: detector failure]`로 바꿔 넘깁니다. 도구 결과는 이 문구로 deny하고, compaction은 건너뜁니다. 훅이 예외를 던지면 Claude Code가 그 훅을 건너뛰고 원문을 그대로 넘기기 때문에, 훅은 예외를 던지지 않습니다. 그래도 훅이 실패하면(버그, 10초 예산 초과) 등록마다 붙인 `.catch`가 같은 문구로 대신 답합니다. 런처(`start-promptguard.*`, `promptguard run`)는 `mcp__pgdetector__scan_batch`를 `--allowedTools`로 미리 허용합니다.

```bash
node --test tests/mod/test_fail_closed.mjs   # 단위 테스트 (엔진 동작을 흉내 냄)
node tests/e2e/fail_closed.mjs               # E2E: 권한 거부, 탐지기 다운, 정상
```

E2E는 `PG_E2E_CLAUDE`로 Claude Code 실행 파일(2.1.291)을, `PG_E2E_PLUGIN_DIR`로 비교할 Mod 폴더를 지정할 수 있습니다. 증거는 `.runtime/e2e-fail-closed/`에 남습니다.

## 5. 다른 프로젝트에서 실행

Windows:

보호하려는 프로젝트로 이동한 뒤 이 repository의 launcher를 절대 경로로 호출합니다.

```powershell
cd C:\path\to\your-project
C:\path\to\promptguard-claude-demoV0\promptguard.cmd run
```

macOS:

```bash
cd /path/to/your-project
/path/to/promptguard-claude-demoV0/promptguard run
```

## 6. Detector 모듈과 합의 정책

detector는 여러 모듈을 **adapter**로 감싸 같은 인터페이스(`name`, `version`, `scan(text)`)로 다룹니다. 응답에는 두 계층이 있습니다.

- `findings`: Native Mod가 마스킹하고 Final Guard가 차단 기준으로 쓰는 span. `candidate_policy`가 무엇을 넣을지 정합니다.
  - `"union"`(기본값): 활성 모듈 중 **하나만** 잡아도 포함합니다. 중간 발표 데모의 recall-first 설정입니다.
  - `"majority"`: 기존 CredSweeper/Gitleaks/custom rules 다수결만 사용합니다. `candidate_only` 모듈은 투표하지 않습니다. 이전 동작과 같아서 비교나 롤백에 씁니다.
- `candidates`: 정책과 상관없이 모든 모듈의 합집합. 겹치는 span은 하나로 합치고, 어느 모듈이 왜 잡았는지(provenance)를 raw 값 없이 남깁니다.

`PG_DETECTOR_CANDIDATE_POLICY=majority`로 실행하면 설정 파일을 고치지 않고 기존 동작으로 돌아갑니다. 탐지기는 `promptguard run --enable ml-span --disable shell-aware --policy union`처럼 실행 옵션으로 켜고 끕니다(`promptguard --help`). 준비와 옵션은 [ML adapter 문서](docs/ML_ADAPTERS.md)를 참고하세요.

| adapter 이름 | 종류 | 구현 |
| --- | --- | --- |
| `credsweeper` | 오픈소스 (Python 라이브러리) | `src/detector/pgdetector/adapters/credsweeper.py` |
| `gitleaks` | 오픈소스 (Go 바이너리, `gitleaks stdin`) | `src/detector/pgdetector/adapters/gitleaks.py` |
| `promptguard-rules` | 직접 만든 모듈 (순수 Python 정규식/키 분류) | `src/detector/pgdetector/adapters/patterns.py` |
| `shell-aware` | command/source/sink 의미 기반 candidate generator | `src/detector/pgdetector/adapters/shell_aware.py` |
| `ml-span` | 팀 mmBERT span 모델, 모델 저장소가 지정한 기본 버전 (기본 꺼짐) | `src/detector/pgdetector/adapters/span_models.py` |
| `ml-v9` | 같은 모델의 v9 고정판, 비교와 재평가용 (기본 꺼짐) | `src/detector/pgdetector/adapters/span_models.py` |
| `ml-qwen` | 팀 Qwen2.5-Coder LoRA span 모델 (기본 꺼짐) | `src/detector/pgdetector/adapters/span_models.py` |

모듈 목록과 정책은 `src/detector/detector.json`에서 지정합니다.

```json
{
  "consensus": { "mode": "majority" },
  "candidate_policy": "union",
  "adapters": [
    { "name": "credsweeper", "type": "credsweeper", "required": true, "options": { ... } },
    { "name": "gitleaks", "type": "gitleaks", "required": false, "options": { ... } },
    { "name": "promptguard-rules", "type": "patterns", "required": true, "options": { ... } },
    { "name": "shell-aware", "type": "shell-aware", "required": true, "candidate_only": true, "options": { ... } }
  ]
}
```

합의 정책(`consensus`):

| 값 | 의미 (활성 모듈 N개 기준) |
| --- | --- |
| `{"mode": "any"}` | 1개 이상이 탐지하면 채택 |
| `{"mode": "majority"}` | 과반(N/2 + 1) 동의 시 채택. 기본값 |
| `{"mode": "unanimous"}` | N개 모두 동의해야 채택 |
| `{"mode": "at_least", "n": 2}` | n개 이상 동의 시 채택 |

설정 파일을 고치지 않고 실행할 때만 바꾸려면 환경 변수를 씁니다. `PG_DETECTOR_CONSENSUS`는 `any`, `majority`, `unanimous`, `at_least:2`(또는 `2`)를 받고, `PG_DETECTOR_CONFIG`는 다른 설정 파일 경로를 받습니다.

```bash
PG_DETECTOR_CONSENSUS=unanimous ../promptguard run
```

```powershell
$env:PG_DETECTOR_CONSENSUS = 'at_least:2'; ..\promptguard.cmd run
```

Runtime V1에서는 이 값이 Mod용·Guard용 detector worker 모두에 적용됩니다. 기존 `start-promptguard.*` launcher에도 같은 환경 변수를 쓸 수 있습니다.

launcher와 detector health(`/status`)는 활성/skip 모듈, `candidate_policy`, 보호에 쓰는 모듈(`protection_adapters`)과 필요한 표 수를 출력합니다.

판정 규칙:

- 서로 다른 모듈의 span이 한 글자라도 겹치면 같은 영역에 동의한 것으로 셉니다. 도구마다 `key=value` 전체를 잡거나 값만 잡는 등 경계가 다르기 때문입니다. 같은 모듈이 여러 번 탐지해도 1표입니다.
- 채택된 영역은 동의한 span들의 합집합으로 가립니다. 일부 모듈이 값을 짧게 잡아도 나머지 부분이 노출되지 않게 하기 위해서입니다.
- finding의 `detectors`에는 동의한 모듈 이름(`["credsweeper", "promptguard-rules"]`)이, `rule_id`에는 V0와 같은 형식으로 각 모듈의 룰 이름이 `+`로 이어져(`Password+secret-assignment`) 남습니다.
- 실행 중 한 모듈이라도 실패하면 해당 요청은 `ADAPTER_FAILURE:<이름>` 오류로 fail-closed 됩니다.
- `required: false` 모듈은 도구가 설치되지 않았으면 시작 시 제외되고, 투표 수(N)에서도 빠집니다. 활성 모듈 수보다 큰 `at_least` 값은 아무것도 가리지 못하게 되므로 worker가 시작을 거부합니다.
- `candidate_only: true` 모듈은 `majority` 투표에서 빠집니다. `union`에서는 다른 모듈과 똑같이 보호에 들어갑니다. 실행 중 실패하면 다른 adapter와 동일하게 요청이 fail-closed 됩니다.

> `unanimous`는 가장 약한 모듈의 재현율에 맞춰집니다. gitleaks 기본 룰은 password류를 거의 잡지 못해서, 이 저장소의 fixture에서 만장일치는 32개 중 8개만 가리고 sample 프로젝트의 password/token은 그대로 통과시킵니다.

### 새 모듈 추가

`DetectorAdapter`를 상속해 `scan(text)`가 `RawFinding(start, end, type, rule_id, confidence)` 목록(Python code point offset)을 반환하도록 구현합니다. `type`은 Mod/Guard가 아는 `PASSWORD`, `API_KEY`, `TOKEN`, `PRIVATE_KEY`, `AWS_KEY`, `GITHUB_TOKEN`, `SLACK_TOKEN`, `JWT`, `SECRET`, `CREDENTIAL` 중 하나로 매핑합니다. 도구가 없을 때는 생성자에서 `AdapterUnavailable`을 던집니다.

```python
from pgdetector import DetectorAdapter, RawFinding

class MyAdapter(DetectorAdapter):
    version = "0.1.0"

    def scan(self, text):
        return [RawFinding(start, end, "TOKEN", "my-rule", "moderate") for start, end in my_tool(text)]
```

`detector.json`에 `{"name": "my-tool", "type": "my_package.my_module:MyAdapter"}`처럼 `module:Class` 경로로 등록하면 기본 adapter 목록을 고치지 않아도 됩니다(모듈은 `src/detector` 아래 또는 `PYTHONPATH`에 있어야 합니다). 자주 쓰는 adapter는 `pgdetector/adapters/__init__.py`의 `ADAPTER_TYPES`에 짧은 이름으로 추가할 수 있습니다. 같은 adapter 종류를 옵션만 바꿔 다른 이름으로 여러 번 등록해도 각각 1표로 셉니다.

## 통합 측정 (eval/integration-1118, release/defaults-1120)

### 탐지 지표: 9개 설정을 한 번에

`scripts/eval_integration/run.py`가 promptguard-data의 채점기(`creddata-trajectory-data` 브랜치: 덮은 recall, 글자 precision, F2, `per_finding.jsonl`)로 아래 8개 설정을 돌리고 `report.md` 한 장을 냅니다. promptguard-data는 읽기만 합니다. 모든 설정은 실행마다 명시적으로 주므로, 이 브랜치의 새 기본값은 1~7번 결과를 바꾸지 않습니다.

| 번호 | 설정 |
|---|---|
| 1 | main 668c2c1 (실행기가 `--out` 아래에 worktree를 만듭니다) |
| 2 | 이 브랜치, 전부 off |
| 3 | 2 + `PG_DETECTOR_FILTERS=on` |
| 4 | 2 + `PG_DETECTOR_FILTERS=on` + `PG_DETECTOR_FILTER_DUMMY=on` |
| 5 | 2 + `PG_REMASK_SHORT=boundary` + `PG_SHELL_POSITIONAL_MIN=4` |
| 6 | 2 + `PG_RULE_HEX_KEY=on` |
| 7 | 전부 on (`PG_PLACEHOLDER_GUIDE`, `PG_RESTORE_ESCAPED`, `PG_GUARD_COUNT_TOKENS`는 탐지 채점에 영향이 없지만 함께 켭니다) |
| 8 | 새 기본값(release/defaults-1120) + `PG_REMASK=off`. 채점기의 Mod 재현(`ModSession`)에서 재마스킹만 뺍니다(`instrument.install_no_remask`) |
| 9 | 새 기본값 + `--policy verifier`(#28, `PG_DETECTOR_CANDIDATE_POLICY=verifier`). 애매함 후보만 뒷단 검증기가 다시 판정합니다. 번들은 `--verifier-bundle DIR` 또는 `PG_VERIFIER_BUNDLE` |

2~7번은 `PG_REMASK=on`입니다(지금까지 늘 켜져 있던 동작).

```bash
cd promptguard-data   # creddata-trajectory-data 브랜치
PG=../promptguard-claude-demoV0   # release/defaults-1120
python $PG/scripts/eval_integration/run.py --data-root . \
  --creddata metric-detection/data_test/sessions_from_CredData-trajectory.jsonl \
  --nine metric-detection/data_test/sessions.jsonl metric-detection/data_test/sessions_2.jsonl \
         metric-detection/data_test/sessions_from_example.jsonl metric-detection/data_test/sessions_from_CredData.jsonl \
         metric-detection/data_test/sessions_from_noseyparker.jsonl metric-detection/data_test/sessions_from_Nemotron-PII.jsonl \
         metric-detection/data_test/sessions_from_trajectory.jsonl metric-detection/data_test/sessions_from_openhands-feedback.jsonl \
         metric-detection/data_test/sessions_from_SWE-Gym.jsonl \
  --out runs/eval-integration-1118 --jobs 2 --gitleaks ../tools/gitleaks-8.30.1 \n  --verifier-bundle ../promptguard-model/runs/verifier/creddata-mmbert-small/model
```

- **돌리는 범위:** CredData-trajectory test는 9개 설정 모두, 기존 9셋은 1·7·8·9번만 돌립니다. 실제 트래픽(openhands-feedback, SWE-Gym)은 "1,000줄당 오탐" 열을 채우려고 9개 설정 모두 돌립니다. 9번만 더하려면 `--configs 9-defaults-verifier --verifier-bundle DIR`로 돌리고 표는 `--report-only`로 다시 만듭니다. 9번이 들어 있는데 번들이 없으면 실행기는 아무것도 돌리지 않고 멈춥니다. 8번만 더하려면 `--configs 7-all 8-defaults-no-remask`로 돌리고 표는 `--report-only`로 다시 만듭니다(끝난 실행은 건너뜁니다).
- **이어 돌리기:** 끝난 실행은 다시 돌리지 않습니다(`--force`로 다시). `--report-only`는 표만 다시 만듭니다.
- **표의 열:** recall(덮었는가), 글자 precision, F2, 못 가린 span 수 / 고유 값 수, 재마스킹 오탐, 실제 트래픽 1,000줄당 오탐, 거르기별 걸러낸 수, 새로 놓친 정답 수, 재마스킹으로만 가린 정답.
  - 새로 놓친 정답은 2번은 1번과, 3~7번은 2번과, 8번과 9번은 7번과 비교합니다. 정답 유형, 기준 설정에서 찾은 규칙, 이 설정에서 그 위를 거른 거르기, 값 모양(종류·길이)별로 따로 표를 냅니다.
  - **재마스킹으로만 가린 정답**(8번 줄): 7번에서는 덮었고 8번에서는 못 덮은 정답 span 수 / 고유 값 수입니다. 7번은 `PG_DETECTOR_FILTER_DUMMY`도 켜므로, 그 거르기 때문에 7번이 놓친 정답은 이 수에 들지 않습니다.
- **7번의 재마스킹 오탐은 그 값을 처음 잡은 탐지기·규칙별로 나눕니다.** 재마스킹 오탐 수와 고유 값 수를 적고, 같은 세션에서 그 값을 처음(가장 앞 항목, 그 안에서 가장 앞 위치) 낸 후보의 `adapter:rule`별로 span 수와 고유 값 수를 냅니다. 같은 자리를 여러 규칙이 냈으면 함께 적고, 세션 안에 그 값을 낸 후보가 없으면 따로 셉니다.
- **7번은 후보 등급별로도 나눕니다.**
  - 바로 가림: `src/detector/high-confidence-rules.json`의 규칙이거나 strong 등급인 후보
  - 애매함: 그 밖의 moderate·ambiguous 후보
  - 각 등급의 TP·FP와, 애매함 구간에서 그 규칙만 찾은 정답 수를 냅니다.
- **9번은 검증기 표를 따로 냅니다.** 데이터셋마다 검증기가 가린 애매함 후보 수, 안 가린 수, 안 가린 것 중 이 실행에서 덮이지 않은 정답과 겹친 수(검증기 때문에 새로 놓친 정답), 검증기 timeout과 fail-closed(그 항목의 애매함 후보를 모두 가림) 항목 수입니다. 구조 거르기에서 걸러진 후보는 검증기에 가지 않습니다.
- **값은 출력하지 않습니다.** 값은 메모리에서 모양을 보고 고유 값을 세는 데만 씁니다.
- recall과 precision은 채점기의 `per_span`·`per_edit`에서 다시 세고 `metrics.json`과 비교합니다. 다르면 표 끝에 적습니다.

### 지표 2 (작업 성공): metric-task

정우 노션의 방법대로 `m2.py`로 돌립니다. `m2.py`는 셸의 환경변수를 Claude Code에 그대로 넘기므로, 설정은 환경변수로 줍니다. 측정 엔진은 Claude Code 2.1.319입니다.

**1. gold 과제 × 3회: main 대비 GUIDE+RESTORE_ESCAPED on.** 이 비교에는 Final Guard를 앞에 두지 않습니다. Guard의 실제 탐지기가 gold 조건(정답으로 가리기)에 섞이기 때문입니다. release/defaults-1120에서는 두 설정이 기본으로 켜져 있으므로 환경변수 없이 돌려도 같습니다.

```bash
cd promptguard-data
PG=../promptguard-claude-demoV0
TASKS="t12 t14 g29 s08 s11 s34 s35 s36 s70 n03 n14 n24 g23 t09 t10 t11 t15 t16 t17 s29 s30 s72 s73 s74 s75 s76 s77 s78 s79 s80"
git -C $PG switch --detach 668c2c1
python3 metric-task/scripts/m2.py run --tasks $TASKS --conditions gold --reps 3 --model sonnet --jobs 2 --system-root $PG --name integ_before
git -C $PG switch release/defaults-1120
PG_PLACEHOLDER_GUIDE=on PG_RESTORE_ESCAPED=on python3 metric-task/scripts/m2.py run --tasks $TASKS --conditions gold --reps 3 --model sonnet --jobs 2 --system-root $PG --name integ_after
python3 metric-task/scripts/m2.py report runs/metric-task/integ_before --out metric-task/results/integ_before
python3 metric-task/scripts/m2.py report runs/metric-task/integ_after --out metric-task/results/integ_after
```

잴 것: 작업 성공률, 멈춤 비율, 자리표시자를 파일 내용으로 보고한 비율, 서버에 간 비밀 수(늘면 안 됨).

**1b. promptguard 조건 (실제 탐지기): 새 기본값으로 `PG_REMASK=on`과 `off`.** 같은 과제 목록(`$TASKS`, gold와 같음) × 3회를 `--conditions promptguard`로 두 번 돌립니다. Mod가 실제 탐지기(`src/detector/worker.py`)를 쓰고, 설정은 새 기본값 그대로 둡니다(`PG_*`를 주지 않음). 재마스킹만 켜고 끕니다. Final Guard는 이 비교에도 두지 않습니다. 두면 Guard가 재마스킹이 놓친 값을 막아 off의 차이가 가려집니다.

```bash
git -C $PG switch release/defaults-1120
for name in $(env | grep -o '^PG_[A-Z_]*'); do unset $name; done   # 셸에 남은 설정이 새 기본값을 덮지 않게
PG_REMASK=on  python3 metric-task/scripts/m2.py run --tasks $TASKS --conditions promptguard --reps 3 --model sonnet --jobs 2 --system-root $PG --name pg_remask_on
PG_REMASK=off python3 metric-task/scripts/m2.py run --tasks $TASKS --conditions promptguard --reps 3 --model sonnet --jobs 2 --system-root $PG --name pg_remask_off
python3 metric-task/scripts/m2.py report runs/metric-task/pg_remask_on  --out metric-task/results/pg_remask_on
python3 metric-task/scripts/m2.py report runs/metric-task/pg_remask_off --out metric-task/results/pg_remask_off
```

잴 것: 작업 성공률, 서버에 간 심은 비밀 수(`to_server`, 캡처 기준), 재마스킹 횟수(Mod audit의 `remasked_count` 합. off면 0이어야 합니다). `PG_REMASK=off`는 측정용입니다. off에서 서버에 간 비밀이 늘어난 만큼이 재마스킹이 막던 누출입니다.

**2. 빈틈 확인 n19, n27 (count_tokens):** Final Guard를 앞에 두고 `PG_GUARD_COUNT_TOKENS=block`과 `mask`로 각각 1회 돌립니다. 서버에 간 비밀 수와 세션이 끝났는지를 봅니다.

**3. 빈틈 확인 g11, s09 (시스템 프롬프트):** 런처로 시스템 프롬프트를 먼저 가리고 1회 돌립니다.

```bash
node $PG/src/launcher/system-prompt.cjs --detector-url http://127.0.0.1:<탐지기 포트> --seed-file <run_dir>/seed.json -- <m2.py가 넘기는 claude 인자>
# 출력은 가린 인자의 JSON 배열입니다. 시드를 썼으면 Claude Code에 PG_MOD_SEED_FILE=<run_dir>/seed.json을 줍니다.
```

**정우 하네스(`m2.py`)에서 바꿔야 할 점** (이 저장소는 정우 저장소를 건드리지 않습니다):
- **재마스킹 횟수 (1b):** `audit_stats()`가 `finding_count`만 더합니다. audit 행의 `remasked_count`를 더한 `remasked`(가능하면 `source`별로도)를 `mod` 요약에 넣고, `report`의 조건별 표에 열로 내야 합니다. 값은 audit에 없으므로 개수만 다룹니다.
- **설정 기록 (1b):** `run_meta`에 Mod·탐지기가 받은 `PG_REMASK`와 탐지 설정(`PG_DETECTOR_FILTERS`, `PG_DETECTOR_FILTER_DUMMY`, `PG_REMASK_SHORT`, `PG_SHELL_POSITIONAL_MIN`, `PG_RULE_HEX_KEY`, `PG_PLACEHOLDER_GUIDE`, `PG_RESTORE_ESCAPED`)을 남겨야 on과 off를 나눠 볼 수 있습니다. 주지 않은 설정은 "기본값"으로 적습니다.
- **Windows의 promptguard 조건:** 탐지기 Python을 `.venv/bin/python`에서만 찾습니다. Windows에서는 `.venv/Scripts/python.exe`도 찾아야 합니다.
- **환경변수:** 탐지기 worker와 Claude Code는 둘 다 `clean_env()`로 셸의 `PG_*`를 그대로 받으므로 `PG_REMASK`는 따로 넘길 필요가 없습니다. 다만 실행 중에 셸 설정이 바뀌지 않게 위처럼 이름을 달리해 따로 돌립니다.
- **Guard 옵션 (2번):** 실행마다 Final Guard를 하나 띄워 Claude Code와 `api_capture.py` 프록시 사이에 둡니다.
  - Claude Code의 `ANTHROPIC_BASE_URL`은 Guard로, Guard의 `PG_UPSTREAM_BASE_URL`은 캡처 프록시로 둡니다. 그래야 캡처에 Guard를 통과한 요청만 남습니다.
  - Guard는 자기 탐지기 worker를 따로 씁니다(`PG_GUARD_DETECTOR_URL`). `PG_GUARD_COUNT_TOKENS`도 Guard 프로세스에 넘깁니다.
  - gold 조건 비교(1번)에서는 이 옵션을 끕니다.
- **시스템 프롬프트 가리기 (3번):** `--append-system-prompt`(또는 `--system-prompt`, `-file` 형태)를 넘기기 전에 위 명령으로 가린 인자로 바꿉니다. 시드를 썼으면 `PG_MOD_SEED_FILE`을 Claude Code 환경에 넣습니다. 탐지기 URL은 Mod가 쓰는 것과 같은 worker면 됩니다.
- **기록:** 실행별 `run_meta`에 Guard 사용 여부, `PG_GUARD_COUNT_TOKENS` 값, 시스템 프롬프트를 가렸는지를 남겨야 결과를 나눠 볼 수 있습니다.
- **대안:** 하네스가 `claude` 대신 `promptguard run -- <인자>`로 띄우면 Guard와 시스템 프롬프트 가리기가 함께 됩니다. 다만 이때는 gold 조건과 실제 탐지기가 섞이므로 2·3번에만 씁니다.

## 검증 결과

`majority` 정책, 3개 모듈 기준(이전 검증 결과):

- Ground truth: TP 32 / FP 0 / FN 0
- Precision / Recall / F1 / F2: 1.0
- 정책별 TP/FP/FN(같은 투표 결과 재사용): `any` 32/0/0, `majority`(=`at_least:2`) 32/0/0, `unanimous` 8/0/24
- 모듈 단독 TP/FP/FN: `credsweeper` 32/0/0, `promptguard-rules` 32/0/0, `gitleaks` 8/0/24
- `union` 정책(Shell-aware 포함)의 fixture·shell suite 수치는 [Shell-aware v0.2 보고서](docs/SHELL_AWARE_V0_2_UNION_MASKING.md)를 참고하세요. CredSweeper/Gitleaks를 포함한 재측정은 그 문서의 "PC에서 재측정" 절차로 다시 만듭니다.
- 합의 로직 단위 테스트(`tests/detector/test_consensus.py`): 19/19 PASS
- detector 단일 스캔 p50: 약 23ms (gitleaks 프로세스 기동이 대부분이며, 같은 머신에서 CredSweeper 단독은 약 0.4ms)
- 5MB scan: 약 3.8초 (같은 macOS 머신에서 CredSweeper 단독은 약 3.3초)
- parallel 20/20 PASS, crash/timeout/malformed/invalid span/Unicode mismatch fail-closed: V0 Guard 검증 결과입니다. 이번 변경에서는 worker 수준의 장애 주입(`ok=false`)만 다시 확인했습니다.

지연 시간이 중요하면 `detector.json`에서 gitleaks 항목에 `"enabled": false`를 지정하면 됩니다.

기계 판독 결과는 `outputs/`에 있습니다. Shell-aware 설계, union 마스킹, 한계는 [v0.2 보고서](docs/SHELL_AWARE_V0_2_UNION_MASKING.md)를 참고하세요. v0.1 보고서는 ML adapter 수치가 섞여 있어 삭제했습니다(커밋 `e7b15df`에 남아 있음).

## 중요 제한

`promptguard run`은 실제 provider forwarding Final Guard를 사용합니다. 반면 기존 `start-promptguard.*`는 **Mod-only 체험 모드**라서 provider-bound fail-closed를 보장하지 않습니다. synthetic mock provider/Guard/detector fixture는 production source가 아닌 `tests/observability/`와 `tests/final-guard/`에만 있습니다. 실제 credential을 repository나 fixture에 넣지 말고, 포함된 synthetic 프로젝트로 먼저 검증하세요.

또한 Claude Code 2.1.291의 `--append-system-prompt`는 Native Mod 훅에 보이지 않아 Mod가 변환할 수 없습니다. 검증 환경에서는 Final Guard가 이를 차단했습니다.

## 구성

```text
src/native-mod/             Claude Code Native Mod
src/detector/               detector worker, adapters, consensus + local MCP bridge
src/guard/                  production Final Guard
src/supervisor/             cross-platform lifecycle/readiness/restart supervisor
src/launcher/               promptguard CLI
src/audit/                  raw-free audit writer
sample-protected-project/   synthetic credential demo
fixtures/                   labeled positive/negative corpus
tests/                      detector/span/performance/Mod/Final Guard/observability/E2E tests
outputs/                    machine-readable validation results
```

## Observability Web UI

`promptguard run`(또는 기존 launcher)을 실행해 둔 상태에서, 별도 터미널에서 Node.js 22 이상으로 실행하세요.

```bash
node src/observability/server.mjs
```

브라우저에서 `http://127.0.0.1:18880`을 열면 Runtime V1의 `.promptguard/audit/mod-audit.json`과 `guard-audit.jsonl`을 읽습니다. 기존 Mod-only `.runtime/audit/` 기록도 fallback으로 지원합니다. `PG_MOD_AUDIT`와 `PG_GUARD_AUDIT`로 특정 파일을 지정할 수 있습니다. UI 실행에는 npm 패키지가 필요하지 않습니다.

- Pipeline, session summary, event timeline, detector/rule/span 상세, Read/tool activity, replacement preview
- Live 데이터와 완전히 분리된 **DEMO / MOCK** 시나리오 선택
- 선택한 session hash와 연결되는 실제 Final Guard audit이 있으면 최종 SAFE/BLOCKED, finding, latency, upstream status 표시
- 실제 원문이나 raw tool output을 브라우저로 보내지 않음
- Turn ID, 파일 경로, 고유 파일 수와 미제공 metadata는 추측하지 않고 unavailable 표시

[구조·보안 경계·실행 및 테스트 설명](docs/OBSERVABILITY.md)
