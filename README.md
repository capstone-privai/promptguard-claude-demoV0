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

끄려면 `PG_RESTORE_PLACEHOLDERS=off`를 지정합니다.

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

`PG_DETECTOR_CANDIDATE_POLICY=majority`로 실행하면 설정 파일을 고치지 않고 기존 동작으로 돌아갑니다. 탐지기는 `promptguard run --enable ml-v9 --disable shell-aware --policy union`처럼 실행 옵션으로 켜고 끕니다(`promptguard --help`). 준비와 옵션은 [ML adapter 문서](docs/ML_ADAPTERS.md)를 참고하세요.

| adapter 이름 | 종류 | 구현 |
| --- | --- | --- |
| `credsweeper` | 오픈소스 (Python 라이브러리) | `src/detector/pgdetector/adapters/credsweeper.py` |
| `gitleaks` | 오픈소스 (Go 바이너리, `gitleaks stdin`) | `src/detector/pgdetector/adapters/gitleaks.py` |
| `promptguard-rules` | 직접 만든 모듈 (순수 Python 정규식/키 분류) | `src/detector/pgdetector/adapters/patterns.py` |
| `shell-aware` | command/source/sink 의미 기반 candidate generator | `src/detector/pgdetector/adapters/shell_aware.py` |
| `ml-v9` | 팀 mmBERT span 모델 (기본 꺼짐) | `src/detector/pgdetector/adapters/span_models.py` |
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
