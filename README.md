# PromptGuard Claude Demo V0

Claude Code 2.1.291 Native Mod와 여러 detector 모듈(CredSweeper 1.19.0, Gitleaks, 자체 룰)의 합의 판정을 이용해 prompt/context/tool output의 credential **값만** placeholder로 바꾸는 Windows/macOS용 portable demo입니다.

> 이 저장소의 password, API key, token, PEM은 모두 비기능 synthetic fixture입니다. 실제 credential은 포함하지 않습니다.

## 준비물

- Windows PowerShell 5.1 이상 또는 macOS의 Bash
- Python 3.12 (PATH 등록)
- Node.js LTS
- macOS: Xcode Command Line Tools (`xcode-select --install`)
- Claude Code 2.1.291
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
`py -3.12` 또는 PATH의 `python`을 자동 탐색합니다. 별도 Python 경로를 써야 한다면 `PROMPTGUARD_PYTHON` 환경 변수에 `python.exe` 경로를 지정할 수 있습니다.

### macOS

```bash
git clone https://github.com/capstone-privai/promptguard-claude-demoV0.git
cd promptguard-claude-demoV0
chmod +x install.sh start-promptguard.sh
./install.sh
```

Python 3.12나 Node.js가 없다면 Homebrew를 사용하는 환경에서는 `brew install python@3.12 node`로 설치할 수 있습니다. 별도 Python 경로를 사용하려면 `PROMPTGUARD_PYTHON=/path/to/python3.12 ./install.sh`처럼 지정합니다.

## 2. synthetic 보호 프로젝트에서 실행

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

Claude 로그인 화면이 처음 나오면 구독 계정 사용자는 `Claude account with subscription`을 선택합니다. 계정이나 token을 팀원끼리 공유하지 마세요.

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
- raw-free audit은 `.runtime/audit/`에 생성

## 3. 다른 프로젝트에서 실행

Windows:

보호하려는 프로젝트로 이동한 뒤 이 repository의 launcher를 절대 경로로 호출합니다.

```powershell
cd C:\path\to\your-project
C:\path\to\promptguard-claude-demoV0\start-promptguard.cmd
```

macOS:

```bash
cd /path/to/your-project
/path/to/promptguard-claude-demoV0/start-promptguard.sh
```

## 4. Detector 모듈과 합의 정책

detector는 여러 모듈을 **adapter**로 감싸 같은 인터페이스(`name`, `version`, `scan(text)`)로 다룹니다. detector 입장에서는 이름만 다른 adapter 여럿이 각자 span에 투표하는 구조이며, 합의 정책을 통과한 span만 placeholder로 바뀝니다.

| adapter 이름 | 종류 | 구현 |
| --- | --- | --- |
| `credsweeper` | 오픈소스 (Python 라이브러리) | `src/detector/pgdetector/adapters/credsweeper.py` |
| `gitleaks` | 오픈소스 (Go 바이너리, `gitleaks stdin`) | `src/detector/pgdetector/adapters/gitleaks.py` |
| `promptguard-rules` | 직접 만든 모듈 (순수 Python 정규식/키 분류) | `src/detector/pgdetector/adapters/patterns.py` |

모듈 목록과 정책은 `src/detector/detector.json`에서 지정합니다.

```json
{
  "consensus": { "mode": "majority" },
  "adapters": [
    { "name": "credsweeper", "type": "credsweeper", "required": true, "options": { ... } },
    { "name": "gitleaks", "type": "gitleaks", "required": false, "options": { ... } },
    { "name": "promptguard-rules", "type": "patterns", "required": true, "options": { ... } }
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
PG_DETECTOR_CONSENSUS=unanimous ../start-promptguard.sh
```

```powershell
$env:PG_DETECTOR_CONSENSUS = 'at_least:2'; ..\start-promptguard.cmd
```

launcher는 시작할 때 활성 모듈과 정책을 출력합니다(`Detector: credsweeper, gitleaks, promptguard-rules (consensus majority, 2 vote(s) needed)`).

판정 규칙:

- 서로 다른 모듈의 span이 한 글자라도 겹치면 같은 영역에 동의한 것으로 셉니다. 도구마다 `key=value` 전체를 잡거나 값만 잡는 등 경계가 다르기 때문입니다. 같은 모듈이 여러 번 탐지해도 1표입니다.
- 채택된 영역은 동의한 span들의 합집합으로 가립니다. 일부 모듈이 값을 짧게 잡아도 나머지 부분이 노출되지 않게 하기 위해서입니다.
- finding의 `rule_id`에는 동의한 모듈과 룰이 `credsweeper:Password+promptguard-rules:secret-assignment` 형식으로 남습니다.
- 실행 중 한 모듈이라도 실패하면 해당 요청은 `ADAPTER_FAILURE:<이름>` 오류로 fail-closed 됩니다.
- `required: false` 모듈은 도구가 설치되지 않았으면 시작 시 제외되고, 투표 수(N)에서도 빠집니다. 활성 모듈 수보다 큰 `at_least` 값은 아무것도 가리지 못하게 되므로 worker가 시작을 거부합니다.

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

기본 설정(3개 모듈, `majority`) 기준:

- Ground truth: TP 32 / FP 0 / FN 0
- Precision / Recall / F1 / F2: 1.0
- 정책별 TP/FP/FN(같은 투표 결과 재사용): `any` 32/0/0, `majority`(=`at_least:2`) 32/0/0, `unanimous` 8/0/24
- 모듈 단독 TP/FP/FN: `credsweeper` 32/0/0, `promptguard-rules` 32/0/0, `gitleaks` 8/0/24
- 합의 로직 단위 테스트(`tests/detector/test_consensus.py`): 19/19 PASS
- detector 단일 스캔 p50: 약 23ms (gitleaks 프로세스 기동이 대부분이며, 같은 머신에서 CredSweeper 단독은 약 0.4ms)
- 5MB scan: 약 3.8초 (같은 macOS 머신에서 CredSweeper 단독은 약 3.3초)
- parallel 20/20 PASS, crash/timeout/malformed/invalid span/Unicode mismatch fail-closed: V0 Guard 검증 결과입니다. 이번 변경에서는 worker 수준의 장애 주입(`ok=false`)만 다시 확인했습니다.

지연 시간이 중요하면 `detector.json`에서 gitleaks 항목에 `"enabled": false`를 지정하면 됩니다.

기계 판독 결과는 `outputs/`에 있습니다.

## 중요 제한

portable launcher는 **Mod-only 체험 모드**입니다. repository의 `src/guard/server.cjs`는 검증용 mock endpoint이며 실제 Anthropic provider forwarding proxy가 아닙니다. 따라서 detector나 Mod 장애 시 실제 provider-bound fail-closed를 보장하지 않습니다. 실제 민감정보 대신 우선 포함된 synthetic 프로젝트로 테스트하세요.

또한 Claude Code 2.1.291의 `--append-system-prompt`는 Native Mod 훅에 보이지 않아 Mod가 변환할 수 없습니다. 검증 환경에서는 Final Guard가 이를 차단했습니다.

## 구성

```text
src/native-mod/             Claude Code Native Mod
src/detector/               detector worker, adapters, consensus + local MCP bridge
src/guard/                  validation-only Final Guard mock
sample-protected-project/   synthetic credential demo
fixtures/                   labeled positive/negative corpus
tests/                      detector/span/performance tests
outputs/                    machine-readable validation results
```
