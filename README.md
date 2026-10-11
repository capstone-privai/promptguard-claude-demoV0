# PromptGuard Claude Demo V0

Claude Code 2.1.291 Native Mod와 CredSweeper 1.19.0을 이용해 prompt/context/tool output의 credential **값만** placeholder로 바꾸는 Windows/macOS용 portable demo입니다.

> 이 저장소의 password, API key, token, PEM은 모두 비기능 synthetic fixture입니다. 실제 credential은 포함하지 않습니다.

## 준비물

- Windows PowerShell 5.1 이상 또는 macOS의 Bash
- Python 3.12 (PATH 등록)
- Node.js LTS
- macOS: Xcode Command Line Tools (`xcode-select --install`)
- Claude Code 2.1.291
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

## 검증 결과

- Ground truth: TP 32 / FP 0 / FN 0
- Precision / Recall / F1 / F2: 1.0
- parallel 20/20 PASS
- 5MB scan: 약 2.30초
- crash/timeout/malformed/invalid span/Unicode mismatch: validation Guard에서 fail-closed 확인

기계 판독 결과는 `outputs/`에 있습니다.

## 중요 제한

portable launcher는 **Mod-only 체험 모드**입니다. repository의 `src/guard/server.cjs`는 검증용 mock endpoint이며 실제 Anthropic provider forwarding proxy가 아닙니다. 따라서 detector나 Mod 장애 시 실제 provider-bound fail-closed를 보장하지 않습니다. 실제 민감정보 대신 우선 포함된 synthetic 프로젝트로 테스트하세요.

또한 Claude Code 2.1.291의 `--append-system-prompt`는 Native Mod 훅에 보이지 않아 Mod가 변환할 수 없습니다. 검증 환경에서는 Final Guard가 이를 차단했습니다.

## 구성

```text
src/native-mod/             Claude Code Native Mod
src/credsweeper-adapter/    CredSweeper worker + local MCP bridge
src/guard/                  validation-only Final Guard mock
sample-protected-project/   synthetic credential demo
fixtures/                   labeled positive/negative corpus
tests/                      detector/span/performance tests
outputs/                    machine-readable validation results
```

## Observability Web UI

기존 launcher는 그대로 사용합니다. 별도 터미널에서 Node.js 22 이상으로 실행하세요.

```bash
node src/observability/server.mjs
```

브라우저에서 `http://127.0.0.1:18880`을 열면 `.runtime/audit/`의 최신 Mod audit를 읽습니다.
`PG_MOD_AUDIT`로 특정 audit 파일을 지정할 수 있습니다. UI 실행에는 npm 패키지가 필요하지 않습니다.

- Pipeline, session summary, event timeline, detector/rule/span 상세, Read/tool activity, replacement preview
- Live 데이터와 완전히 분리된 **DEMO / MOCK** 시나리오 선택
- 실제 provider-bound 검증이 없으므로 최종 Cloud egress는 항상 **NOT VERIFIED**
- 실제 원문이나 raw tool output을 브라우저로 보내지 않음
- Turn ID, 파일 경로, 고유 파일 수와 미제공 metadata는 추측하지 않고 unavailable 표시

[구조·보안 경계·실행 및 테스트 설명](docs/OBSERVABILITY.md)
