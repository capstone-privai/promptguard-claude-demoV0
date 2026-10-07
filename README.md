# PromptGuard Claude Demo V0

Claude Code 2.1.291 Native Mod와 CredSweeper 1.19.0을 이용해 prompt/context/tool output의 credential **값만** placeholder로 바꾸는 Windows용 portable demo입니다.

> 이 저장소의 password, API key, token, PEM은 모두 비기능 synthetic fixture입니다. 실제 credential은 포함하지 않습니다.

## 준비물

- Windows PowerShell 5.1 이상
- Python 3.12 (PATH 등록)
- Node.js LTS
- Claude Code 2.1.291
- Claude Pro/Max/Team/Enterprise 계정 또는 Anthropic Console billing

Claude Code가 없다면:

```powershell
npm install -g @anthropic-ai/claude-code@2.1.291
```

## 1. 설치

저장소를 clone한 뒤 실행합니다. `.cmd` wrapper가 현재 PowerShell execution policy를 영구 변경하지 않고 설치 스크립트를 실행합니다.

```powershell
git clone https://github.com/capstone-privai/promptguard-claude-demoV0.git
cd promptguard-claude-demoV0
.\install.cmd
```

설치 시 repository-local `.venv`에 `credsweeper==1.19.0`을 고정 설치합니다.
`py -3.12` 또는 PATH의 `python`을 자동 탐색합니다. 별도 Python 경로를 써야 한다면 `PROMPTGUARD_PYTHON` 환경 변수에 `python.exe` 경로를 지정할 수 있습니다.

## 2. synthetic 보호 프로젝트에서 실행

```powershell
cd sample-protected-project
..\start-promptguard.cmd
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

보호하려는 프로젝트로 이동한 뒤 이 repository의 launcher를 절대 경로로 호출합니다.

```powershell
cd C:\path\to\your-project
C:\path\to\promptguard-claude-demoV0\start-promptguard.cmd
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
