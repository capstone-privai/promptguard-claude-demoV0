# PromptGuard Runtime V1

Runtime V1은 Native Mod의 사전 변환과 provider 직전의 Final Transmission Guard를 하나의 fail-closed 실행 경로로 묶습니다. Windows에서는 `promptguard.cmd`, macOS/Linux에서는 `promptguard`를 사용합니다.

## 요청 경로

```text
project files / tool output
        |
        v
Claude Code + Native Mod ----> transform detector (127.0.0.1:18771)
        |
        | provider request forced through ANTHROPIC_BASE_URL
        v
Final Guard (127.0.0.1:18191) ---> verification detector (127.0.0.1:18772)
        |
        | only after a clean, well-formed scan
        v
configured Anthropic upstream
```

두 detector는 같은 `src/detector/detector.json` ensemble을 로드하지만 서로 다른 process와 port를 사용합니다. Supervisor는 두 worker와 Guard가 모두 ready가 되기 전에는 Claude Code를 시작하지 않습니다. 실행 중 필수 service가 죽으면 제한된 backoff restart를 시도하며, 보호 상태를 복구할 수 없으면 Claude와 전체 runtime을 종료합니다.

## Final Guard 정책

- loopback에만 bind합니다.
- `POST /v1/messages`와 `POST /v1/messages/count_tokens`만 허용합니다.
- `application/json`의 모든 문자열 leaf를 검사합니다. 같은 문자열은 요청마다 한 번만 검사합니다.
- detector가 이미 깨끗하다고 판정한 문자열은 Guard process 메모리에 기억하고 다시 검사하지 않습니다. 원문이 아니라 process마다 새로 만든 key의 HMAC만 보관하며(최대 100,000개), finding이 나온 문자열은 캐시하지 않아 매 요청 다시 검사되고 차단됩니다. 매 turn 반복되는 system prompt와 tool 정의는 첫 요청에서만 검사되므로, 이후 요청은 새로 추가된 대화만 검사합니다.
- 캐시되지 않은 문자열은 256개 단위 batch로 detector에 보내며 batch마다 timeout을 따로 적용합니다. 이미 끝난 batch의 결과는 캐시에 남으므로 첫 요청이 timeout되더라도 client 재시도 때 이어서 검사합니다. finding이 나온 batch에서 검사를 멈추고 차단합니다.
- detector finding, timeout, 연결 실패, HTTP 오류, malformed/불일치 응답을 모두 차단합니다.
- body 크기, 수신 시간, 문자열 leaf 수(요청당 65,536개)를 제한합니다.
- 검사를 통과한 원본 byte만 설정된 upstream으로 전달하고 response는 streaming passthrough합니다.
- authorization 등 provider 인증 header는 전달하지만 Guard/detector process 환경이나 audit에는 복사하지 않습니다.

## 실행과 상태 확인

```bash
./promptguard run
./promptguard run -- --resume
./promptguard run --no-claude
./promptguard status
./promptguard status --json
```

PowerShell에서는 같은 명령을 `promptguard.cmd`로 실행합니다. `run`은 foreground supervisor이므로 종료하려면 해당 터미널에서 `Ctrl+C`를 누릅니다.

기본 설정은 `promptguard.config.json`입니다. 다른 설정은 `--config FILE`, runtime metadata 위치는 `--runtime-dir DIR`로 지정합니다. 주요 환경 변수 override는 `PG_UPSTREAM_BASE_URL`, `PG_PYTHON`, `PG_CLAUDE_BINARY`, `PG_GUARD_PORT`, `PG_MOD_DETECTOR_PORT`, `PG_GUARD_DETECTOR_PORT`, `PG_DETECTOR_TIMEOUT_MS`(Guard는 batch당 적용), `PG_MAX_BODY_BYTES`, `PG_AUDIT_PATH`, `PG_MOD_CONNECT_WAIT_MS`입니다.

Native Mod의 detector MCP 서버는 세션 시작 후 background로 연결되므로, Mod는 첫 연결까지만 detector 호출을 재시도합니다(`PG_MOD_CONNECT_WAIT_MS`, 기본 15초). 예외를 던진 훅은 Claude Code가 건너뛰기 때문에, 기다리지 않으면 세션 시작 직후의 CLAUDE.md 등이 마스킹 없이 Guard까지 가게 됩니다. 한 번 연결된 뒤의 detector 실패는 기다리지 않고 바로 실패합니다.

Supervisor는 Python 3.12와 3.14 detector worker를 모두 받습니다.

## Audit와 상태 데이터

`.promptguard/runtime-state.json`과 `.promptguard/audit/`에는 service 상태, count, latency, 결정 코드, endpoint, body size, finding type 같은 metadata만 기록합니다. 요청/응답 원문, detector 입력, finding 값, authorization header, credential은 기록하지 않습니다.

## 보안 경계와 한계

Final Guard는 Native Mod가 비활성화되거나 변환 뒤 raw 값이 다시 생기는 경우에도 provider 직전에서 별도로 차단하고, detector worker 장애에는 fail-closed 합니다. 그러나 같은 detector ensemble과 규칙을 사용하므로 모든 adapter가 공통으로 놓치는 credential 형식은 두 단계 모두 통과할 수 있습니다. 이것은 detector 다양화, 정책 튜닝, labeled corpus 회귀 테스트로 관리해야 합니다.

Guard를 우회해 `ANTHROPIC_BASE_URL`을 다른 곳으로 지정한 별도 Claude process를 실행하는 행위, Claude Code 외의 독립 network client, endpoint pinning을 우회하는 로컬 관리자 공격은 이 portable demo의 보호 범위 밖입니다.

## 검증 명령

```bash
npm run check:runtime
npm run selftest:runtime
npm run test:final-guard
npm test
npm run lint
npm run typecheck
npm run build
```
