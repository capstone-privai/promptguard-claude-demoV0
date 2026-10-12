# Security notice

- 이 repository의 credential-like 값은 모두 비기능 synthetic fixture입니다.
- 실제 password, API key, token, private key를 commit하지 마세요.
- `.runtime/`, `.venv/`, local audit, Claude transcript는 Git에서 제외됩니다.
- 권장 `promptguard run` 경로는 Claude Code의 provider base URL을 loopback Final Transmission Guard로 강제하고, 요청 본문을 독립 detector worker로 다시 검사합니다. detector 오류·timeout·malformed result·finding은 provider 전송 전에 fail-closed 됩니다.
- 기존 `start-promptguard.*`는 호환용 Native Mod-only 체험 경로입니다. 이 경로에는 provider-bound 차단 보장이 없습니다.
- Mod와 Final Guard는 서로 다른 worker/process를 사용하지만 같은 detector ensemble 및 설정을 사용합니다. 프로세스 장애와 변환 이후 재노출에는 방어층이 되지만, 동일한 탐지 규칙의 공통 blind spot까지 해결하지는 않습니다.
- audit에는 원문, credential 값, authorization header를 기록하지 않습니다. 그래도 실제 민감 프로젝트에 적용하기 전에는 threat model, local persistence, detector coverage와 upstream 설정을 별도로 검토하세요.
