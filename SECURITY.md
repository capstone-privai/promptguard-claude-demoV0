# Security notice

- 이 repository의 credential-like 값은 모두 비기능 synthetic fixture입니다.
- 실제 password, API key, token, private key를 commit하지 마세요.
- `.runtime/`, `.promptguard/`, `.venv/`, local audit는 Git에서 제외됩니다. Claude transcript는 repository 밖(`~/.claude/projects/`)에 저장됩니다.
- 권장 `promptguard run` 경로는 Claude Code의 provider base URL을 loopback Final Transmission Guard로 강제하고, 요청 본문을 독립 detector worker로 다시 검사합니다. detector 오류·timeout·malformed result·finding은 provider 전송 전에 fail-closed 됩니다.
- 보호는 `promptguard run`이 Claude Code를 띄울 때만 적용됩니다. 보호 프로젝트 폴더에서 `claude`를 직접 실행하면 Mod와 Final Guard가 모두 빠집니다.
- 기존 `start-promptguard.*`는 호환용 Native Mod-only 체험 경로입니다. 이 경로에는 provider-bound 차단 보장이 없습니다.
- Claude Code는 예외를 던진 Native Mod 훅을 건너뛰고 진행합니다. 따라서 Mod 단독으로는 fail-closed가 아니며, detector 장애 시 원문을 막는 최종 방어선은 Final Guard입니다.
- Mod와 Final Guard는 서로 다른 worker/process를 사용하지만 같은 detector ensemble 및 설정을 사용합니다. 프로세스 장애와 변환 이후 재노출에는 방어층이 되지만, 동일한 탐지 규칙의 공통 blind spot까지 해결하지는 않습니다.
- Final Guard는 detector가 깨끗하다고 판정한 문자열의 HMAC(process마다 새 key)만 메모리에 보관해 재검사를 생략합니다. 원문은 보관하지 않고, finding이 나온 문자열은 캐시하지 않습니다.
- audit에는 원문, credential 값, authorization header를 기록하지 않습니다. 그래도 실제 민감 프로젝트에 적용하기 전에는 threat model, local persistence, detector coverage와 upstream 설정을 별도로 검토하세요.
