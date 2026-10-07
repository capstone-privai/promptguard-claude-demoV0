# Security notice

- 이 repository의 credential-like 값은 모두 비기능 synthetic fixture입니다.
- 실제 password, API key, token, private key를 commit하지 마세요.
- `.runtime/`, `.venv/`, local audit, Claude transcript는 Git에서 제외됩니다.
- 현재 portable launcher는 Native Mod-only 체험 모드입니다. detector/Mod 장애까지 막는 실제 provider용 Final Transmission Guard는 제공하지 않습니다.
- 실제 민감 프로젝트에 적용하기 전에 별도 threat model, local persistence 검토, provider-bound Guard 배포가 필요합니다.
