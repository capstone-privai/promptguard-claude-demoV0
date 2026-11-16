# 자리표시자 공개 접두어 표

`PG_PLACEHOLDER_PUBLIC_PREFIX=on`이면 Native Mod가 이 표를 읽어, 표에 있는 접두어로 시작하는 값을 `접두어[TYPE_N]`으로 가린다. 예: `sk_live_[STRIPE_SECRET_KEY_1]`. 기본값은 꺼짐이다.

- 표에 없는 값과, 접두어를 뺀 나머지가 16자 미만인 값은 전체를 가린다.
- 표를 읽지 못하면 켜져 있어도 전체를 가린다.
- 코드는 아래 표의 각 행에서 앞 두 칸(접두어, TYPE)을 읽는다. 첫 칸은 백틱으로 감싸야 한다.

| 접두어 | TYPE | 출처 | 접두어가 알려 주는 것 |
|---|---|---|---|
| `AKIA` | AWS_ACCESS_KEY_ID | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html | AWS 액세스 키 ID |
| `ASIA` | AWS_ACCESS_KEY_ID | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html | AWS STS가 발급한 임시 액세스 키 ID |
| `ghp_` | GITHUB_TOKEN | https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types | 개인 액세스 토큰(classic), 장기, 사용자 계정 |
| `gho_` | GITHUB_TOKEN | https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types | OAuth 앱 액세스 토큰, 장기 |
| `ghu_` | GITHUB_TOKEN | https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types | GitHub App 사용자 액세스 토큰, 기본 8시간 |
| `ghs_` | GITHUB_TOKEN | https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types | GitHub App 설치 액세스 토큰, 1시간 |
| `ghr_` | GITHUB_TOKEN | https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types | GitHub App 갱신 토큰, 6개월 |
| `github_pat_` | GITHUB_TOKEN | https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types | 세분화된 개인 액세스 토큰, 최대 1년 또는 만료 없음 |
| `sk_live_` | STRIPE_SECRET_KEY | https://docs.stripe.com/keys | 운영 환경, 제한 없는 비밀 키 |
| `sk_test_` | STRIPE_SECRET_KEY | https://docs.stripe.com/keys | 샌드박스(테스트), 제한 없는 비밀 키 |
| `rk_live_` | STRIPE_RESTRICTED_KEY | https://docs.stripe.com/keys | 운영 환경, 권한을 제한한 키 |
| `rk_test_` | STRIPE_RESTRICTED_KEY | https://docs.stripe.com/keys | 샌드박스(테스트), 권한을 제한한 키 |
| `xoxb-` | SLACK_TOKEN | https://docs.slack.dev/authentication/tokens/ | 봇 토큰 |
| `xoxp-` | SLACK_TOKEN | https://docs.slack.dev/authentication/tokens/ | 사용자 토큰 |
| `xapp-` | SLACK_TOKEN | https://docs.slack.dev/authentication/tokens/ | 앱 수준 토큰 |
| `sk-ant-` | ANTHROPIC_API_KEY | https://platform.claude.com/docs/en/get-api-key | Anthropic API 키. 키 유형(개인, 서비스 계정 등)은 알려 주지 않는다 |
| `glpat-` | GITLAB_TOKEN | https://docs.gitlab.com/security/tokens/ | GitLab 개인, 프로젝트, 그룹, 대리 액세스 토큰(서로 구분되지 않음). 개인 액세스 토큰의 접두어는 바꿀 수 있어서, 바꾼 인스턴스의 값은 이 행에 맞지 않는다 |

출처는 2026-11-11에 각 페이지 본문에서 확인했다.

## 넣지 않은 후보

- OpenAI `sk-proj-`: 읽을 수 있었던 OpenAI 공식 페이지에서 이 접두어를 찾지 못했다. API 참조는 `sk-abc...def` 같은 일반 예시만 보여 주고, 다른 두 페이지는 403으로 열리지 않았다.
- Google `AIza`: Google Cloud 문서에 예시 값으로만 나오고, 키 문자열의 형식으로 명시되어 있지 않다.

## 알아둘 점

- AWS 문서는 접두어가 만든 시점에 따라 달라질 수 있다고 적고 있다.
- Slack의 순환 앱 수준 토큰은 `xoxe.xapp-`로 시작하므로 `xapp-` 행에 맞지 않는다.
- 맞지 않는 값은 전체를 가리므로, 이런 경우에도 값이 드러나지는 않는다.
