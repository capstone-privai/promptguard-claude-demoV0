# 짧은 값 재마스킹 (`PG_REMASK_SHORT`, `PG_SHELL_POSITIONAL_MIN`)

## 왜

정우의 668c2c1 미탐·오탐 분석(CredData-trajectory test)에서 다음 일이 확인됐다.

1. shell-aware가 `CreateOrUpdateEnvSecret(ctx, 1, "e", input)`의 `"e"`를 비밀값으로 냈다. 함수 이름의 단서(Secret)로 잡는 위치 인자이고, 최소 길이가 1이다.
2. Native Mod의 재마스킹(`remaskText`)은 그 뒤 출력 전체의 `e`를 가렸다. 전체 값 재마스킹은 `includes/split/join`으로 부분 문자열을 바꾸므로, 최소 길이도 단어 경계도 없다.
3. 그 결과 16진수 키 24개가 "일부만 찾음"이 됐다.

짧은 진짜 비밀번호(`mgb`, `45678`)를 잡게 되면 같은 일이 그 값에서도 생긴다.

## 설정

release/defaults-1120부터 두 설정 모두 새 기본값을 쓴다(정우 측정: 재마스킹 오탐 −91%, 새로 놓친 정답 0). 이전 동작은 `PG_SHELL_POSITIONAL_MIN=1`, `PG_REMASK_SHORT=substring`이다.

| 설정 | 기본 | 값별 동작 |
|---|---|---|
| `PG_SHELL_POSITIONAL_MIN` | `4` | shell-aware `function_argument`가 함수 이름 단서만으로 잡는 위치 인자 리터럴은 이 길이 미만이면 내지 않는다. `4`가 CredSweeper와 같은 기준이다. 빈 값은 기본값(4), 정수가 아니거나 1보다 작으면 1로 본다 |
| `PG_REMASK_SHORT` | `boundary` | `boundary`: 8자 미만 값은 앞뒤 글자가 `[A-Za-z0-9_]`가 아닐 때만 다시 가린다. 8자 이상은 부분 문자열로 가린다. `substring`(또는 그 밖의 값): 모든 값을 부분 문자열로 가린다(이전 동작) |

### `PG_SHELL_POSITIONAL_MIN`이 바꾸는 범위 (shell-aware 규칙별)

| 규칙 | 바뀌나 |
|---|---|
| `function_argument`: 함수 이름 단서로 잡는 마지막 위치 인자 리터럴 (`login('admin', 'mgb')`) | 바뀐다. 설정값 미만이면 내지 않는다 |
| `function_argument`: 비밀 이름의 키워드 인자 (`connect(password="e")`) | 바뀌지 않는다 (`min_value_length` 1) |
| `long_option`, `short_option`, `powershell_param`, `powershell_securestring`, `stdin_sink`, 히어 문자열·히어 문서, `expect_send` | 바뀌지 않는다 |

### `PG_REMASK_SHORT=boundary`의 경계

- **경계로 보는 것:** `[A-Za-z0-9_]`가 아닌 모든 글자와 텍스트의 시작·끝이다. 따옴표, 괄호, 대괄호, 공백, 탭, 줄 끝, `=`, `;`, `-`, `.`가 여기에 든다.
- **한글도 경계다.** `비밀번호는mgb입니다`의 `mgb`는 가린다. 한글 조사가 붙은 진짜 값을 놓치지 않으려는 선택이고, 테스트로 고정했다.
- **가리지 않는 것:** `mgbx`, `xmgb`, `mgb_1`, `456789` 안의 값이다.
- **복원했던 짧은 값:** 명령 출력에 다시 나올 때 같은 규칙을 쓴다.
- **바뀌지 않는 것:** 부분 재마스킹(`remaskPartial`, `PART_MIN` 8)은 그대로다.

## 측정 (정우)

`eval/integration-1118`부터는 `scripts/eval_integration/run.py`가 한 번에 돌린다. 5번 설정(+REMASK_SHORT=boundary+POSITIONAL_MIN=4)이 이 PR이다. 실행 방법과 표의 열은 README의 "통합 측정"에 있다. 이 PR의 `scripts/remask_floor/run_eval.py`·`compare.py`는 그 실행기로 옮겨 합쳤다.

- **탐지기 설정:** `PG_SHELL_POSITIONAL_MIN`은 채점기가 같은 프로세스에서 부르는 탐지기가 읽는다.
- **Mod 설정:** `PG_REMASK_SHORT`는 Native Mod의 설정이라, 채점기의 Mod 복제(`ModSession`)에 짧은 값 부분만 `register.mjs`와 같은 규칙으로 바꿔 끼운다(`scripts/eval_integration/instrument.py`의 `install_boundary`, 코드 그대로). 8자 이상과 부분 재마스킹은 채점기 코드를 그대로 쓴다.

**채택 기준:** 고유 값 기준 recall 손실 0, 그리고 재마스킹 오탐 감소. 통합 표의 5번과 2번을 비교한다("못 가린 span / 고유 값", "재마스킹 오탐", "새로 놓친 정답").
