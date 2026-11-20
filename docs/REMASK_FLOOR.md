# 짧은 값 재마스킹 (`PG_REMASK_SHORT`, `PG_SHELL_POSITIONAL_MIN`)

## 왜

정우의 668c2c1 미탐·오탐 분석(CredData-trajectory test)에서 다음 일이 확인됐다.

1. shell-aware가 `CreateOrUpdateEnvSecret(ctx, 1, "e", input)`의 `"e"`를 비밀값으로 냈다. 함수 이름의 단서(Secret)로 잡는 위치 인자이고, 최소 길이가 1이다.
2. Native Mod의 재마스킹(`remaskText`)은 그 뒤 출력 전체의 `e`를 가렸다. 전체 값 재마스킹은 `includes/split/join`으로 부분 문자열을 바꾸므로, 최소 길이도 단어 경계도 없다.
3. 그 결과 16진수 키 24개가 "일부만 찾음"이 됐다.

짧은 진짜 비밀번호(`mgb`, `45678`)를 잡게 되면 같은 일이 그 값에서도 생긴다.

## 설정

두 설정 모두 기본값은 지금 동작이다. 정우의 측정 뒤에 기본값을 정한다.

| 설정 | 기본 | 바꾸면 |
|---|---|---|
| `PG_SHELL_POSITIONAL_MIN` | `1` | shell-aware `function_argument`가 함수 이름 단서만으로 잡는 위치 인자 리터럴은 이 길이 미만이면 내지 않는다. `4`가 CredSweeper와 같은 기준이다. 정수가 아니거나 1보다 작으면 1로 본다 |
| `PG_REMASK_SHORT` | `substring` | `boundary`: 8자 미만 값은 앞뒤 글자가 `[A-Za-z0-9_]`가 아닐 때만 다시 가린다. 8자 이상은 지금처럼 부분 문자열로 가린다 |

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

promptguard-data 루트에서, 이 브랜치의 PromptGuard(`$PG`)로 ML을 끄고(기본) 돌린다.

`scripts/remask_floor/run_eval.py`는 채점기를 고치지 않는다.
- **탐지기 설정:** `PG_SHELL_POSITIONAL_MIN`은 채점기가 같은 프로세스에서 부르는 탐지기가 읽는다.
- **Mod 설정:** `PG_REMASK_SHORT`는 Native Mod의 설정이다. 채점기의 Mod 복제(`ModSession`)에는 이 규칙이 없으므로, 실행 중에만 짧은 값 부분을 `register.mjs`와 같은 규칙으로 바꿔 끼운다. 8자 이상과 부분 재마스킹은 채점기 코드를 그대로 쓴다.
- **`--config`:** `default`, `boundary`, `min4`, `floor`(boundary + 4)가 있다. 원인을 나눠 보려면 `boundary`와 `min4`도 돌린다.

#23의 `scripts/detector_filters/compare.py`는 main에 없고, 고유 값 수와 16진수 키 행이 없어서 쓰지 않았다. 대신 `scripts/remask_floor/compare.py`를 새로 만들었다.

```bash
PG=../promptguard-claude-demoV0
# (a) 기존 9개 데이터셋 (eval/stage0-fp-analysis 브랜치)
for cfg in default floor; do
  for d in sessions sessions_2 sessions_from_example sessions_from_CredData sessions_from_noseyparker \
           sessions_from_Nemotron-PII sessions_from_trajectory sessions_from_openhands-feedback sessions_from_SWE-Gym; do
    python $PG/scripts/remask_floor/run_eval.py --data-root . --config $cfg -- \
      run --system promptguard --system-root $PG \
      --sessions metric-detection/data_test/$d.jsonl --out metric-detection/results/floor_$cfg
  done
done
python $PG/scripts/remask_floor/compare.py --data-root . \
  --run default=metric-detection/results/floor_default --run floor=metric-detection/results/floor_floor --out floor_compare_a.md

# (b) creddata-v1 test 분할 (creddata-trajectory-data 브랜치)
S=metric-detection/data_test/sessions_from_CredData-trajectory.jsonl
for cfg in default floor; do
  python $PG/scripts/remask_floor/run_eval.py --data-root . --config $cfg -- \
    run --system promptguard --system-root $PG --sessions $S --out runs/floor/$cfg
done
python $PG/scripts/remask_floor/compare.py --data-root . \
  --run default=runs/floor/default --run floor=runs/floor/floor --out floor_compare_b.md
```

`compare.py`는 데이터셋과 설정마다 다음을 **span 수와 고유 값 수**로 함께 낸다.
- recall(정확히/덮었는가)과 precision(채점기 값)
- 재마스킹 오탐: 병합된 finding span이 아니고 정답과 겹치지 않는 edit
- "16진수 키인데 일부만 가려짐": 값이 16자 이상 16진수인 정답 중 status가 partial인 것
- 새로 놓친 비밀: 정답 유형과 값 길이(<4, 4-7, 8+)별

값은 메모리에서 해시로만 세고, 출력하지 않는다.

**채택 기준:** 고유 값 기준 recall 손실 0, 그리고 재마스킹 오탐 감소. `compare.py` 마지막 표가 판정한다.
