# 재마스킹 목록 입장 기준 (`PG_REMASK_POLICY`)

## 왜

정우의 0단계 오탐 분석(promptguard-data `eval/stage0-fp-analysis`, `metric-detection/results/stage0_fp_20261115/`)에서, 형식 탐지 그룹(ML 끔)의 가린 곳 138,038곳 중 96,485곳이 어느 탐지기 결과와도 겹치지 않는 재마스킹이었다. 그중 95,894곳이 오탐이었다. 탐지기 결과만으로는 precision이 0.62인데, 시스템 전체는 0.19였다.

가설은 다음과 같다. 탐지기가 오탐으로 찾은 값(긴 파일 속 식별자 등)이 재마스킹 목록에 들어가, 세션 안에서 다시 나올 때마다 전부 가려진다. 한 건씩 확인한 것은 아니다. 확인에는 `scripts/remask_admission/breakdown.py`를 쓴다.

## 무엇이 바뀌나

Mod에는 대응표가 두 개 있다.

| 대응표 | 쓰는 곳 | 바뀌나 |
|---|---|---|
| 복원용 (`[TYPE_N]` → 원래 값) | 명령 실행 직전 복원 | 바뀌지 않는다. 가린 값은 전부 저장한다 |
| 재마스킹용 (원래 값 → `[TYPE_N]`) | `remaskText`, 부분 재마스킹(#12) | `admitted`에서는 들어갈 값을 고른다 |

탐지기가 찾은 위치는 두 모드 모두 지금처럼 가린다. 바뀌는 것은 "다른 곳에 다시 나왔을 때, 탐지기 없이 가리는 것"뿐이다.

| `PG_REMASK_POLICY` | 동작 |
|---|---|
| `all` (기본, 그 밖의 값도 같다) | 지금과 같다. 가린 값은 모두 재마스킹 목록에 들어간다 |
| `admitted` | 아래 조건 중 하나를 만족하는 값만 들어간다 |

`admitted`의 입장 조건은 다음과 같다.

1. **고신뢰 규칙이 찾은 값.** `src/native-mod/remask-admission.json`에 있는 (탐지기, 규칙) 쌍이다. finding의 `detectors`에 그 탐지기가 있고, `rule_id`를 `+`로 나눈 조각 중 하나가 그 규칙이면 해당한다.
2. **값 자체가 비밀처럼 보이는 경우.** 모양(`valueShape`)이 `secret_like`이면 해당한다. 아래 모양은 들어가지 않는다.
   - `short`: 8자 미만
   - `template`: `<...>`, `{{ }}`, `[TYPE_N]`, `***`, `xxx`
   - `example`: changeme, `your_..._here`, dummy, example, 같은 글자 반복
   - `reference`: `${X}`, `$X`, `%X%`, `os.environ[...]`, `process.env.X`, `self.x` 같은 점으로 이은 식별자
   - `uuid`, `numeric`(숫자와 구분 기호만), `hex`(16진수 해시, `sha256:` 접두 포함)
   - `words`: #16의 흔한 단어로만 된 값. camelCase, snake_case로 이은 단어(`buildCacheDirectory`)도 포함한다. 숫자나 기호가 섞이면 해당하지 않는다.
3. **실행 직전에 원래 값으로 복원된 적이 있는 값.** 정책과 상관없이 넣는다. 명령 출력에 다시 나올 수 있기 때문이다.

부분 재마스킹은 재마스킹 목록에 든 값에만 일어난다. `admitted`인데 규칙 목록을 읽지 못하면 `all`로 동작한다(더 많이 가리는 쪽). `all`이면 목록 파일을 읽지 않는다.

같은 판정을 `scripts/remask_admission/shapes.py`가 Python으로 한다. 두 쪽이 같은 답을 내는지는 `tests/fixtures/remask_shapes.json`으로 확인한다(`tests/mod/test_remask_admission.mjs`, `tests/detector/test_remask_shapes.py`).

## 고신뢰 규칙을 고른 근거

`rules.csv`의 형식 탐지 그룹, ML 끔, `(group)` 행에서 다음을 모두 만족하는 규칙을 골랐다.

- precision 0.90 이상
- 탐지 10건 이상
- 혼자 낸 오탐이 탐지의 2% 이하

| 탐지기 | 규칙 | 탐지 | precision | 혼자 낸 오탐 |
|---|---|---|---|---|
| credsweeper | PEM Private Key | 12,635 | 1.0000 | 0 |
| credsweeper | Bearer Authorization | 306 | 0.9902 | 0 |
| credsweeper | JSON Web Token | 174 | 0.9713 | 0 |
| credsweeper | NTLM Token | 112 | 1.0000 | 0 |
| credsweeper | PromptGuard Bearer Token | 100 | 0.9800 | 0 |
| credsweeper | AWS Multi | 68 | 0.9559 | 1 |
| credsweeper | PASETO Token | 63 | 1.0000 | 0 |
| credsweeper | BASE64 Private Key | 39 | 0.9487 | 0 |
| credsweeper | Slack Token | 34 | 0.9706 | 0 |
| credsweeper | Azure Access Token | 17 | 1.0000 | 0 |
| credsweeper | Google API Key | 15 | 1.0000 | 0 |
| credsweeper | CURL User Password | 12 | 1.0000 | 0 |
| gitleaks | private-key | 10,537 | 0.9991 | 8 |
| gitleaks | jwt | 179 | 0.9385 | 1 |
| gitleaks | curl-auth-header | 33 | 0.9394 | 0 |
| gitleaks | gcp-api-key | 11 | 1.0000 | 0 |
| gitleaks | slack-bot-token | 10 | 1.0000 | 0 |
| promptguard-rules | pem-private-key | 10,188 | 0.9999 | 1 |

넣지 않은 주요 규칙은 다음과 같다. 이 규칙들이 찾은 값도 모양이 `secret_like`이면 2번 조건으로 들어간다.

| 탐지기 | 규칙 | 탐지 | precision | 혼자 낸 오탐 | 빠진 이유 |
|---|---|---|---|---|---|
| promptguard-rules | secret-assignment | 13,875 | 0.3907 | 4,584 | precision |
| credsweeper | Password | 7,515 | 0.4194 | 2,753 | precision |
| gitleaks | generic-api-key | 6,708 | 0.7987 | 1,141 | precision |
| credsweeper | PromptGuard Token Assignment | 4,259 | 0.5377 | 100 | precision |
| credsweeper | Token | 3,431 | 0.3124 | 1,313 | precision |
| credsweeper | Secret | 2,205 | 0.7678 | 326 | precision |
| shell-aware | shell-function_argument | 1,342 | 0.3264 | 752 | precision |
| promptguard-rules | bearer-token | 222 | 0.9099 | 16 | 혼자 낸 오탐 7.2% |
| gitleaks | aws-access-token | 106 | 0.8774 | 0 | precision |
| promptguard-rules | slack-token | 29 | 0.9310 | 1 | 혼자 낸 오탐 3.4% |

탐지가 10건 미만인 규칙은 근거가 부족해 넣지 않았다. 제공사 형식의 키는 대부분 무작위 문자열이라 2번 조건으로 들어간다.

## 측정 방법 (정우)

promptguard-data 저장소 루트에서, 이 브랜치를 체크아웃한 PromptGuard(`$PG`)로 돌린다. ML은 끈다(`detector.json` 기본값). `policy_eval.py`는 채점기를 고치지 않고, 채점기의 Mod 복제(`ModSession`)를 실행 중에만 `admitted`로 바꿔 끼운다.

```bash
PG=../promptguard-claude-demoV0
for policy in all admitted; do
  for d in sessions_from_CredData sessions_from_noseyparker sessions_from_openhands-feedback sessions_from_SWE-Gym; do
    python $PG/scripts/remask_admission/policy_eval.py --data-root . --policy $policy -- \
      run --system promptguard --system-root $PG \
      --sessions metric-detection/data_test/$d.jsonl --out metric-detection/results/remask_$policy
  done
done

# 표: precision, recall, 덮었는가 기준 recall, 재마스킹 tp/over/fp, recall 변화, admitted에서 새로 놓친 비밀
python $PG/scripts/remask_admission/compare.py --data-root . \
  --all metric-detection/results/remask_all --admitted metric-detection/results/remask_admitted --out remask_compare.md

# 재마스킹 오탐 분류: 전체 값/부분 조각, 처음 찾은 규칙, 값 모양, 길이, 세션 안 반복 횟수, 100개 표본
python $PG/scripts/remask_admission/breakdown.py --data-root . metric-detection/results/remask_all --out remask_breakdown.md

# 규칙별 수치(rules.csv, union.csv)도 같은 방식으로 비교할 수 있다
cd metric-detection && python -m evaluation.report.fp_analysis \
  --config all results/remask_all --config admitted results/remask_admitted --out results/remask_fp
```

채택 기준은 데이터셋마다 recall 손실 1%p 이내다. 넘으면 `compare.py`의 "새로 놓친 비밀" 표(유형, 모양, 그 자리에서 찾은 규칙)를 보고 기준을 조정한다.

`breakdown.py`와 `compare.py`는 세션 파일에서 값을 읽어 모양만 계산하고, 값은 출력하지 않는다.

## 측정의 한계

- 채점기는 `tool_input`(모델이 쓴 명령)을 복원하지 않는다. `policy_eval.py`는 앞에서 가린 값이 뒤의 `tool_input`에 나오면 복원된 것으로 보고 목록에 넣는다. 녹화된 세션에서는 에이전트가 그 값을 직접 쳤기 때문이다.
- `breakdown.py`의 "admitted면 빠지는 수"는 복원 조건을 보지 못하므로, 실제로 빠지는 수보다 크게 나올 수 있다(상한).
