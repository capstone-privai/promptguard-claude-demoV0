# Shell-aware v0.2와 union 마스킹

작성일: 2026-10-29
판정: **MODIFY** — union 마스킹과 shell-aware v0.2는 데모 기본값으로 쓴다. CredSweeper·Gitleaks를 포함한 재측정과 held-out 검증 전까지 성능 주장은 synthetic 범위로 제한한다.

표기: **[측정]** 이 문서 작성 환경에서 실행한 결과. **[PC]** 세훈 PC에서 다시 만들어야 하는 결과. **[제안]** 다음 단계.

## Summary

- Native Mod와 Final Guard가 쓰는 `findings`를 `candidate_policy`로 고를 수 있게 했다. 기본값 `union`은 활성 모듈 하나만 잡아도 마스킹하고, `majority`는 이전 다수결과 같다.
- shell-aware를 v0.2.0으로 고쳤다. v0.1.0을 독립 리뷰한 경계 케이스 18개에서 부분 노출 2건, FP 9건, 미탐 4건이 나왔고, 모두 고쳤다.
- 팀 ML adapter(`ml-detector`)와 그 설정·평가·문서를 이 저장소에서 뺐다. ML은 민준이 따로 붙인다. `RawFinding.score` 필드는 다른 adapter도 쓸 수 있는 일반 필드라 남겼다.

## Problem

v0.1.0(커밋 `e7b15df`)은 ML과 shell-aware를 `candidates`에만 넣었다. Native Mod와 Final Guard는 여전히 다수결 `findings`만 봐서, shell-aware만 잡은 값은 **가려지지 않고 전송됐다**. 팀 결정(10/29: 합집합으로 recall을 높게 잡고 마스킹)과 맞지 않았다.

v0.1.0 보고서는 "Shell-aware 추가 FP 0"이었지만, 평가셋 29개를 구현한 쪽이 같이 만들었고 hard negative가 `-p`와 ID류에 몰려 있었다.

## Evidence (v0.1.0 리뷰)

| 입력 유형 | v0.1.0 결과 |
|---|---|
| `--password="a b"`, `-p"a b"` | 따옴표 안의 첫 단어만 가림 (**부분 노출**) |
| `mysql -u root -p mydb` | DB 이름을 비밀번호로 잡음 |
| `--password --user root` | `--user`를 잡음 |
| `--token "$GITHUB_TOKEN"` | 변수 이름을 잡음 |
| `tokenize("...")`, `count_tokens("...")`, `set_author("...")` | 부분 문자열 cue로 잡음 |
| `authenticate(request, username="bob")` | username을 잡음 |
| `echo x \| sudo -s` | `-s`(셸)와 `-S`(stdin 비밀번호)를 구분 못 함 |
| `sudo -S bash <<EOF` 본문 | 비밀번호 줄 다음 명령까지 잡음 |
| login 근처 `send "yes\r"` | 잡음 |
| `sudo -kS`, `cat <<EOF \| sudo -S`, `\` 줄 이어쓰기, PowerShell | 놓침 |

## Architecture

```text
text ─┬─ credsweeper ─┐
      ├─ gitleaks ────┤
      ├─ promptguard-rules ─┤── candidate_policy ──┬─ union:    1표 → findings
      └─ shell-aware ─┘    (candidate_only)        └─ majority: 기존 3개 다수결 → findings
                                                    (candidates는 항상 전체 합집합 + provenance)
findings ──> Native Mod: [TYPE_n]으로 값만 마스킹, 로컬 tool 실행 직전 복원
         └─> Final Guard: 같은 정책으로 재검사, 남으면 BLOCK (fail-closed 유지)
```

- 정책은 `src/detector/detector.json`의 `candidate_policy`로 정하고, `PG_DETECTOR_CANDIDATE_POLICY`로 덮어쓸 수 있다. 키가 없는 설정 파일은 `majority`로 동작한다(이전 설정 호환).
- 겹치는 span은 `normalize()`가 하나로 합쳐 전체를 덮는다. `value_hash`도 유지돼서 같은 값은 같은 placeholder를 받는다.
- adapter 하나라도 실패하면 `ok=false`, `ADAPTER_FAILURE:<이름>`으로 기존과 같이 fail-closed된다.
- Node 코드(Native Mod, Final Guard)는 바꾸지 않았다. 둘 다 원래 `findings`를 쓰기 때문이다.

## Experiment

1. shell-aware 단위 테스트 9개, 회귀 테스트 8개(양성 32건, 음성 27건), `candidate_policy` 테스트 8개
2. 평가셋 확장: 기존 29개에 독립 리뷰 케이스 26개(`rv-` 접두사)를 더해 55개(gold 27, gold 없는 case 28)
3. 멱등성: union으로 마스킹한 fixture와 평가셋을 다시 스캔해 placeholder가 재탐지되는지 확인
4. 기존 fixture(32 span)에 shell-aware 단독 FP가 생기는지 확인
5. 지연: 평가셋 55개 × 20회, 16K자 입력

이 환경에서는 PyPI에 접속할 수 없어 CredSweeper를 설치하지 못했다. Gitleaks도 실행하지 않았다. 그래서 1~5는 사내 adapter(promptguard-rules, shell-aware)와 stub으로만 돌렸다.

## Results

| 항목 | 결과 |
|---|---|
| [측정] Python 테스트 | candidate_policy 8/8, shell_aware 9/9, regression 8/8, consensus 19/19, normalize 7/7 |
| [측정] Node 테스트 | 16/18. 실패 2개는 환경 문제(`jsdom` 미설치, 실제 CredSweeper 필요)이고 변경 전 코드도 같음 |
| [측정] 확장 평가셋 shell-aware 단독 | gold 27 중 25 커버, FP 0. 놓친 2개는 범위 밖인 `password = "..."` 대입 |
| [측정] promptguard-rules + shell-aware | 27/27 커버, FP 0 |
| [측정] promptguard-rules 단독 | 5/27 |
| [측정] 기존 fixture에서 shell-aware FP | 0 |
| [측정] 마스킹 후 재스캔 | 재탐지 0 (fixture 9개 + 평가셋 55개) |
| [측정] shell-aware 지연 | p50 0.062ms, p95 0.149ms. 16K자 입력 12.9ms. 비정상 16K 입력 최대 약 60ms |
| [PC] CredSweeper·Gitleaks 포함 union | 아래 "PC에서 재측정"으로 생성 |

## Limitations

- **확장 평가셋도 순환 위험이 있다.** `rv-` 케이스는 v0.2를 고친 쪽(리뷰어)이 만들었다. v0.1보다 넓어졌을 뿐 독립 hold-out이 아니다. FP 0, 커버 100%는 이 suite에서만의 숫자다.
- 실제 Claude Code·Anthropic provider E2E는 돌리지 않았다.
- union은 precision을 낮춘다. 오탐도 그대로 마스킹되므로 task utility 측정이 필요하다(기말 검증기 범위).
- Final Guard가 Mod와 같은 union으로 재검사하므로, 의미적으로 독립된 검증은 아니다.
- 토크나이저는 완전한 shell 파서가 아니다. 중첩 치환, alias, zsh/fish 고유 문법, PowerShell 일반 문법은 제한적이다.
- 변수 참조(`$VAR`, `$(...)`)는 값이 텍스트에 없어서 후보에서 뺐다. 그 값이 tool output에 찍히면 다른 adapter가 잡아야 한다.

## Decision

- **GO (데모 기본값):** `candidate_policy: "union"`, shell-aware v0.2.0
- **MODIFY:** 성능 주장은 synthetic suite 범위로만, CredSweeper·Gitleaks 포함 수치로 다시 쓴다
- **HOLD:** precision 검증기(기말), ML adapter 통합(민준)
- **NO-GO:** Final Guard 완화, union 오탐을 근거로 한 자동 ALLOW

## Next Step

### PC에서 재측정 [PC]

저장소 폴더에서 실행한다.

```powershell
.venv\Scripts\python.exe -m unittest tests\detector\test_candidate_policy.py tests\detector\test_shell_aware.py tests\detector\test_shell_aware_regression.py
.venv\Scripts\python.exe tests\detector\test_consensus.py
.venv\Scripts\python.exe tests\detector\test_normalize.py
.venv\Scripts\python.exe tests\detector\run_detector_tests.py
.venv\Scripts\python.exe tests\detector\evaluate_shell_aware.py
npm test
```

- `run_detector_tests.py`는 union 정책으로 fixture를 다시 잰다. 이전 `any` 정책 결과가 32/0/0이었고 shell-aware의 fixture FP가 0이었으므로 32/0/0이 기대값이다.
- `evaluate_shell_aware.py`는 `outputs/`에 3-way union, +shell-aware, shell-aware 단독 결과와 지연을 쓴다.
- 결과가 기대와 다르면 이 문서의 Results 표를 그 수치로 바꾼다.

### 그다음 [제안]

1. 실제 agent trace에서 credential을 뺀 held-out shell 데이터와 hard negative를 따로 만든다(작성자와 평가자 분리).
2. union 오탐이 작업 성공률에 주는 영향을 원본 vs 마스킹으로 비교한다.
3. 민준 ML adapter가 들어오면 같은 `candidate_policy` 경로에 adapter 하나로 추가한다.
