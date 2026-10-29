# PromptGuard Recall-First Detector Union + Shell-aware Adapter

작성일: 2026-10-29

구현 base revision: `928c84ce71646d629c3ab6e5c261317af1347dcb`

평가 성격: synthetic-only, raw-free, 동일 29-case/16-secret 비교

최종 판정: **MODIFY — 정식 candidate adapter와 shadow union은 유지하고, production 자동 보호 승격은 held-out 검증 뒤 결정한다.**

이 문서에서 `finding`은 현재 majority 정책을 통과해 기존 Native Mod/Final Guard가 사용하는 보호 결과이고, `candidate`는 adapter 하나만 탐지해도 포함되는 recall-first union 결과다. 둘을 섞지 않는다.

## 1. 기존 detector 구조

기준 repository의 detector는 `DetectorAdapter.scan(text) -> list[RawFinding]` contract, adapter별 ballot 수집, overlap vote, canonical normalization의 순서로 동작한다. 기존 production protection 경로는 다음 세 adapter와 majority 정책이다.

- CredSweeper 1.19.0
- Gitleaks 8.30.1(설치된 경우)
- `promptguard-rules` 0.1.0
- majority: 이 평가 환경에서는 3개 중 2표

Native Mod와 Final Guard는 worker가 반환한 `findings`를 사용한다. 이번 구현은 이 기존 보호 경로를 유지하고, 같은 scan 응답에 별도의 `candidates`를 추가했다.

팀 ML repository `capstone-privai/promptguard-model`도 실제 코드를 확인해 연동했다. 확인한 contract는 다음과 같다.

- class: `MLSpanDetector(checkpoint, device="cpu")`
- inference: `scan_text(text, threshold=None)`
- output: Python code-point 기준 `start`, `end`, `secret_type`, `detector`, `score`
- checkpoint: `models/span-detector-v9`, Git LFS의 `model.safetensors` 필요
- bundle: `ml-span-bundle-v1`, revision `abc32620dd4f...`
- load-once: adapter 생성 시 모델을 한 번 로드하고 scan마다 재사용
- scan 예외: adapter failure로 전파되어 기존 worker의 fail-closed 경로에 포함

현재 실제 평가 topology는 다음과 같다.

| 계층 | adapter |
| --- | --- |
| 기존 protection voters | CredSweeper, Gitleaks, promptguard-rules |
| recall-first candidate union | 위 3개 + ML detector + Shell-aware |
| candidate-only | ML detector, Shell-aware |

ML repository/weight/dependency가 없으면 optional adapter로 startup에서 명시적으로 skip된다. Shell-aware는 dependency가 없는 required adapter다. 실제 5-way 비교에서는 skip된 adapter와 runtime adapter error가 모두 0이었다.

## 2. candidate-generation 문제

Majority는 precision을 위한 protection 정책이지만 candidate generation에 그대로 쓰면 한 adapter만 아는 shell 문맥이 사라진다. 기존 네 detector의 합집합도 key/value 형식에는 강하지만 다음 위치를 자주 놓쳤다.

- command-specific `-p`
- password stdin source/sink
- here-string과 heredoc
- expect/sendline 문맥
- credential 의미를 가진 함수 인자

따라서 보호 결과 `P0`를 바꾸는 대신, 모든 활성 adapter ballot을 `required_votes=1`로 canonicalize하는 candidate union을 추가했다.

```text
legacy protection = majority(CredSweeper, Gitleaks, promptguard-rules)
candidate union   = CredSweeper ∪ Gitleaks ∪ promptguard-rules ∪ ML ∪ Shell-aware
```

`Old Candidate Set ⊆ New Candidate Set`은 evaluator와 unit test에서 확인하며, 이번 결과의 regression count는 0이다.

## 3. Shell-aware 설계

Shell-aware는 secret value의 모양을 보고 최종 분류하는 regex collection이 아니다. 최소 tokenizer로 다음 구조를 먼저 분리한다.

- command와 subcommand
- option과 붙은/분리된 option value
- pipe source와 credential-consuming sink
- `<<<`, `<<`, `<<-` redirection
- quoted/unquoted token의 실제 value boundary
- send/sendline 앞 문맥
- credential 의미를 가진 function/call name

그 뒤 command/option registry와 source/sink semantics를 적용한다. 예를 들어 `-p`는 `sshpass`, `mysql`, `mysqldump`, `docker login`에서만 password option으로 취급한다. `mkdir -p`, `ssh -p 2222`, `docker run -p`, `pytest -p`, `cp -p`는 후보가 아니다.

각 candidate evidence에는 raw value 대신 다음 정보만 남긴다.

- adapter
- family
- strength (`strong` 또는 `ambiguous`)
- command, option, source, sink, function 같은 구조 정보
- ML의 경우 score와 고정된 model identifier

동일하거나 겹치는 span은 하나의 candidate로 union하고 `detectors` 및 evidence 배열로 provenance를 보존한다. shortest-span-wins를 사용하지 않으며 overlap-connected span 전체를 덮어 secret 일부가 노출되지 않게 한다.

현재 `strong`/`ambiguous`는 candidate metadata다. 이번 작업은 Native Mod 및 Guard action semantics를 바꾸지 않는 범위이므로 Shell-aware strong을 독립적으로 production `finding`으로 승격하지 않았다. 기존 P0 protection은 그대로이고, 실제 승격은 held-out gate 뒤 별도 결정한다.

## 4. 지원 family

| family | 근거 | strength 기본값 |
| --- | --- | --- |
| `long_option` | `--password`, `--token`, `--secret`, `--api-key`, `--client-secret`, `--access-token`; `=` 포함 | strong |
| `short_option` | command registry와 `-p` 조합 | strong |
| `stdin_sink` | `echo`/`printf` source + `sudo -S`, `docker login --password-stdin`, `passwd --stdin` sink | literal strong, semantic variable ambiguous |
| `here_string` | credential sink 또는 credential-named variable와 `<<<` | strong/ambiguous |
| `heredoc` | credential-consuming sink에 연결된 heredoc body | strong |
| `expect_send` | 앞 256자에 password/login/auth/credential cue가 있는 send/sendline | ambiguous |
| `function_argument` | password/passwd/credential/secret/token/login/authenticate 의미의 함수명과 마지막 literal | strong/ambiguous |

일반 UUID, request/trace/session ID, commit hash, Docker digest, random-looking identifier만으로는 candidate를 만들지 않는다.

## 5. 구현 구조

주요 변경은 다음과 같다.

- `src/detector/pgdetector/adapters/shell_aware.py`: tokenizer와 semantic candidate generator
- `src/detector/pgdetector/adapters/ml_span.py`: 팀 ML detector의 실제 local inference adapter
- `src/detector/detector.json`: ML/Shell-aware를 candidate-only adapter로 등록
- `src/detector/pgdetector/ensemble.py`: 기존 protection vote와 5-way candidate union 분리
- `src/detector/pgdetector/core.py`: overlap canonicalization 시 raw-free evidence/provenance 병합
- `tests/detector/test_shell_aware.py`: family, hard negative, subset, provenance, raw logging, response schema 검사
- `tests/detector/evaluate_shell_aware.py`: A/B/C ablation과 latency 측정

`scan()` 응답은 기존 `findings`를 그대로 유지하면서 `candidates`, `candidate_count`, `candidate_policy="union"`을 추가한다. Candidate에서는 process-local `value_hash`도 제거한다. 기존 adapter failure는 candidate error에도 합쳐져 `ok=false`가 되므로 runtime fail-closed 동작을 약화하지 않는다.

## 6. hard negative 설계

29개 case 중 13개는 gold가 없는 hard negative다.

- `mkdir -p build`
- `ssh -p 2222 localhost`
- `docker run -p 8080:80 nginx`
- `pytest -p plugin_name`
- `cp -p source target`
- UUID
- request ID
- trace ID
- commit SHA
- Docker digest
- session ID
- random-looking artifact reference
- credential cue가 없는 `sendline("hello world")`

특히 `-p` 5개 hard negative의 Shell-aware FP는 0이었다. 모든 synthetic secret은 비기능 fixture이며 output에는 case ID와 aggregate만 저장한다.

## 7. 기존 4-detector union과 비교

동일한 29 requests, 16 gold secrets를 사용했다.

| Metric | A. 기존 4 union | B. A + Shell-aware | C. Shell-aware only |
| --- | ---: | ---: | ---: |
| Candidate Recall | 0.4375 | **1.0000** | 0.8750 |
| Secret-Value Exposure Recall | 0.4375 | **1.0000** | 0.8750 |
| Exact Span Recall | 0.4375 | **1.0000** | 0.8750 |
| Precision | 0.7000 | **0.842105** | 1.0000 |
| F2 | 0.472973 | **0.963855** | 0.897436 |
| FN | 9 | **0** | 2 |
| FP | 3 | **3** | 0 |
| FP/request | 0.103448 | **0.103448** | 0 |
| Candidates/request | 0.344828 | 0.655172 | 0.482759 |

기존 union의 FP 3개는 positive case 안에서 ML/기존 detector가 gold 외 span을 추가로 낸 결과다. Shell-aware를 추가한 뒤 같은 세 case만 남았으며 Shell-aware 자체가 새 FP를 추가하지 않았다.

## 8. Recall 증가량과 family contribution

Shell-aware가 기존 4-way union에 추가한 독립 TP는 9개다.

| family | 신규 TP |
| --- | ---: |
| `long_option` | 1 |
| `short_option` | 2 |
| `stdin_sink` | 2 |
| `here_string` | 1 |
| `heredoc` | 1 |
| `expect_send` | 1 |
| `function_argument` | 1 |
| 합계 | **9** |

Shell-aware only는 14/16을 찾았고, 의도적으로 범위 밖에 둔 일반 known assignment 2개는 다른 detector가 찾았다. Shell-aware TP 14개 중 ML과 겹친 것은 5개(35.7143%)다. 기존 4개가 놓치고 Shell-aware만 추가한 9개는 전체 gold의 56.25%이며, Shell-aware가 찾은 14개 중에서는 64.2857%다.

## 9. Precision과 FP 변화

New union precision은 0.7000에서 0.842105로 올라갔다. 이유는 FP 수가 3으로 유지된 채 TP가 7에서 16으로 늘었기 때문이다. 이것은 larger/held-out corpus에서 Shell-aware precision 1.0을 보장한다는 뜻이 아니다.

Family별 Shell-aware 결과는 `known_assignment` 0/2를 제외하면 모두 recall 1.0이고, 각 family FP는 0이었다. 따라서 이번 데이터만 놓고 특정 shell family를 좁힐 근거는 없다. 다만 function/expect는 의미가 넓어질수록 FP가 생길 가능성이 높으므로 ambiguous를 유지한다.

별도의 precision classifier는 만들지 않았다. 현재 candidate union의 전체 FP 3개는 Shell-aware가 아니라 기존/ML 후보에서 왔으므로, 먼저 held-out corpus와 deterministic evidence policy로 잔여 FP를 분석해야 한다.

## 10. Latency

측정은 모델 load, HTTP/MCP, Claude UX를 제외한 warm in-process per-input이다. 각 union 내부 adapter는 concurrent scan했다.

| 경로 | p50 | p95 |
| --- | ---: | ---: |
| 기존 4 union | 338.2736 ms | 446.4941 ms |
| 새 5 union | 345.9887 ms | 455.5113 ms |
| Shell-aware only | **0.0776 ms** | **0.1231 ms** |
| 단순 union 차이 | +7.7151 ms | +9.0172 ms |

Shell-aware 자체 p95가 0.1231 ms이고 adapter는 병렬 실행되므로 +7.7/+9.0 ms를 Shell-aware의 인과적 비용으로 해석하면 안 된다. 29회 소표본에서 ML inference, Gitleaks process startup, OS scheduling noise가 지배한다.

## 11. 실패 사례와 regression

- Shell-aware FN: `known_assignment` 2개. 이 family는 범용 shell adapter의 책임이 아니며 기존 detector가 모두 보완했다.
- Shell-aware FP: 0.
- 기존 candidate coverage regression: 0.
- partial leak: 0.
- boundary-only error: 0.
- adapter runtime error: 0.
- required old detector missing: 0.

회귀 결과:

- Shell-aware unittest: 9/9 PASS
- consensus checks: 19/19 PASS
- normalize checks: 7/7 PASS
- 기존 detector fixture protection: TP 32 / FP 0 / FN 0
- Node Runtime/Final Guard/Native Mod/observability: 31/31 PASS

기존 detector fixture에서 ML 단독은 TP 1 / FP 24 / FN 31이었다. 이는 key/value fixture에 대해 현재 팀 ML checkpoint가 OOD/부적합할 가능성을 보여 주며, ML을 candidate-only로 둔 근거다. Candidate union은 TP 32 / FP 3 / FN 0이었다.

## 12. 알려진 한계

1. 이번 평가는 held-out production trace가 아니라 29-case synthetic suite다. `GO`의 held-out 조건을 만족하지 않는다.
2. tokenizer는 완전한 Bash/PowerShell AST가 아니다. nested substitutions, escaped multiline, aliases/wrappers, complex pipelines, fish/zsh/PowerShell 고유 문법은 제한적이다.
3. `expect_send`는 앞 256자 credential cue, function argument는 마지막 string literal이라는 보수적 휴리스틱이다.
4. ML bundle metadata가 `production_ready: false`이고, 현재 Transformers 로딩에서 Mistral tokenizer regex 경고가 발생한다. upstream model repository와 함께 수정/재검증해야 하며 이번 작업에서 임의로 tokenizer 규칙을 바꾸지 않았다.
5. ML dependency와 약 563 MB weight는 기본 설치에 포함하지 않았다. sibling repository와 Git LFS weight가 없으면 optional skip된다.
6. Gitleaks availability에 따라 실제 candidate topology가 달라질 수 있다. 평가 output은 active/skipped adapter를 항상 기록한다.
7. Strong evidence를 즉시 production 보호로 승격하지 않았다. 이는 기존 Native Mod/Guard semantics를 유지하기 위한 의도적 범위 제한이다.

## 13. Recall V2 비교와 다음 단계

과거 Recall V2 synthetic gap pilot은 `P1 25% → P1+shell 75%`, 즉 +50%p를 보고했다. 이번 정식 adapter 평가는 실제 Gitleaks와 팀 ML을 포함한 다른 29-case suite에서 `4-way union 43.75% → 5-way union 100%`, 즉 +56.25%p를 재현했다. 데이터와 topology가 다르므로 두 숫자를 직접 합치거나 production 성능으로 일반화하지 않는다. 공통 결론은 shell 위치에서 candidate-generation gap이 있고 Shell-aware가 독립 TP를 추가한다는 것이다.

다음 단계:

1. 실제 credential을 제거/대체한 held-out coding-agent shell trace와 더 넓은 hard-negative corpus를 고정한다.
2. shell family별 exposure recall, FP/request, candidates/request, task utility를 다시 측정한다.
3. tokenizer warning을 팀 ML repository에서 해결하고 checkpoint를 재평가한다.
4. complex shell syntax miss가 확인될 때만 tree-sitter/bashlex 같은 parser 도입을 size/Windows/macOS/latency 기준으로 검토한다.
5. P0는 항상 유지하고, strong promotion 및 ambiguous precision recovery gate를 별도 설계한다.
6. Held-out에서도 Shell-aware FP가 낮으면 strong family만 protection에 승격한다. FP가 생기면 새 LM보다 먼저 registry/context/deterministic policy를 보정한다.

## 최종 판정: MODIFY

Shell-aware는 정식 candidate adapter로 유지할 가치가 있다. 9개의 독립 TP, 0개의 추가 FP, 0개의 legacy regression, sub-millisecond 자체 latency를 보였다. 다만 production 자동 보호까지 `GO`라고 부르기에는 synthetic-only 평가, 최소 tokenizer의 문법 한계, ML bundle의 비-production 상태가 남아 있다. 따라서 candidate union/shadow는 유지하고 enforcement 승격 전 held-out 검증을 요구한다.

## 최종 질문 15개

1. **기존 4-detector Union Recall:** `7/16 = 0.4375 (43.75%)`.
2. **Shell-aware 추가 후 Recall:** `16/16 = 1.0000 (100%)`.
3. **Shell-aware가 새로 찾은 TP:** `9개`.
4. **신규 TP family:** `long_option 1`, `short_option 2`, `stdin_sink 2`, `here_string 1`, `heredoc 1`, `expect_send 1`, `function_argument 1`.
5. **Shell-aware 때문에 생긴 FP:** `0개`. 전체 union FP는 `3 → 3`으로 동일하다.
6. **가장 FP가 많은 shell family:** 없음. 모든 shell family가 `0 FP`로 공동 최저다.
7. **기존 candidate가 사라진 사례:** `0개`.
8. **Shell-aware가 없으면 secret-value leak인 케이스:** `9개`.
9. **Shell-aware adapter latency:** p50 `0.0776 ms`, p95 `0.1231 ms`.
10. **전체 union latency 증가:** p50 `+7.7151 ms`, p95 `+9.0172 ms`; Shell-aware 자체 비용보다 ML/process/scheduling noise가 큰 측정이다.
11. **ML과 Shell-aware overlap:** `5/14 = 35.7143%` of Shell-aware TP.
12. **Shell-aware 독립 발견 비율:** 전체 gold 기준 `9/16 = 56.25%`; Shell-aware TP 기준 `9/14 = 64.2857%`.
13. **`-p` hard negative FP:** `0/5`.
14. **정식 adapter 유지 가치:** 예. 신규 TP `9`, 추가 FP `0`, regression `0`, 자체 p95 `0.1231 ms`다.
15. **다음 단계 precision recovery:** candidate-generation/shadow 평가에는 현재 union으로 충분하다. Production enforcement 전에는 전체 union의 `3 FP`를 다룰 precision recovery가 필요하지만, 지금 새 모델을 만들 근거는 없다. held-out 데이터와 deterministic evidence policy를 먼저 적용하고 그 뒤 모델 필요성을 재판정한다.

기계 판독 원본은 `outputs/detector-union-comparison.json`, `outputs/shell-aware-metrics.json`, `outputs/shell-aware-family-breakdown.json`, `outputs/shell-aware-latency.json`에 있다.
