# Team Brief — Recall-First Union + Shell-aware

작성일: 2026-10-29

한 줄 결론: **Shell-aware candidate adapter는 유지할 가치가 있다. 기존 4-way union이 놓친 synthetic secret 9개를 추가했고 새 FP는 0이었지만, held-out 검증 전 production 자동 보호 승격은 보류한다.**

## 무엇이 바뀌었나

기존 protection과 recall-first candidate를 분리했다.

```text
기존 findings: majority(CredSweeper, Gitleaks, promptguard-rules)
새 candidates:  CredSweeper ∪ Gitleaks ∪ rules ∪ 팀 ML ∪ Shell-aware
```

Native Mod와 Final Guard는 계속 기존 `findings`를 사용한다. 즉 P0와 fail-closed 정책은 바뀌지 않았다. `candidates`에는 한 detector만 잡아도 들어가고, 겹치는 span은 하나로 합치되 detector/family/strength provenance를 남긴다.

Shell-aware는 다음 위치를 본다.

- credential long option
- command-aware `-p`
- credential stdin sink
- here-string/heredoc
- credential 문맥의 send/sendline
- credential 의미 함수의 string argument

일반 random string이나 모든 `-p`를 잡는 regex가 아니다.

## 핵심 수치

동일한 synthetic 29 requests / 16 secrets 기준이다.

| Metric | 기존 4 union | + Shell-aware |
| --- | ---: | ---: |
| Exposure Recall | 43.75% | **100%** |
| Exact Recall | 43.75% | **100%** |
| Precision | 70.00% | **84.21%** |
| FN | 9 | **0** |
| FP | 3 | **3** |
| F2 | 0.4730 | **0.9639** |

Shell-aware 신규 TP는 9개다: long option 1, short option 2, stdin 2, here-string 1, heredoc 1, expect 1, function argument 1.

- Shell-aware 추가 FP: **0**
- 기존 candidate regression: **0**
- `-p` hard-negative FP: **0/5**
- ML/Shell overlap: **5/14 = 35.71%**
- Shell 독립 기여: **9/16 = 56.25%** of all gold
- Shell adapter latency: p50 **0.0776 ms**, p95 **0.1231 ms**

## 과거 Recall V2와 관계

과거 pilot은 다른 synthetic gap suite에서 `P1 25% → P1+shell 75%`(+50%p)를 보였다. 이번에는 실제 Gitleaks와 팀 ML을 포함한 정식 adapter union에서 `43.75% → 100%`(+56.25%p)를 보였다. 데이터가 달라 절대값을 합치면 안 되지만, shell candidate gap의 독립 기여는 다시 확인됐다.

## 주의할 점

- 이번 데이터는 held-out production trace가 아니다.
- 팀 ML checkpoint는 현재 key/value fixture에서 단독 TP 1 / FP 24 / FN 31이고 bundle도 `production_ready: false`다.
- ML tokenizer 로딩 경고가 남아 있다.
- Shell-aware tokenizer는 완전한 shell AST가 아니므로 복잡한 substitution/alias/multiline syntax는 후속 corpus에서 검증해야 한다.
- Strong/Ambiguous는 지금 candidate metadata다. Strong을 production protect로 자동 승격하지 않았다.

## 팀 결정 제안

판정은 **MODIFY**다.

1. Shell-aware를 candidate-only 정식 adapter로 유지한다.
2. 실제 credential을 제거한 held-out agent trace와 hard-negative corpus를 만든다.
3. 그 데이터에서 recall/FP/request/task utility gate를 통과한 strong family만 보호로 승격한다.
4. Precision recovery는 먼저 deterministic evidence policy를 비교한다. 새 모델은 그보다 유의미한 개선이 입증될 때만 시작한다.
5. ML tokenizer warning과 checkpoint OOD 성능은 `promptguard-model` 쪽 별도 수정으로 다룬다.

상세 근거와 15개 최종 답은 `docs/SHELL_AWARE_ADAPTER_REPORT.md`, 기계 판독 수치는 `outputs/shell-aware-*.json` 및 `outputs/detector-union-comparison.json`에 있다.
