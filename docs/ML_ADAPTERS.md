# 팀 ML 탐지기 adapter (ml-span, ml-v9, ml-qwen)

민준 저장소 [`capstone-privai/promptguard-model`](https://github.com/capstone-privai/promptguard-model)의 두 모델을 PromptGuard 탐지기 모듈로 붙이는 adapter다. 두 모듈은 서로 독립이라 하나씩 또는 같이 켤 수 있다. 기본값은 둘 다 꺼짐이다.

| 모듈 | 감싸는 함수 | 모델 폴더 | 속도 (민준 측정, CPU 4스레드) |
|---|---|---|---|
| `ml-span` | `privai_model.ml_span.runtime.MLSpanDetector.scan_text` | 민준 저장소의 기본 모델, 지금은 `models/span-detector-v10` (약 560MB) | v9와 같은 구조 |
| `ml-v9` | `privai_model.ml_span.runtime.MLSpanDetector.scan_text` | `models/span-detector-v9`로 고정 (약 560MB) | 입력당 평균 33ms |
| `ml-qwen` | `privai_model.qwen_span.wrapper.QwenSecretScanner.scan` | `models/qwen-span-v3` (LoRA + 베이스 Qwen2.5-Coder-0.5B) | 입력당 평균 약 1.0초 (v3, 민준 측정) |

세 모듈 모두 `candidate_only: true`라 `majority` 정책에서는 투표하지 않는다. `union` 정책(기본)에서는 하나만 잡아도 마스킹된다.

## Qwen v3 (2026-10-30부터 기본)

민준이 2026-10-29 `promptguard-model` main(18cd162)에 올린 `qwen-span-v3`를 기본으로 쓴다. 함수 형태(`QwenSecretScanner.scan` → `ScanResult`)는 v2와 같아 adapter 코드는 그대로이고 모델 폴더만 바뀐다. 민준 보고: 학습에서 뺀 참조형 문법 hold-out의 hard negative 78행 중 오탐 0행(v2 38행), validation F2 .884(v2 .893), 합성 데이터만 학습, `production_ready: false`. 이 수치는 민준 측정이며 데모 저장소에서 다시 재지 않았다.

## 준비

1. 민준 저장소를 데모 저장소 **옆 폴더**에 둔다. 기본 경로는 `src/detector` 기준 `../../../promptguard-model`, 즉 데모 저장소와 같은 부모 폴더다. 다른 곳이면 `detector.json`의 `repository`를 바꾼다.
2. 그 폴더에서 `git pull`과 `git lfs pull`을 실행한다. 가중치가 LFS 포인터 상태(1KB 미만)면 `detector.json`에서 켠 모듈은 시작할 때 건너뛰고 이유를 출력한다. `--enable`이나 `PG_DETECTOR_ENABLE`로 이름을 지정해 켰는데 쓸 수 없으면 PromptGuard가 시작하지 않는다.
3. 데모 `.venv`에 `torch`, `transformers>=4.51,<5`, `numpy`, `peft>=0.13,<1`를 설치한다. 민준 패키지는 설치하지 않아도 된다. adapter가 `promptguard-model/src`를 import 경로에 넣는다.
4. Qwen은 처음 실행할 때 베이스 모델(약 1GB)을 Hugging Face에서 받는다. 2026-10-29 세훈 PC에서 첫 로딩은 468초였다(대부분 다운로드). PromptGuard를 켜기 전에 확인 스크립트로 한 번 받아 두고, 모델을 켤 때는 worker 준비 대기 시간을 늘린다(`PG_READINESS_TIMEOUT_MS`, 기본 30000).

## 켜고 끄기

`promptguard run` 옵션으로 고른다. 이름은 쉼표로 구분하고, `--disable`이 `--enable`보다 우선한다.

```powershell
cd sample-protected-project
..\promptguard.cmd run --enable ml-span                     # 기본 4종 + 민준 저장소의 기본 모델
..\promptguard.cmd run --enable ml-v9                       # 기본 4종 + v9 고정 (비교, 재평가용)
..\promptguard.cmd run --enable ml-qwen                     # 기본 4종 + Qwen
..\promptguard.cmd run --enable ml-span,ml-qwen             # 둘 다
..\promptguard.cmd run --enable ml-span --disable shell-aware # 섞어서
..\promptguard.cmd run --policy majority                    # 기존 다수결로 비교
```

- ML 모듈이 켜지면 worker 준비 대기 시간이 자동으로 180초가 된다. Qwen이 켜지면 detector 응답 대기 시간도 30초가 된다. `--readiness-timeout-ms`, `--detector-timeout-ms`로 직접 정할 수 있다.
- 시작할 때 `Detectors: ...` 줄에 실제로 켜지는 모듈이 나온다. 이름을 잘못 쓰거나 전부 끄면 시작하지 않는다.
- 모델 두 개를 같이 켜면 CPU를 나눠 써서 한 번 호출이 혼자일 때보다 오래 걸린다. `PG_ML_TIMEOUT_SECONDS`가 있으면 모든 모델 모듈의 `timeout_seconds`를 덮어쓴다.
- 같은 동작을 환경변수(`PG_DETECTOR_ENABLE`, `PG_DETECTOR_DISABLE`, `PG_DETECTOR_CANDIDATE_POLICY`, `PG_READINESS_TIMEOUT_MS`, `PG_DETECTOR_TIMEOUT_MS`)로도 할 수 있다. 옵션이 환경변수보다 우선한다.
- ml-span과 ml-v9가 읽는 범위는 `--ml-scope cue|full`로 고른다(환경변수 `PG_ML_SCOPE`). `cue`(기본)는 2,000자까지 통째로 읽고 더 긴 글은 단서 단어 주변 줄만 읽는다. `full`은 20,000자까지 통째로 읽고, 더 긴 글은 `cue`와 같이 처리한다. `full`은 느리다. 세훈 PC 기준 실제 저장소 글 20,000자에 호출당 약 4~6.4초가 걸리므로 모델 제한이 25초, 탐지기 대기가 30초(`--detector-timeout-ms`로 바꿀 수 있음)가 된다. 25초를 넘기면 다른 모델 오류와 같이 요청을 막는다. ml-qwen에는 적용되지 않는다.

`promptguard status`의 detector 정보에서 `adapters`(켜진 모듈)와 `skipped`(건너뛴 모듈과 이유)를 확인한다.

## 옵션 (`detector.json`)

| 옵션 | 모듈 | 기본값 | 뜻 |
|---|---|---|---|
| `repository` | 둘 다 | `../../../promptguard-model` | 민준 저장소 경로 |
| `checkpoint` / `bundle` | v9 / Qwen | `default` (ml-span, ml-qwen) / `models/span-detector-v9` (ml-v9) | `default`면 민준 저장소 모듈의 `DEFAULT_BUNDLE`을 따른다. 폴더를 직접 쓰면 그 폴더로 고정된다(저장소 기준, 예: `models/span-detector-v9`, `models/qwen-span-v2`) |
| `fallback_checkpoint` / `fallback_bundle` | ml-span / Qwen | `models/span-detector-v10` / `models/qwen-span-v3` | `default`인데 저장소가 `DEFAULT_BUNDLE`을 정하지 않았을 때 쓸 폴더 |
| `device` | 둘 다 | `cpu` / `auto` | `cpu`, `mps`, `cuda`, `auto` |
| `threshold` | 둘 다 | 모델 번들의 값 | 점수 cutoff. 비우면 민준이 validation에서 고정한 값 |
| `gate` | 둘 다 | `always` / `cue` | `cue`면 password, token, 비밀번호 같은 단어가 **단어 단위로** 있는 텍스트만 모델에 보낸다("tests passed"는 해당 없음) |
| `timeout_seconds` | 둘 다 | 4 / 25 | 모델 작업이 넘기면 오류로 처리해 요청을 막는다. 앞선 호출이 끝나기를 기다리는 시간은 따로 같은 길이만큼 허용한다 |
| `max_text_chars` | 둘 다 | 없음 / 12000 (Qwen) | 이보다 긴 텍스트는 이 모델이 보지 않고 다른 모듈에 맡긴다(cue 게이트와 같은 방식) |
| `too_long` | 둘 다 | `fail` (코드 기본) / `skip` (detector.json) | 줄 하나가 입력 한도를 넘거나 청크가 `max_chunks`보다 많을 때: `fail`이면 오류로 요청을 막고, `skip`이면 그 텍스트를 다른 모듈에 맡긴다. 2026-10-30 시연 리허설에서 Claude Code의 긴 시스템 텍스트 때문에 Qwen이 실패해 요청이 막혀 `skip`으로 정했다 |
| `min_value_length` | 둘 다 | 6 | 모델이 찍은 스팬이 이보다 짧거나 평범한 영어 단어(of, by, option 등)면 버린다. 2026-10-30 시연 중 ml-v9가 "of", "by"를 비밀로 찍은 오탐 때문에 넣었다. 6자 미만 비밀번호는 모델로는 가리지 않는다(다른 모듈은 여전히 검사) |
| `max_chunks`, `overlap_lines` | Qwen | 8, 1 | 입력 한도(4,096 토큰)를 넘는 텍스트를 줄 단위로 나누는 방식 |
| `long_text` | 둘 다 | `whole` (코드 기본) / `cue_windows` (v9, detector.json) | `cue_windows`면 `whole_text_chars`(2000)자 이하 텍스트는 통째로, 더 긴 텍스트는 cue 단어가 있는 줄과 앞뒤 `window_lines`(2)줄만 모델에 보낸다. 이때 `max_text_chars`는 모델이 읽는 창들의 합이고, 넘으면 `too_long`을 따른다. v9는 CPU에서 2KB에 약 0.4초, 20KB에 4~9초가 걸려 4초 timeout을 넘겼고, 큰 도구 출력은 매번 막혔다(2026-11-05 측정) |
| `scope` | ml-span, ml-v9 | `cue` | `full`이면 `full_text_chars`(20000)자까지 통째로 읽고, 더 긴 글은 단서 주변 방식으로 읽는다. 모델 제한은 `full_timeout_seconds`(25)가 된다. `PG_ML_SCOPE`와 `--ml-scope`가 이 값보다 우선하고, `PG_ML_TIMEOUT_SECONDS`는 제한 시간에서 계속 우선한다 |

## 동작 원칙

- **fail-closed:** 모델 오류, Qwen의 `invalid_json`·`truncated`·`input_too_long`, 청크 수 초과, timeout은 모두 `ADAPTER_FAILURE:<이름>`이 되고 Native Mod와 Final Guard가 요청을 막는다.
- **원문 비노출:** finding에는 위치, 점수, 모델 이름만 남는다.
- **버전 교체:** 민준이 같은 함수 형태로 새 모델을 올리고 `DEFAULT_BUNDLE`을 바꾸면, 그 저장소에서 `git pull`과 `git lfs pull` 후 PromptGuard를 재시작하면 된다. 가장 높은 번호의 폴더를 쓰지 않는 이유는 번호가 팀의 채택을 뜻하지 않기 때문이다. `ml_span/runtime.py`에는 아직 이 상수가 없어서 mmBERT는 `fallback_checkpoint`를 쓴다. 실제로 로드한 폴더는 `promptguard status`의 `adapters[].version`에 나온다(예: `span-detector-v10:abc32620dd4f`). 이 동작은 `ml-span`의 것이다. `ml-v9`는 저장소 기본이 바뀌어도 v9로 남으므로, v9라고 표시된 결과는 항상 v9다. 두 모듈을 같이 켜면 모델을 worker마다 두 벌 올린다. 함수 이름이나 출력 필드가 바뀌면 `src/detector/pgdetector/adapters/span_models.py`를 고친다.

## 실제 모델 확인 (2026-10-29, 세훈 PC, CPU)

합성 문장 3개로 설치와 연결만 확인한 결과다. 성능 근거가 아니다.

| 문장 | CredSweeper | 자체 규칙 | Shell-aware | ml-v9 | ml-qwen | 합집합 |
|---|---|---|---|---|---|---|
| 로그 속 인증 토큰 | 0 | 0 | 0 | 1 (282ms) | 1 (3.6초) | 1 |
| 한국어 "비밀번호는 …" | 0 | 0 | 0 | 1 (140ms) | 1 (3.8초) | 1 |
| 키 없는 빌드 로그 | 0 | 0 | 0 | 0 (108ms) | 0 (1.9초) | 0 |

마지막 줄의 Qwen 1.9초는 cue 패턴이 "passed"를 단서로 잡았기 때문이다. 이후 단어 단위로 고쳐 이런 문장에서는 Qwen을 건너뛴다.

## 알려진 비용

- PromptGuard는 detector worker를 두 개(Native Mod용, Final Guard용) 띄운다. 모델도 두 번 로드돼 메모리가 두 배 든다. Qwen(float32)은 worker당 약 2GB다.
- Qwen의 `gate: cue`는 속도를 위한 선택이다. cue 단어가 없는 텍스트의 키는 Qwen이 보지 않는다(다른 모듈은 여전히 검사한다).
- 테스트(`tests/detector/test_span_models.py`)는 가짜 모델로 adapter 동작만 검증한다. 실제 가중치로 돌린 결과가 아니다.

## 뒷단 검증기 (`--policy verifier`)

탐지기는 후보마다 strong/ambiguous를 붙인다. `candidate_policy: "verifier"`는 민준 저장소의 검증기 계획(`docs/ml_span/VERIFIER_PLAN.md`)의 "strong + 검증기" 정책이다.

- 후보의 strength는 `majority`와 같다. 다수결이 남긴 span 안에 있거나 어떤 규칙이 강한 근거를 냈으면 strong, 아니면 ambiguous다.
- strong 후보는 가린다. ambiguous 후보는 검증기의 P(MASK)가 기준값 이상일 때만 가린다. 나머지 ambiguous 후보는 가리지 않는다.
- 검증기는 `privai_model.verifier.runtime.CandidateVerifier`다. 로컬용 mmBERT 후보 분류기와 서버용 Qwen LoRA 검증기 번들을 모두 읽는다. 모델은 학습 때와 같은 코드(`verifier.candidates.candidate_records`)로 만든 입력을 받는다.
- 기준값은 번들에 들어 있다(validation에서 recall 0.99로 고정). `recall_target`으로 번들에 있는 다른 값(예: 0.95)을 고를 수 있다.
- **fail-closed:** 검증기 오류, 점수 개수나 범위 이상, timeout이면 그 텍스트의 후보를 전부 가리고 `ADAPTER_FAILURE:verifier`를 낸다. Native Mod와 Final Guard는 요청을 막는다.
- 후보에는 `verifier_score`(숫자)만 붙는다. 원문은 남기지 않는다.

```powershell
..\promptguard.cmd run --policy verifier
```

| 옵션 (`detector.json`의 `verifier`) | 기본값 | 뜻 |
|---|---|---|
| `repository` | `../../../promptguard-model` | 민준 저장소 경로 |
| `bundle` | `runs/verifier/creddata-mmbert-small/model` | 검증기 번들 폴더(저장소 기준). `PG_VERIFIER_BUNDLE`이 우선한다. 가중치는 저장소에 커밋되지 않으므로 학습한 PC에서 이 경로로 옮겨 둔다 |
| `device` | `cpu` | `cpu`, `mps`, `cuda`, `auto` |
| `recall_target` | `null` | `null`이면 번들의 배포 기준(0.99) |
| `context_lines` | 3 | 후보 앞뒤로 모델에 주는 줄 수. 학습 때와 같아야 한다 |
| `timeout_seconds` | 4 | 넘기면 fail-closed. `PG_ML_TIMEOUT_SECONDS`가 우선한다 |

- `--policy verifier`를 골랐는데 번들이 없거나 불러오지 못하면 PromptGuard가 시작하지 않는다. 기본 정책(`union`)에서는 검증기를 불러오지 않는다.
- worker 준비 대기 시간은 180초가 된다(`--readiness-timeout-ms`로 바꿀 수 있다).
- 학습 데이터의 channel은 CredData-trajectory 행의 source다. 실행 중에는 탐지기가 받은 scan source가 그 자리에 들어간다. 두 값의 어휘가 다르면 모델이 학습 때 못 본 입력을 받는다.
- 테스트(`tests/detector/test_verifier.py`)는 가짜 모델로 정책과 fail-closed 동작만 검증한다. 실제 검증기로 탐지기를 돌린 결과는 validation 정책 비교(F2 0.784, mmBERT-small)와 맞는지 따로 확인해야 한다.

## 측정용 덮어쓰기 (온프레미스 GPU)

제품 기본값(`detector.json`: ml-span·ml-v9·검증기 `device: cpu`, `timeout_seconds: 4`)은 그대로 두고, 측정할 때만 환경변수로 덮어쓴다.

| 환경변수 | 적용 대상 | 뜻 |
|---|---|---|
| `PG_ML_DEVICE` | ml-span, ml-v9 | `device`를 덮어쓴다(`cpu`, `cuda`, `mps`, `auto`). ml-qwen은 `detector.json`의 `device`를 그대로 쓴다 |
| `PG_VERIFIER_DEVICE` | 검증기 | 검증기의 `device`를 덮어쓴다 |
| `PG_ML_TIMEOUT_SECONDS` | ml-span, ml-v9, ml-qwen, 검증기 | `timeout_seconds`를 덮어쓴다. ml-span·ml-v9의 `scope: full` 기본 25초도 덮는다(이전부터 그랬고 테스트로 고정) |
| `PG_ML_CHECKPOINT` | ml-span | 체크포인트(번들 폴더). 모델 저장소 기준 상대 경로 또는 절대 경로. ml-v9는 v9에 고정이라 쓰지 않는다 |
| `PG_VERIFIER_BUNDLE` | 검증기 | 검증기 번들 폴더(이전부터 있음) |

- **예시 파일:** `src/detector/profiles/onprem.env` (device cuda, timeout 60초, 번들 경로 자리)
- **지표 1 오프라인 채점용이다.** 지표 2(실제 Claude Code)는 브리지 5초(`PG_DETECTOR_TIMEOUT_MS` 기본값)·훅 10초 제한이 있어 이 timeout이 그대로 적용되지 않는다.
- **측정 실행기:** `scripts/eval_integration/run.py --env-file FILE`이 파일의 값을 모든 실행에 넘긴다. 실행마다 `eval_config.json`에 기록한다.
  - `overrides`: 실행이 본 덮어쓰기 값. 경로는 마지막 폴더 이름만 남긴다.
  - `runtime`: 탐지기가 실제로 쓴 후보 정책, 켜진 모듈, 모델별 장치·timeout·번들 이름
  - 보고서의 "실행 설정" 표에도 낸다.
- **기록되는 값:** 탐지기는 `describe()["runtime_settings"]`로 모델 모듈과 검증기의 장치·timeout·번들 폴더 이름을 알려 준다. 경로는 내지 않는다.
- **채울 자리:** 예시 파일의 `<…>` 자리를 채우지 않고 `--env-file`로 넘기면 실행기가 멈춘다. 없는 번들로 돌면 ml-span이 조용히 빠진 채(선택 모듈) 측정되기 때문이다.
