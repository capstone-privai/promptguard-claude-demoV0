# 팀 ML 탐지기 adapter (ml-v9, ml-qwen)

민준 저장소 [`capstone-privai/promptguard-model`](https://github.com/capstone-privai/promptguard-model)의 두 모델을 PromptGuard 탐지기 모듈로 붙이는 adapter다. 두 모듈은 서로 독립이라 하나씩 또는 같이 켤 수 있다. 기본값은 둘 다 꺼짐이다.

| 모듈 | 감싸는 함수 | 모델 폴더 | 속도 (민준 측정, CPU 4스레드) |
|---|---|---|---|
| `ml-v9` | `privai_model.ml_span.runtime.MLSpanDetector.scan_text` | `models/span-detector-v9` (약 560MB) | 입력당 평균 33ms |
| `ml-qwen` | `privai_model.qwen_span.wrapper.QwenSecretScanner.scan` | `models/qwen-span-v2` (LoRA 35MB + 베이스 Qwen2.5-Coder-0.5B) | 입력당 평균 약 1.4초 |

두 모듈 모두 `candidate_only: true`라 `majority` 정책에서는 투표하지 않는다. `union` 정책(기본)에서는 하나만 잡아도 마스킹된다.

## 준비

1. 민준 저장소를 데모 저장소 **옆 폴더**에 둔다. 기본 경로는 `src/detector` 기준 `../../../promptguard-model`, 즉 데모 저장소와 같은 부모 폴더다. 다른 곳이면 `detector.json`의 `repository`를 바꾼다.
2. 그 폴더에서 `git pull`과 `git lfs pull`을 실행한다. 가중치가 LFS 포인터 상태(1KB 미만)면 모듈은 시작할 때 건너뛰고 이유를 출력한다.
3. 데모 `.venv`에 `torch`, `transformers>=4.51,<5`, `numpy`, `peft>=0.13,<1`를 설치한다. 민준 패키지는 설치하지 않아도 된다. adapter가 `promptguard-model/src`를 import 경로에 넣는다.
4. Qwen은 처음 실행할 때 베이스 모델을 Hugging Face에서 받는다. PromptGuard를 켜기 전에 한 번 받아 두지 않으면 worker 준비 시간(30초)을 넘길 수 있다.

## 켜고 끄기

`detector.json`을 고치지 않고 환경변수로 켠다. 이름은 쉼표로 구분하고, `PG_DETECTOR_DISABLE`이 `PG_DETECTOR_ENABLE`보다 우선한다.

```powershell
# v9만
$env:PG_DETECTOR_ENABLE = 'ml-v9'
# Qwen만 (느리므로 detector 대기 시간을 늘린다)
$env:PG_DETECTOR_ENABLE = 'ml-qwen'; $env:PG_DETECTOR_TIMEOUT_MS = '30000'
# 둘 다
$env:PG_DETECTOR_ENABLE = 'ml-v9,ml-qwen'; $env:PG_DETECTOR_TIMEOUT_MS = '30000'
# 기존 4종만 (끄기)
Remove-Item Env:PG_DETECTOR_ENABLE
```

`promptguard status`의 detector 정보에서 `adapters`(켜진 모듈)와 `skipped`(건너뛴 모듈과 이유)를 확인한다.

## 옵션 (`detector.json`)

| 옵션 | 모듈 | 기본값 | 뜻 |
|---|---|---|---|
| `repository` | 둘 다 | `../../../promptguard-model` | 민준 저장소 경로 |
| `checkpoint` / `bundle` | v9 / Qwen | `models/span-detector-v9` / `models/qwen-span-v2` | 모델 폴더 (저장소 기준) |
| `device` | 둘 다 | `cpu` / `auto` | `cpu`, `mps`, `cuda`, `auto` |
| `threshold` | 둘 다 | 모델 번들의 값 | 점수 cutoff. 비우면 민준이 validation에서 고정한 값 |
| `gate` | 둘 다 | `always` / `cue` | `cue`면 password, token, 비밀번호 같은 단어가 있는 텍스트만 모델에 보낸다 |
| `timeout_seconds` | 둘 다 | 4 / 25 | 넘기면 오류로 처리해 요청을 막는다 |
| `max_chunks`, `overlap_lines` | Qwen | 8, 1 | 입력 한도(4,096 토큰)를 넘는 텍스트를 줄 단위로 나누는 방식 |

## 동작 원칙

- **fail-closed:** 모델 오류, Qwen의 `invalid_json`·`truncated`·`input_too_long`, 청크 수 초과, timeout은 모두 `ADAPTER_FAILURE:<이름>`이 되고 Native Mod와 Final Guard가 요청을 막는다.
- **원문 비노출:** finding에는 위치, 점수, 모델 이름만 남는다.
- **버전 교체:** 민준이 같은 함수 형태로 새 모델을 올리면 그 저장소에서 `git pull` 후 PromptGuard를 재시작하면 된다. 함수 이름이나 출력 필드가 바뀌면 `src/detector/pgdetector/adapters/span_models.py`를 고친다.

## 알려진 비용

- PromptGuard는 detector worker를 두 개(Native Mod용, Final Guard용) 띄운다. 모델도 두 번 로드돼 메모리가 두 배 든다. Qwen(float32)은 worker당 약 2GB다.
- Qwen의 `gate: cue`는 속도를 위한 선택이다. cue 단어가 없는 텍스트의 키는 Qwen이 보지 않는다(다른 모듈은 여전히 검사한다).
- 테스트(`tests/detector/test_span_models.py`)는 가짜 모델로 adapter 동작만 검증한다. 실제 가중치로 돌린 결과가 아니다.
