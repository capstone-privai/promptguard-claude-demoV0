# Final Guard 백스톱: Mod가 놓친 경로도 막는가

Mod를 거치지 않은 요청(Mod가 모르는 경로, Mod 실패)을 Final Guard에 직접 보내 확인했다. 테스트: `tests/final-guard/guard.test.cjs`의 `backstop:` 테스트(`node --test tests/final-guard/guard.test.cjs`).

- 요청 본문에 합성 비밀(`PG_TEST_SECRET_…`)을 넣고 Guard에 POST한다. 탐지기는 그 값을 찾는 모의 탐지기(`tests/final-guard/mock-detector.cjs`)다.
- "막힘"은 다음을 모두 만족한다는 뜻이다: 응답 422 `DETECTOR_FINDINGS`, upstream 요청 0건, 응답 본문·헤더·Guard 감사 로그(`guard.jsonl`)·Guard stderr에 원래 값 없음, 감사 로그 마지막 행이 `decision: block`이고 endpoint가 맞음.

## 확인한 경로

| 위치 | `/v1/messages` | `/v1/messages/count_tokens` |
|---|---|---|
| user 메시지 (문자열 `content`) | 막힘 (기존 테스트) | — |
| user 메시지 (text 블록) | 막힘 | 막힘 |
| tool_result (문자열 content) | 막힘 | 막힘 |
| tool_result (text 블록 배열) | 막힘 | — |
| tool_result (`is_error: true`) | 막힘 | — |
| 이전 assistant 턴의 tool_use input 값 | 막힘 | — |
| 이전 assistant 턴의 text | 막힘 | — |
| system (문자열) | 막힘 | 막힘 |
| system (text 블록, cache_control 포함) | 막힘 | 막힘 |
| tools 정의의 description | 막힘 | — |
| document 블록 (`source.type: text`) | 막힘 | — |
| image 블록 (`source.type: url`, URL에 값) | 막힘 | — |

`—`는 따로 테스트하지 않은 칸이다. 두 엔드포인트는 같은 검사 코드(본문의 모든 JSON 문자열 값)를 거친다.

## 텍스트가 아닌 내용: 지금 동작 (고치지 않음)

Guard는 본문의 **모든 JSON 문자열 값을 그대로** 검사한다. 디코딩하지 않고, 객체의 **키**는 보지 않는다(`src/guard/lib.cjs`의 `collectStringLeaves`가 `Object.values`만 따라감).

| 경우 | 결과 |
|---|---|
| image 블록, base64 데이터가 값을 인코딩한 것 | **통과** (upstream으로 감) |
| document 블록, `text/plain` base64에 값이 들어 있음 | **통과** |
| image 블록, base64 필드에 값이 인코딩 없이 들어 있음 | 막힘 |
| tool_use input의 **객체 키**에 값이 있음 (`{ "<값>": "x" }`) | **통과** |

이미지 픽셀 속 글자(스크린샷에 찍힌 비밀번호)도 같은 이유로 볼 수 없다.

## 한계

- 탐지 자체는 모의 탐지기가 정확한 문자열로 찾는다. 이 표는 "Guard가 어느 위치를 검사하는가"를 보여 주고, "실제 탐지기가 그 값을 찾는가"(재현율)는 따로 봐야 한다.
- 다른 엔드포인트는 404로 막힌다(기존 테스트). 스트리밍 응답(모델 출력)은 검사하지 않고 그대로 전달한다(기존 테스트).
