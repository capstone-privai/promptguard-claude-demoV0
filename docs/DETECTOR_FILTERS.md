# 탐지기 거르기 (`PG_DETECTOR_FILTERS`, `PG_DETECTOR_FILTER_DUMMY`)

## 왜

정우의 0단계 오탐 분석(promptguard-data `eval/stage0-fp-analysis`, `metric-detection/results/stage0_fp_20261115/`)에서 오탐의 출처는 두 가지였다.

- **실제 트래픽(openhands, SWE-Gym):** 오탐은 대부분 자체 규칙 `secret-assignment`가 냈다. 비밀 자리에 변수·속성 참조, 함수 호출, 코드 표현식, 템플릿이 온 경우다.
- **CredData의 재마스킹 오탐:** `secret-assignment`와 CredSweeper `Password`가 HTML·코드 조각을 비밀로 잡고, 그 값이 반복돼 생겼다.

모양만 보고 재마스킹을 거르는 방식(PR #22 admitted)은 짧은 진짜 비밀번호까지 빼서 recall이 3%p 떨어졌다. 그래서 여기서는 길이와 상관없이 **구조상 비밀일 수 없는 값**만 거른다.

## 무엇을 거르나

두 설정 모두 기본값은 `off`이고, `off`면 지금과 결과가 같다.

| 설정 | 이름 | 걸러지는 값 | 예 |
|---|---|---|---|
| `PG_DETECTOR_FILTERS=on` | `assignment_reference` | `secret-assignment`만: 값이 속성 참조 (`self.`, `config.` 같은 받는 쪽으로 시작하거나, 마지막이 password·token·key 같은 이름) | `self.password`, `config.db.password`, `settings.SECRET_KEY` |
| | `assignment_code` | `secret-assignment`만: 값이 식별자의 호출이나 인덱스이고, 따옴표 인자가 모두 키 이름 | `get_token()`, `os.getenv(`, `request.headers[` |
| | `assignment_template` | `secret-assignment`만: 값이 템플릿. 따옴표 안에서도 거른다 | `{{vault_password}}`, `"%(secret_key)s"` |
| | `html_fragment` | 모든 탐지기: HTML 엔티티나 알려진 HTML 태그, 그 사이에 글자·공백·`/`만 있는 값 | `&lt;/p&gt;`, `</p>`, `<pre><code>`, `&#39;` |
| | `css_value` | 모든 탐지기: CSS 키워드, `px`·`em`·`rem`·`vh`·`vw`·`%` 길이, 닫는 괄호까지 있고 안이 CSS 값인 함수 | `:unset`, `!important`, `12px`, `50%`, `rgba(0,0,0,0.5)`, `var(--main-color)`, `calc(100% - 12px)` |
| | `template` | 모든 탐지기: 템플릿과 자리표시자 | `{{ x }}`, `{% x %}`, `${X}`, `#{x}`, `<db-password>`, `%(x)s`, `{x}`, `[PASSWORD_1]` |
| | `code_fragment` | 모든 탐지기: `(`나 `[`로 끝나는 식별자, 또는 닫혔는데 안에 코드만 있는 호출·인덱스(아래) | `function(`, `attributes[`, `get_token()`, `options['password']`, `os.environ["DB_PASS"]`, `config.get("db.password")` |
| `PG_DETECTOR_FILTER_DUMMY=on` (따로) | `dummy_value` | 모든 탐지기: 자리표시 모양만 (정확히 일치하는 목록과 명시적 패턴) | `<password>`, `replace_me`, `your_api_key_here`, `<your-token>`, `xxxxxxxx`, `********`, `REDACTED` |

**어떤 값을 거르고 어떤 값을 남기나**

- **코드 조각:** 닫힌 괄호·대괄호 안에는 비어 있음, 식별자·속성 참조, 따옴표로 감싼 키 이름, 이들의 쉼표 목록만 올 수 있다. 그 밖의 문자가 있으면 통과한다. 예를 들어 `Xk9(mZ!q#2)`, `S3cr3t(!)`는 통과한다.
- **키 이름:** 환경변수 이름(`[A-Z_][A-Z0-9_]*`, 예 `DB_PASS`)이나, 숫자 없는 소문자 단어를 `.` `_` `-`로 이은 것(`[a-z]+(?:[._-][a-z]+)*`, 예 `db.password`)뿐이다. 8자 이상 16진수는 글자만 있어도(`deadbeefcafe`) 키 이름이 아니다.
- **따옴표 인자:** 키 이름이 아닌 따옴표 인자가 하나라도 있으면 거르지 않는다. 16진수, 숫자·글자가 섞인 값, 그 밖의 문자가 든 값이 여기에 든다. `os.getenv("DB_PASS", "<비밀>")`, `options['<비밀>']`, `String("<32자 hex>")`가 그 예다. `secret-assignment`는 값이 따옴표 앞에서 끊기므로, 같은 줄에서 닫히는 호출 전체로 판정한다.
- **숫자만 든 괄호:** `Hunter(2)`, `Summer[2024]`, `Pass(12, 34)`처럼 숫자만 든 괄호는 코드와 비밀번호를 구분할 수 없어 거르지 않는다.
- **CSS 함수:** 닫는 괄호까지 있고 안이 CSS 값 모양일 때만 거른다. `var(Xk9!q`, `url(Xk9!q)`, `calc(Xk9!)`는 통과한다.
- **CSS 길이 단위:** `px`, `em`, `rem`, `vh`, `vw`, `%`만 본다. `19951231s`, `300ms`, `12deg`처럼 다른 단위로 읽히는 값은 통과한다.
- **따옴표 안의 값 (`secret-assignment`):** 문자열 리터럴로 본다. `"Admin.Master.Key"`, `'alpha.bravo.charlie'`, `"get_token()"`은 참조·코드로 거르지 않는다. 템플릿(`"{{ x }}"`, `"%(name)s"`)만 따옴표 안에서도 거른다.
- **.env 형식 값 (`secret-assignment`):** 줄 맨 앞(또는 `export` 뒤)의 대문자 키에 `=` 앞뒤 공백이 없는 줄은 따옴표가 없어도 리터럴로 본다. 예를 들어 `DB_PASSWORD=alpha.bravo.charlie`다. 템플릿만 거른다.
- **그 밖의 따옴표 없는 값:** 참조·코드·템플릿을 모두 판정한다. 점으로 나뉜 덩어리가 3개 이상이라는 것만으로는 참조로 보지 않는다. 첫 덩어리가 알려진 receiver(`self`, `config`, `settings` 등)이거나 마지막 덩어리가 비밀 단어일 때만 참조다. 그래서 `password = alpha.bravo.charlie`는 통과하고 `config.db.password`, `self.password`는 걸러진다.
- **그 밖에 통과하는 값:** `p@ss(w0rd`, `Tr0ub&dor`, `a<b>c!9`, `my&lt!pass9`처럼 위 구조와 맞지 않는 값이다.
- **흔한 비밀번호와 약한 기본 비밀번호:** `password123`, `admin123`, `letmein2026`, 그리고 `changeme`, `change_me`, `change-me`, `changeit`, `dummy`는 `dummy_value`도 거르지 않는다. 라벨 가이드 결정 3에 따라 약한 기본 비밀번호는 가려야 하는 값이다.
- **판정 방법:** 탐지기 묶음의 거르기는 값 앞뒤의 따옴표와 공백을 뗀 문자열로 판정한다. 길이는 어디에서도 기준이 아니다.

## 거르기와 별개인 탐지 범위 확대: 조회 호출의 기본값

`secret-assignment`는 비밀 이름의 키에 아래 조회 호출이 오면, 키 이름 모양이 아닌 따옴표 기본값을 비밀 후보로 낸다. 거르기를 켜든 끄든 같다.

- `os.getenv(..., "…")`
- `os.environ.get(..., "…")`
- `process.env.X || "…"`, `process.env.X ?? "…"`
- `config.get(..., "…")`

이전에는 다음과 같았다.
- **거르기를 켠 경우:** 호출(`os.getenv(`)을 통째로 코드로 거르면서, 기본값의 비밀도 같이 버렸다.
- **거르기를 끈 경우:** `os.environ.get`과 `process.env`는 자리표시 규칙(`PLACEHOLDER`)에 걸려 아예 보지 않았다.

이제는 다음과 같다.
- **거르기를 켠 경우:** 기본값을 따로 내고, 호출 자체(`os.getenv(`)는 `assignment_code`로 셈한다.
- **거르기를 끈 경우:** 호출은 지금처럼 내고, 기본값을 더 낸다.

키 이름 모양인 기본값(`"DEFAULT_PASS"`, `"db.password"`)은 내지 않는다.

**측정 주의:** 이 변경으로 off 기준선도 바뀐다. off에서도 `os.environ.get`·`process.env`의 기본값과 `os.getenv`·`config.get`의 기본값을 잡는다. 따라서 off와 on의 차이에는 이 탐지 확대가 들어 있지 않다. 이전 측정값(예: CredData-trajectory 668c2c1)과 비교할 때는 off도 다시 돌려야 한다.

## 어디서 거르나

거르기는 `pgdetector`의 `Detector.collect()` 안에 있다. 모든 탐지기의 결과를 투표와 병합(합집합) 전에 거른다.

- Native Mod와 Final Guard는 각자 탐지기 프로세스를 띄우지만, 둘 다 같은 `pgdetector`를 쓴다. 같은 설정이면 같은 텍스트를 같은 결과로 판단한다(`tests/final-guard/detector_filters_real.test.cjs`). 한쪽에만 거르기를 넣으면, Mod가 통과시킨 값을 Guard가 422로 막게 된다.
- `collect()`가 거른 뒤의 결과를 돌려주므로, `collect()`를 기록하는 정우의 채점기(`per_finding.jsonl`)도 거른 뒤의 결과를 본다.
- 응답의 각 item에는 `filtered: {이름: 개수}`가 붙는다. 이름별 개수만 있고 값은 없으며, 설정이 꺼져 있으면 이 필드가 없다.

### 두 프로세스에 같은 값을 준다

Native Mod의 탐지기(Transform)와 Final Guard의 탐지기(Verification)에는 `PG_DETECTOR_FILTERS`와 `PG_DETECTOR_FILTER_DUMMY`를 **같은 값으로** 줘야 한다. Mod 쪽만 켜면 Mod가 통과시킨 값을 Guard가 422로 막는다.

- **`promptguard run`:** 두 프로세스가 같은 환경변수를 물려받으므로 실행 환경에 한 번만 주면 된다.
- **설정이 다를 때:** 각 탐지기는 준비 응답(`/ready`의 `filter_settings`)에 두 설정을 on/off로 알린다. 런타임은 시작할 때 둘을 비교한다. 다르면 경고를 낸다(설정 이름만, 값 없음). 그러면 Final Guard가 막을 때 422 응답의 `message`에 "필터 설정 불일치: <설정 이름>"을, `filter_settings_mismatch`에 그 이름 목록을 적는다.
- **프로세스를 따로 띄울 때:** 두 프로세스를 직접 띄우는 경우에도 같은 값을 줘야 한다.

## 고신뢰 규칙은 거르지 않는다

`src/detector/high-confidence-rules.json`의 18개 (탐지기, 규칙) 쌍이 찾은 값은 어느 거르기에도 걸리지 않는다. 목록은 PR #22(`fix/remask-admission`)의 `src/native-mod/remask-admission.json`과 같다. 기준은 `rules.csv` 형식 탐지 그룹, ML 끔에서 precision 0.90 이상, 탐지 10건 이상, 혼자 낸 오탐 2% 이하다.

**위치를 `src/detector/`로 정한 이유:**
- 규칙 이름은 탐지기가 정하는 이름이다.
- 거르기는 탐지기 안에서 이 목록을 읽는다.
- Native Mod도 PR #21의 접두어 표처럼 `$.plugin.root`에서 상대 경로(`../detector/high-confidence-rules.json`)로 같은 파일을 읽을 수 있다. #22는 자기 사본 대신 이 파일을 읽도록 바꾸면 된다.

## 측정 (정우)

### (a) 기존 9개 데이터셋 (`eval/stage0-fp-analysis` 브랜치)

promptguard-data 루트에서 이 브랜치의 PromptGuard(`$PG`)로 ML을 끄고(기본) 돌린다. `run_eval.py`는 채점기를 고치지 않는다. 실행 중에만 설정을 켜고, 결과 폴더에 `filters.jsonl`(item별 이름별 개수와 걸러낸 finding의 탐지기·규칙·위치, 값 없음)을 남긴다.

```bash
PG=../promptguard-claude-demoV0
for cfg in off on; do
  for d in sessions sessions_2 sessions_from_example sessions_from_CredData sessions_from_noseyparker \
           sessions_from_Nemotron-PII sessions_from_trajectory sessions_from_openhands-feedback sessions_from_SWE-Gym; do
    python $PG/scripts/detector_filters/run_eval.py --data-root . --filters $cfg -- \
      run --system promptguard --system-root $PG \
      --sessions metric-detection/data_test/$d.jsonl --out metric-detection/results/filters_$cfg
  done
done
python $PG/scripts/detector_filters/compare.py --data-root . \
  --run off=metric-detection/results/filters_off --run on=metric-detection/results/filters_on --out filters_compare_a.md
```

`compare.py`는 데이터셋별로 다음을 표로 낸다.
- precision, recall(정확히/덮었는가)
- 탐지기 오탐(병합된 finding span과 같은 edit)과 재마스킹 오탐(그 밖의 edit)
- 덮었는가 기준 recall 변화(%p)와 거르기 규칙별 걸러낸 수
- on에서 새로 놓친 비밀: 정답 유형, 그 위를 걸러낸 거르기 이름, 탐지기:규칙별

규칙별 수치(`rules.csv`)도 기존 방식대로 비교할 수 있다: `python -m evaluation.report.fp_analysis --config off results/filters_off --config on results/filters_on --out results/filters_fp` (`metric-detection/`에서).

### (b) creddata-v1 test 분할 (`creddata-trajectory-data` 브랜치)

그 브랜치의 채점은 덮은 recall, 글자 단위 precision, F2를 쓴다. `sessions_from_CredData-trajectory.jsonl`(test 분할)로 off, on, on+dummy와 프로토타입(CredSweeper만, ML 끔)을 돌린다.

```bash
PG=../promptguard-claude-demoV0
S=metric-detection/data_test/sessions_from_CredData-trajectory.jsonl
for cfg in off on on+dummy; do
  python $PG/scripts/detector_filters/run_eval.py --data-root . --filters $cfg -- \
    run --system promptguard --system-root $PG --sessions $S --out runs/filters/$cfg
done
python metric-detection/scripts/evaluate.py run --system credsweeper --ml off --sessions $S --out runs/filters/prototype
python $PG/scripts/detector_filters/compare.py --data-root . \
  --run off=runs/filters/off --run on=runs/filters/on --run on+dummy=runs/filters/on+dummy \
  --prototype runs/filters/prototype --out filters_compare_b.md
```

**채택 기준 (b):** 덮은 recall 손실이 off 대비 1%p 이내이고, F2가 프로토타입 0.816 이상이어야 한다. `compare.py` 마지막 표가 둘을 판정한다. 하나라도 못 넘으면 "새로 놓친 비밀" 표에서 거르기 이름과 탐지기:규칙별로 원인을 본다.

두 스크립트 모두 값은 출력하지 않는다.
