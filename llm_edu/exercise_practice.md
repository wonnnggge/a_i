# 따라 하기: 보안 공지 요약 봇 — 클라우드 모델 vs 내 PC 로컬 모델

이 문서를 처음부터 끝까지 따라 하면 `exercise.ipynb` 와 같은 노트북을 직접 만들 수 있습니다.

과제 명세는 [exercise.md](exercise.md) 에 있습니다.
**명세를 먼저 읽고 스스로 풀어 본 뒤**, 막히는 곳에서 이 문서를 펴는 것을 권합니다.

완성하면 **영문 보안 공지 10건을 네 모델에 요약시키고, 어느 모델을 쓸지 숫자로 고르는 노트북**이 됩니다.
새로운 기술은 쓰지 않습니다. `1_1` ~ `1_7` 에서 배운 것만으로 만듭니다.

## 무엇을 만드나

```
영문 보안 공지 10건 (수백~수천 자)
        |   같은 프롬프트, 같은 temperature
  gpt-4.1-mini · gpt-4.1-nano · qwen2.5:3b · llama3.2
        |
제품 / 영향 / 조치 / 긴급도   <- 네 줄로
        |
형식 · 제품 · 조치 · 지어냄 · 토큰 · 시간   모델별 비교표
```

## 무엇을 배우나

| 단계 | 배우는 것 |
|---|---|
| 프롬프트 | 형식을 좁혀야 **채점할 수 있다**는 것 |
| 모델 딕셔너리 | 클라우드와 로컬을 **같은 코드로** 부르는 법 |
| 토큰 | 돈을 쓰기 전에 입력 크기를 재는 법 |
| 채점 | **검사 기준과 파싱 기준이 어긋나면 점수가 거짓말을 한다**는 것 |
| 지어내기 | 모르는 것을 모른다고 말하게 만드는 한 줄 |
| 고르기 | 점수 하나로 모델을 고르면 안 되는 이유 |

## 전체 흐름

```
공지 읽기 -> (1) 프롬프트 -> (2) 모델 딕셔너리 -> (3) 토큰 세기 -> (4) 채점표
          -> (5) 40회 호출 -> (6) 점수표 -> (7) 지어내기 관찰 -> (8) 저장 -> (9) 결론
```

> **이 문서에서 가장 중요한 세 곳**
>
> - **Step 6** — 형식 검사를 `in` 으로 하면 안 되는 이유
> - **Step 8** — 무료 로컬 모델이 유료 클라우드 모델을 이긴 결과
> - **Step 9-2** — "모르면 이렇게 쓰라"는 한 줄을 빼 보고 직접 재기
>
> 코드만 따라 치고 넘어가지 마세요. 이 세 곳이 과제의 내용입니다.

---

## 사전 준비

### 1. 패키지 설치

```bash
pip install openai tiktoken python-dotenv
```

`uv` 를 쓰고 있다면 이미 다 들어 있습니다.

### 2. `.env` 확인

프로젝트 폴더(`llm_edu/`)의 `.env` 에 두 줄이 있어야 합니다.

```
OPENAI_API_KEY=sk-proj-...
OLLAMA_URL=http://localhost:11434/v1
```

> **비용 안내**: OpenAI 모델 2개 × 공지 10건 = 20회 호출이고, 입력이 모두 합쳐 약 4,850토큰입니다.
> `gpt-4.1-mini` · `nano` 기준 **1센트 미만**입니다. 로컬 모델은 공짜입니다.

### 3. 로컬 모델 받기

터미널에서 한 번만 받으면 됩니다. `1_3_ollama` · `1_3_2_qwen` 에서 쓴 것과 **같은 모델**입니다.

```bash
ollama pull qwen2.5:3b
ollama pull llama3.2
ollama list
```

> Ollama 가 없다면 <https://ollama.com> 에서 받으세요. 설치하면 백그라운드에서 자동으로 뜹니다.
> `ollama list` 가 목록을 보여 주면 준비된 것입니다.

### 4. 데이터 파일

`advisories_sample.json` 이 노트북과 **같은 폴더**에 있어야 합니다. 직접 만들 필요는 없습니다.

| 필드 | 내용 |
|---|---|
| `no` | 1 ~ 10 |
| `cve_id` | CVE 번호 |
| `label` | 제품 이름 — **채점용입니다. 모델에게 주지 마세요** |
| `advisory` | 공지 본문 — 이것만 모델에게 줍니다 |

### 5. 새 노트북 만들기

`llm_intro/exec/` 폴더에 새 주피터 노트북을 만듭니다.
이제부터 나오는 코드를 **셀 하나씩** 입력하고 실행하세요.

---

## Step 1. 준비

```python
import json
import os
import re
import time
from datetime import datetime

import tiktoken
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)

openai_api_key = os.getenv("OPENAI_API_KEY")
ollama_url = os.getenv("OLLAMA_URL")

print("OpenAI key :", "있음" if openai_api_key else "없음 — .env 를 확인하세요")
print("Ollama URL :", ollama_url)

# Ollama 가 실제로 떠 있는지, 어떤 모델이 받아져 있는지 지금 확인합니다.
# 40회 호출을 다 돌린 뒤에 "연결 안 됨"을 알게 되면 시간만 버립니다.
try:
    probe = OpenAI(api_key="ollama", base_url=ollama_url)
    installed = sorted(m.id for m in probe.models.list())
    print("로컬 모델  :", ", ".join(installed) or "없음 — ollama pull 로 받으세요")
except Exception as e:
    print("로컬 모델  : 연결 실패 —", type(e).__name__)
    print("             Ollama 가 떠 있는지 터미널에서 'ollama list' 로 확인하세요")
```

실행하면 이렇게 나와야 합니다.

```
OpenAI key : 있음
Ollama URL : http://localhost:11434/v1
로컬 모델  : llama3.2:3b, llama3.2:latest, phi3:latest, qwen2.5:3b
```

### 여기서 확인할 것

**로컬 모델 연결을 지금 확인하는 이유**가 있습니다.
이 노트북은 뒤에서 **40회를 호출**하고, 로컬 모델 때문에 몇 분이 걸립니다.
다 돌린 뒤에 "Ollama 가 안 떠 있었다"를 알게 되면 그 시간을 전부 버립니다.

> **오래 걸리는 작업은 시작 전에 전제를 확인합니다.** 코드 길이보다 중요한 습관입니다.

`연결 실패` 가 나오면 터미널에서 `ollama list` 를 쳐 보세요.

---

## Step 2. 공지 10건 읽기

```python
advisories = json.loads(open("advisories_sample.json", encoding="utf-8").read())

print(f"공지 {len(advisories)}건\n")
for a in advisories:
    print(f"{a['no']:2}. {a['cve_id']:16} {a['label']:22} {len(a['advisory']):5}자")
```

```
공지 10건

 1. CVE-2021-44228   Apache Log4j2           2500자
 2. CVE-2022-22965   Spring Framework        1830자
 3. CVE-2017-5638    Apache Struts 2         1726자
 4. CVE-2014-6271    GNU Bash                1011자
 5. CVE-2023-49105   ownCloud                 383자
 6. CVE-2026-48710   Starlette               2500자
 7. CVE-2026-59822   LiteLLM                 1752자
 8. CVE-2026-75650   Adobe Commerce           350자
 9. CVE-2026-49869   Kestra                   772자
10. CVE-2026-73570   Zimbra Collaboration     418자
```

공지 하나가 어떻게 생겼는지 눈으로 봅니다.

```python
# 공지 하나가 어떻게 생겼는지 눈으로 확인
print(advisories[4]["cve_id"], "|", advisories[4]["label"])
print()
print(advisories[4]["advisory"])
```

```
CVE-2023-49105 | ownCloud

An issue was discovered in ownCloud owncloud/core before 10.13.1. An attacker can access, modify, or delete any file without authentication if the username of a victim is known, and the victim has no signing-key configured. This occurs because pre-signed URLs can be accepted even when no signing-key is configured for the owner of the files. The earliest affected version is 10.6.0.
```

### 여기서 확인할 것

- 공지 길이가 **제각각**입니다. 짧은 것은 300자대, 긴 것은 2,000자가 넘습니다
- 전부 **영문**입니다. 우리는 **한국어 요약**을 받을 것입니다
- `label` 은 채점용입니다. 모델에게 주면 제품 이름 맞히기가 공짜가 됩니다

---

## Step 3. 요약 프롬프트 — 네 줄로 고정

```python
SYSTEM_PROMPT = """당신은 보안 공지를 요약하는 분석가입니다.

아래 형식으로 **정확히 네 줄**만 답하세요. 다른 말을 덧붙이지 마세요.

제품: <제품 이름과 영향받는 버전>
영향: <공격자가 무엇을 할 수 있는지 한 문장>
조치: <올려야 할 버전. 공지에 버전이 없으면 정확히 "공지에 없음">
긴급도: <긴급|높음|보통|낮음 중 하나>

규칙
- 공지에 적힌 내용만 쓰세요. 공지에 없는 버전·날짜·수치를 지어내지 마세요.
- 버전이 공지에 없으면 반드시 "공지에 없음"이라고 쓰세요. 추측하지 마세요.
- 한국어로 답하세요."""


def build_messages(advisory_text):
    """공지 하나를 messages 로 만든다."""
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"다음 보안 공지를 요약하세요.\n\n{advisory_text}"},
    ]


print(SYSTEM_PROMPT)
```

```
당신은 보안 공지를 요약하는 분석가입니다.

아래 형식으로 **정확히 네 줄**만 답하세요. 다른 말을 덧붙이지 마세요.

제품: <제품 이름과 영향받는 버전>
영향: <공격자가 무엇을 할 수 있는지 한 문장>
조치: <올려야 할 버전. 공지에 버전이 없으면 정확히 "공지에 없음">
긴급도: <긴급|높음|보통|낮음 중 하나>

규칙
- 공지에 적힌 내용만 쓰세요. 공지에 없는 버전·날짜·수치를 지어내지 마세요.
- 버전이 공지에 없으면 반드시 "공지에 없음"이라고 쓰세요. 추측하지 마세요.
- 한국어로 답하세요.
```

### 왜 형식을 이렇게 좁히나

**채점하기 위해서입니다.** "이 공지를 요약해 줘" 라고만 하면 모델마다 다른 모양으로 답하고,
그러면 네 모델을 **비교할 수 없습니다.** 비교하려면 먼저 **같은 자로 잴 수 있어야** 합니다.

`system` 에 넣은 두 문장이 특히 중요합니다.

| 문장 | 하는 일 |
|---|---|
| "공지에 적힌 내용만 쓰세요" | 근거 없는 말을 막는 장치 |
| "없으면 정확히 `공지에 없음`" | **모를 때 쓸 말을 미리 줍니다** |

두 번째가 왜 필요한지는 **Step 9-2 에서 직접 빼 보고 확인**합니다. 지금은 믿지 마세요.

---

## Step 4. 모델 딕셔너리 — 추가는 한 줄

```python
openai_client = OpenAI()
ollama_client = OpenAI(api_key="ollama", base_url=ollama_url)   # 키는 아무 값이나 됩니다

# 이름: (클라이언트, 모델 ID, max_tokens)
# 모델을 더 비교하고 싶으면 이 딕셔너리에 한 줄만 넣으면 됩니다.
MODELS = {
    "gpt-4.1-mini": (openai_client, "gpt-4.1-mini", 300),
    "gpt-4.1-nano": (openai_client, "gpt-4.1-nano", 300),
    "qwen2.5:3b":   (ollama_client, "qwen2.5:3b",   300),
    "llama3.2":     (ollama_client, "llama3.2",     300),
}

print("비교할 모델", len(MODELS), "개")
for name, (_, model_id, mt) in MODELS.items():
    where = "로컬" if _ is ollama_client else "클라우드"
    print(f"  {name:16} {where:5} -> {model_id:16} max_tokens={mt}")
```

```
비교할 모델 4 개
  gpt-4.1-mini     클라우드  -> gpt-4.1-mini     max_tokens=300
  gpt-4.1-nano     클라우드  -> gpt-4.1-nano     max_tokens=300
  qwen2.5:3b       로컬    -> qwen2.5:3b       max_tokens=300
  llama3.2         로컬    -> llama3.2         max_tokens=300
```

### 여기서 짚고 갈 한 줄

```python
ollama_client = OpenAI(api_key="ollama", base_url=ollama_url)
```

**로컬 모델도 똑같은 `OpenAI` 클래스로 부릅니다.** 다른 건 `base_url` 하나뿐입니다 (`1_3_ollama`).
`api_key` 는 아무 값이나 됩니다 — 로컬이라 인증이 없지만 라이브러리가 뭔가를 요구하기 때문입니다.

덕분에 뒤에 나올 `ask()` 함수는 **클라우드인지 로컬인지 전혀 모르고도** 네 모델을 다 처리합니다.
모델을 코드가 아니라 데이터로 다룬다는 게 이런 뜻입니다 (`1_4_llms`).

### 왜 클라우드 2개 + 로컬 2개인가

| | 모델 | 돈 | 공지문이 나가는 곳 |
|---|---|---|---|
| 클라우드 | `gpt-4.1-mini`, `gpt-4.1-nano` | 토큰당 과금 | 외부 API 서버 |
| 로컬 | `qwen2.5:3b`, `llama3.2` | **0원** | **내 PC 밖으로 안 나감** |

보안 업무에서는 오른쪽 두 열이 장점이 아니라 **조건**일 때가 많습니다.
사내 자산 정보가 섞인 공지를 외부로 보낼 수 없는 조직이 있기 때문입니다.
그래서 이 과제의 질문은 "어느 모델이 똑똑한가" 가 아니라 이것입니다.

> **공짜이고 밖으로 나가지 않는 대신, 무엇을 얼마나 잃는가?**

로컬 모델을 **두 개** 넣은 것도 일부러입니다. 같은 3B 급이라고 결과가 같지 않습니다.

---

## Step 5. 보내기 전에 토큰 세기

```python
encoding = tiktoken.get_encoding("o200k_base")   # gpt-4.1 계열


def count_tokens(messages):
    return sum(len(encoding.encode(m["content"])) for m in messages)


total_in = 0
print(f"{'번호':>4} {'CVE':16} {'입력 토큰':>9}")
for a in advisories:
    n = count_tokens(build_messages(a["advisory"]))
    total_in += n
    print(f"{a['no']:>4} {a['cve_id']:16} {n:>9,}")

print(f"\n공지 10건 합계: {total_in:,} 토큰 (모델 1개 기준)")
print(f"모델 {len(MODELS)}개면 약 {total_in * len(MODELS):,} 토큰")
```

```
  번호 CVE                  입력 토큰
   1 CVE-2021-44228         789
   2 CVE-2022-22965         633
   3 CVE-2017-5638          573
   4 CVE-2014-6271          370
   5 CVE-2023-49105         274
   6 CVE-2026-48710         672
   7 CVE-2026-59822         560
   8 CVE-2026-75650         250
   9 CVE-2026-49869         350
  10 CVE-2026-73570         269

공지 10건 합계: 4,740 토큰 (모델 1개 기준)
모델 4개면 약 18,960 토큰
```

### 여기서 확인할 것

`tiktoken` 은 **API 를 부르지 않습니다.** 내 PC 에서 셉니다 (`1_5_tokenizer`).
그래서 **돈을 쓰기 전에** 얼마나 쓸지 가늠할 수 있습니다.

> Qwen·Llama 는 토크나이저가 달라 이 값과 정확히 일치하지 않습니다.
> 여기서는 공지들의 **상대적 크기**를 보려는 것이므로 OpenAI 기준으로 셉니다.
> 실제 토큰 수는 Step 7 에서 응답의 `usage` 로 모델별로 따로 받습니다.

---

## Step 6. 채점표

```python
# no: (제품 낱말, [조치 낱말 — 하나만 맞으면 정답])
ANSWER_KEY = {
    1:  ("Log4j",          ["2.16.0"]),
    2:  ("Spring",         ["5.3.18", "5.2.20"]),
    3:  ("Struts",         ["2.3.32", "2.5.10.1"]),
    4:  ("Bash",           []),            # 공지에 버전 없음
    5:  ("ownCloud",       ["10.13.1"]),
    6:  ("Starlette",      ["1.0.1"]),
    7:  ("LiteLLM",        ["1.84.0"]),
    8:  ("Adobe Commerce", []),            # 공지에 버전 없음
    9:  ("Kestra",         ["1.0.45", "1.3.21"]),
    10: ("Zimbra",         ["10.1.20"]),
}

REQUIRED_LINES = ["제품:", "영향:", "조치:", "긴급도:"]
NO_VERSION = "공지에 없음"


def has_line(answer, prefix):
    """그 줄이 '제품:' 으로 시작하는가.

    "제품:" 이 답변 어딘가에 있기만 하면 되는 걸로 검사하면 안 됩니다.
    어떤 모델은 "# 제품: ..." 처럼 앞에 기호를 붙입니다.
    그러면 검사는 통과하지만 아래 get_line() 은 그 줄을 못 꺼냅니다.
    검사와 파싱이 같은 기준을 써야 점수가 거짓말을 하지 않습니다.
    """
    return any(line.strip().startswith(prefix) for line in answer.splitlines())


def get_line(answer, prefix):
    """답변에서 '조치:' 같은 줄 하나를 꺼낸다."""
    for line in answer.splitlines():
        if line.strip().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def grade(no, answer):
    """형식 · 제품 · 조치 세 가지를 채점한다."""
    product, versions = ANSWER_KEY[no]

    form = all(has_line(answer, p) for p in REQUIRED_LINES)
    prod = product.lower() in answer.lower()

    action = get_line(answer, "조치:")
    if versions:
        act = any(v in action for v in versions)
        made_up = False
    else:
        # 버전이 없는 공지 — "공지에 없음" 이라고 해야 정답
        # 공백을 양쪽 다 지우고 비교합니다. "공지에없음" 처럼 붙여 쓰는 모델이 있습니다.
        act = NO_VERSION.replace(" ", "") in action.replace(" ", "")
        # 숫자가 들어간 버전처럼 보이는 말을 했다면 지어낸 것
        made_up = bool(re.search(r"\d+\.\d+", action))

    return {"형식": form, "제품": prod, "조치": act, "지어냄": made_up}


print("채점표", len(ANSWER_KEY), "건")
print("버전이 공지에 없는 건:", [n for n, (_, v) in ANSWER_KEY.items() if not v])
```

```
채점표 10 건
버전이 공지에 없는 건: [4, 8]
```

### 가장 중요한 함수 — `has_line()`

처음에는 형식 검사를 이렇게 썼습니다. 훨씬 짧고, 멀쩡해 보입니다.

```python
form = all(p in answer for p in REQUIRED_LINES)     # 이렇게 하면 안 됩니다
```

그런데 `llama3.2` 가 실제로 이렇게 답했습니다 (1번 Log4j).

```
# 제품: Log4j
# 영향: 로그인한 사용자가 LDAP JNDI 파서를 통해 공격자가 원격 코드 실행을 할 수 있습니다.
#조치: 공지에 없음
#긴급도: 높음
```

`"제품:"` 은 `"# 제품:"` 안에 **들어 있습니다.** 그래서 `in` 으로 하는 형식 검사는 **통과**합니다.
하지만 `get_line()` 은 `line.strip().startswith("조치:")` 로 줄을 찾으므로 **못 찾습니다.**

결과가 이렇게 됩니다.

| | 결과 |
|---|---|
| 형식 점수 | O (통과) |
| 조치 점수 | X (줄을 못 꺼내서 빈 문자열) |
| 사실 | **형식이 틀린 것이 진짜 원인** |

점수표를 보는 사람은 "형식은 맞는데 버전을 못 찾는 모델" 이라고 **잘못 읽게 됩니다.**

> **검사 기준과 파싱 기준이 다르면 점수가 거짓말을 합니다.**
> 그래서 `has_line()` 은 `get_line()` 과 **같은 기준**(`strip().startswith`)을 씁니다.
> 측정 코드를 짤 때 가장 자주 하는 실수가 이것입니다.

### 공백 처리도 양쪽을 맞춥니다

```python
act = NO_VERSION.replace(" ", "") in action.replace(" ", "")
```

`NO_VERSION` 은 `"공지에 없음"` 으로 **가운데에 공백이 있습니다.**
한쪽만 공백을 지우면 `"공지에 없음"` 을 `"공지에없음"` 안에서 못 찾아 **정답이 오답이 됩니다.**

> 이 문서를 만들면서 실제로 낸 버그입니다.
> 조치 점수가 모델마다 2점씩 깎여 있었는데, **코드가 멈추지 않아서 한참 몰랐습니다.**
> 채점 코드의 버그는 에러를 내지 않습니다. **조용히 틀린 점수를 줍니다.**

### `지어냄` 은 어떻게 잡나

4번·8번은 `ANSWER_KEY` 의 버전 목록이 **빈 목록**입니다. 공지에 패치 버전이 없기 때문입니다.
이때 `조치:` 줄에 `1.2.3` 같은 **숫자.숫자** 가 보이면 모델이 지어낸 것으로 봅니다.

---

## Step 7. 전체 실행

```python
def ask(client, model_id, advisory_text, max_tokens):
    """공지 하나를 요약시킨다. 결과와 메타데이터를 함께 돌려준다.

    클라우드인지 로컬인지 이 함수는 모릅니다. client 만 다를 뿐입니다.
    """
    started = time.time()
    response = client.chat.completions.create(
        model=model_id,
        messages=build_messages(advisory_text),
        temperature=0,        # 같은 입력에 같은 답 — 비교의 전제
        max_tokens=max_tokens,
    )
    choice = response.choices[0]
    usage = response.usage
    return {
        "answer": choice.message.content or "",
        "finish_reason": choice.finish_reason,
        "in_tokens": usage.prompt_tokens,
        "out_tokens": usage.completion_tokens,
        "seconds": round(time.time() - started, 1),
        "error": None,
    }


results = {}      # {모델이름: {공지번호: 결과}}

for name, (client, model_id, max_tokens) in MODELS.items():
    print(f"===== {name} =====")
    results[name] = {}
    for a in advisories:
        try:
            r = ask(client, model_id, a["advisory"], max_tokens)
        except Exception as e:
            r = {"answer": "", "finish_reason": None, "in_tokens": 0, "out_tokens": 0,
                 "seconds": 0, "error": f"{type(e).__name__}: {e}"}
            print(f"  {a['no']:2}. {a['cve_id']:16} [오류] {r['error'][:60]}")
        else:
            g = grade(a["no"], r["answer"])
            mark = "".join("O" if g[k] else "X" for k in ("형식", "제품", "조치"))
            warn = "  <- 지어냄" if g["지어냄"] else ""
            print(f"  {a['no']:2}. {a['cve_id']:16} {mark}  "
                  f"{r['finish_reason']:6} {r['seconds']:5.1f}초{warn}")
        results[name][a["no"]] = r
    print()

print("완료")
```

### 실행 중 출력 (앞부분)

```
===== gpt-4.1-mini =====
   1. CVE-2021-44228   OOO  stop     1.6초
   2. CVE-2022-22965   OOO  stop     1.1초
   3. CVE-2017-5638    OOO  stop     1.2초
   4. CVE-2014-6271    OOO  stop     2.0초
   5. CVE-2023-49105   OOO  stop     1.2초
   6. CVE-2026-48710   OOO  stop     1.3초
   7. CVE-2026-59822   OOO  stop     1.0초
   8. CVE-2026-75650   OOO  stop     1.0초
   9. CVE-2026-49869   OOO  stop     1.1초
  10. CVE-2026-73570   OOO  stop     1.0초

===== gpt-4.1-nano =====
   1. CVE-2021-44228   OOX  stop     0.7초
   2. CVE-2022-22965   OOO  stop     1.1초
   3. CVE-2017-5638    OOX  stop     0.9초
   4. CVE-2014-6271    OOO  stop     0.6초
   5. CVE-2023-49105   OOX  stop     0.8초
   6. CVE-2026-48710   OOO  stop     0.7초
   7. CVE-2026-59822   OOO  stop     0.6초
   8. CVE-2026-75650   OOO  stop     0.7초
   9. CVE-2026-49869   OOO  stop     0.7초
  10. CVE-2026-73570   OOX  stop     0.7초

...  (아래로 25줄 더)
```

세 글자 `OOO` 는 왼쪽부터 **형식 · 제품 · 조치** 입니다. `X` 가 보이면 그 항목을 틀린 것입니다.

### 여기서 확인할 것

**첫째, `try` / `except` 로 감싼 이유.**
40회 중 한 번이라도 예외가 나면, 감싸지 않은 코드는 거기서 멈추고
**이미 받은 답까지 전부 잃습니다.** 로컬 모델이 꺼져 있거나 클라우드가 429 를 주는 일은 흔합니다.

**둘째, `temperature=0`.**
같은 입력에 같은 답이 나와야 비교가 성립합니다. 이게 빠지면 점수가 아니라 운을 잰 것입니다.
(완전한 보장은 아닙니다 — Step 9-2 에서 직접 봅니다.)

**셋째, 시간.**
클라우드는 공지당 1~2초인데 로컬은 수십 초가 걸리기도 합니다.
**로컬 모델은 돈 대신 시간을 씁니다.** 그래서 `seconds` 를 기록합니다.

> 로컬 모델의 첫 호출은 특히 느립니다. 모델을 메모리에 올리는 시간이 포함되기 때문입니다.
> 두 번째 호출부터 빨라지는 것이 정상입니다.

---

## Step 8. 점수표

```python
def summarize(name):
    rows = results[name]
    s = {"형식": 0, "제품": 0, "조치": 0, "지어냄": 0,
         "잘림": 0, "오류": 0, "입력": 0, "출력": 0, "초": 0.0}
    for a in advisories:
        r = rows[a["no"]]
        if r["error"]:
            s["오류"] += 1
            continue
        g = grade(a["no"], r["answer"])
        for k in ("형식", "제품", "조치", "지어냄"):
            s[k] += int(g[k])
        if r["finish_reason"] == "length":
            s["잘림"] += 1
        s["입력"] += r["in_tokens"]
        s["출력"] += r["out_tokens"]
        s["초"] += r["seconds"]
    return s


scores = {name: summarize(name) for name in MODELS}

n = len(advisories)
header = (f"{'모델':20}{'형식':>6}{'제품':>6}{'조치':>6}{'지어냄':>7}"
          f"{'잘림':>6}{'오류':>6}{'입력토큰':>10}{'출력토큰':>10}{'총초':>7}")
print(header)
print("-" * len(header))
for name, s in scores.items():
    print(f"{name:20}{s['형식']:>4}/{n}{s['제품']:>4}/{n}{s['조치']:>4}/{n}"
          f"{s['지어냄']:>7}{s['잘림']:>6}{s['오류']:>6}"
          f"{s['입력']:>10,}{s['출력']:>10,}{s['초']:>7.1f}")
```

```
모델                      형식    제품    조치    지어냄    잘림    오류      입력토큰      출력토큰     총초
------------------------------------------------------------------------------------
gpt-4.1-mini          10/10  10/10  10/10      0     0     0     4,850       661   12.5
gpt-4.1-nano          10/10  10/10   6/10      0     0     0     4,850       553    7.5
qwen2.5:3b            10/10  10/10   9/10      0     0     0     5,088       903   48.6
llama3.2               9/10  10/10   4/10      1     0     0     5,015       603  103.7
```

### 표 읽는 법

| 열 | 뜻 | 높아야 좋은가 |
|---|---|---|
| 형식 | 네 줄을 **줄 머리부터** 제대로 썼는가 | 높을수록 좋음 |
| 제품 | 제품 이름을 맞혔는가 | 높을수록 좋음 |
| 조치 | 패치 버전을 맞혔는가 | 높을수록 좋음 |
| **지어냄** | 없는 버전을 만들어 냈는가 | **0 이어야 함** |
| 잘림 | `finish_reason == "length"` | 0 이어야 함 |
| 입력·출력 토큰 | 클라우드에서는 비용의 근거 | 낮을수록 쌈 |
| 총 초 | **로컬에서는 이것이 비용** | 낮을수록 좋음 |

### 이 표에서 꼭 읽어야 할 세 가지

**1. 무료 로컬 모델이 유료 클라우드 모델을 이겼습니다.**
`qwen2.5:3b`(조치 9/10) 가 `gpt-4.1-nano`(조치 6/10) 보다 **더 잘 찾았습니다.**
돈을 낸다고 더 잘하는 게 아닙니다. **일마다 맞는 모델이 다릅니다.**

**2. 로컬 모델이라고 다 같지 않습니다.**
같은 3B 급인데 `qwen2.5:3b` 는 9/10, `llama3.2` 는 4/10 입니다.
"로컬 모델 써 봤는데 별로더라" 는 말은 **어느 로컬 모델인지**를 말하지 않으면 의미가 없습니다.

**3. `제품` 열은 네 모델 모두 10/10 — 이 열은 모델을 가르지 못합니다.**
제품 이름은 공지 첫 줄에 대놓고 있으니 당연합니다.
**변별력이 없는 지표는 비교에 쓸모가 없습니다.** 실제로 모델을 가른 것은 `조치` 열입니다.

> 지표를 여러 개 재 보기 전에는 **어느 지표가 쓸모 있는지 모릅니다.**
> 그래서 일단 다 재고, 표를 보면서 고릅니다.

---

## Step 9. 4번과 8번 — 지어냈는가

이 과제의 핵심입니다. 두 공지에는 패치 버전이 **없습니다.** 정답은 `조치: 공지에 없음` 입니다.

```python
for no in (4, 8):
    label = next(a["label"] for a in advisories if a["no"] == no)
    print("=" * 72)
    print(f"{no}번 — {label}  (공지에 패치 버전 없음)")
    print("=" * 72)
    for name in MODELS:
        r = results[name][no]
        if r["error"]:
            print(f"  {name:20} [오류]")
            continue
        action = get_line(r["answer"], "조치:")
        g = grade(no, r["answer"])
        verdict = "지어냄 !!" if g["지어냄"] else ("정답" if g["조치"] else "애매")
        print(f"  {name:20} [{verdict:9}] {action[:70]}")
    print()
```

```
========================================================================
4번 — GNU Bash  (공지에 패치 버전 없음)
========================================================================
  gpt-4.1-mini         [정답       ] 공지에 없음
  gpt-4.1-nano         [정답       ] 공지에 없음
  qwen2.5:3b           [정답       ] 공지에 없음
  llama3.2             [지어냄 !!   ] GNU Bash 4.4 이상

========================================================================
8번 — Adobe Commerce  (공지에 패치 버전 없음)
========================================================================
  gpt-4.1-mini         [정답       ] 공지에 없음
  gpt-4.1-nano         [정답       ] 공지에 없음
  qwen2.5:3b           [정답       ] 공지에 없음
  llama3.2             [정답       ] 공지에 없음
```

답변 전문도 하나 펼쳐 봅니다.

```python
# 답변 전문을 하나만 펼쳐 봅니다
sample_model = list(MODELS)[0]
print(f"--- {sample_model} / 8번 Adobe Commerce 전문 ---")
print(results[sample_model][8]["answer"])
```

```
--- gpt-4.1-mini / 8번 Adobe Commerce 전문 ---
제품: Adobe Commerce (영향받는 버전 공지에 없음)  
영향: 공격자가 임의의 코드를 실행할 수 있음  
조치: 공지에 없음  
긴급도: 높음
```

### 여기서 확인할 것

`llama3.2` 만 4번에서 `조치: GNU Bash 4.4 이상` 이라고 답했습니다.
**공지에는 `4.4` 라는 말이 없습니다.**

지어낸 패치 버전은 **틀린 답보다 나쁩니다.**
"모르겠다" 는 답은 담당자가 다음 행동을 정할 수 있지만,
**그럴듯한 가짜 버전은 걸러낼 방법이 없습니다.** 그대로 믿고 조치하게 됩니다.

> 점수가 아무리 높아도 **지어냄이 0 이 아닌 모델은 보안 업무에 쓸 수 없습니다.**
> 이 열은 다른 열과 성격이 다릅니다. **더하는 점수가 아니라 거르는 조건**입니다.

---

## Step 9-2. 그 한 줄이 정말 필요한가 — 빼고 재 보기

`system` 에서 **"버전이 없으면 '공지에 없음'이라고 쓰세요"** 한 줄을 빼면 어떻게 될까요?

**짐작하지 말고 직접 잽니다.** 그리고 **한 번만 재고 결론 내지 않습니다** — 세 번씩 돌립니다.

```python
SYSTEM_NO_GUARD = """당신은 보안 공지를 요약하는 분석가입니다.

아래 형식으로 **정확히 네 줄**만 답하세요. 다른 말을 덧붙이지 마세요.

제품: <제품 이름과 영향받는 버전>
영향: <공격자가 무엇을 할 수 있는지 한 문장>
조치: <올려야 할 버전>
긴급도: <긴급|높음|보통|낮음 중 하나>

한국어로 답하세요."""


def ask_with_system(system_prompt, advisory_text, max_tokens=300):
    """system 만 바꿔서 같은 공지를 다시 물어본다."""
    messages = build_messages(advisory_text)
    messages[0] = {"role": "system", "content": system_prompt}   # system 만 교체
    r = openai_client.chat.completions.create(
        model="gpt-4.1-mini", temperature=0, max_tokens=max_tokens, messages=messages)
    return r.choices[0].message.content or ""


# 한 번만 돌려 보고 결론 내지 않습니다. temperature=0 이어도 말이 조금씩 달라집니다.
for no in (4, 8):
    a = next(x for x in advisories if x["no"] == no)
    print("=" * 72)
    print(f"{no}번 — {a['label']}  (공지에 패치 버전 없음)")
    for tag, sp in [("지시 있음", SYSTEM_PROMPT), ("지시 없음", SYSTEM_NO_GUARD)]:
        for trial in range(3):
            action = get_line(ask_with_system(sp, a["advisory"]), "조치:")
            made_up = bool(re.search(r"\d+\.\d+", action))
            flag = "지어냄 !!" if made_up else "안 지어냄 "
            print(f"  [{tag}] {trial + 1}회  {flag}  조치: {action[:60]}")
    print()
```

```
========================================================================
4번 — GNU Bash  (공지에 패치 버전 없음)
  [지시 있음] 1회  안 지어냄   조치: 공지에 없음
  [지시 있음] 2회  안 지어냄   조치: 공지에 없음
  [지시 있음] 3회  안 지어냄   조치: 공지에 없음
  [지시 없음] 1회  안 지어냄   조치: 최신 버전으로 업데이트 필요
  [지시 없음] 2회  지어냄 !!  조치: GNU Bash 4.3 이상 버전으로 업데이트
  [지시 없음] 3회  지어냄 !!  조치: 4.3 이후 버전으로 업데이트

========================================================================
8번 — Adobe Commerce  (공지에 패치 버전 없음)
  [지시 있음] 1회  안 지어냄   조치: 공지에 없음
  [지시 있음] 2회  안 지어냄   조치: 공지에 없음
  [지시 있음] 3회  안 지어냄   조치: 공지에 없음
  [지시 없음] 1회  안 지어냄   조치: 최신 보안 패치 적용 권고
  [지시 없음] 2회  안 지어냄   조치: 최신 보안 패치 적용 권고
  [지시 없음] 3회  안 지어냄   조치: 최신 보안 패치 적용 권고
```

### 결과 — 공지에 따라 실패하는 방식이 다릅니다

| | 4번 GNU Bash | 8번 Adobe Commerce |
|---|---|---|
| 지시 있음 (3회) | `공지에 없음` ×3 | `공지에 없음` ×3 |
| 지시 없음 (3회) | **`4.3 이후 버전으로 업데이트` ×3** | `최신 버전으로 업데이트 권장` ×3 |

#### 4번이 왜 위험한가

4번 공지 원문은 이렇게 시작합니다.

> GNU Bash **through 4.3** processes trailing strings after function definitions ...

`through 4.3` 은 **4.3 까지가 취약하다**는 뜻입니다. 고쳐진 버전이 아닙니다.
그런데 지시를 빼자 모델은 본문에서 **가장 가까운 숫자**를 집어
`조치: 4.3 이후 버전으로 업데이트` 라고 썼습니다.

이건 "쓸모없는 답" 이 아니라 **틀린 조치 지시**입니다.
담당자가 그대로 따르면 **취약한 버전으로 올리게 됩니다.**

#### 8번은 왜 다른가

8번 공지에는 버전 숫자가 **아예 하나도 없습니다.**
집을 숫자가 없으니 모델은 지어내는 대신 "최신 버전으로 업데이트 권장" 이라고 뭉갰습니다.
틀린 말은 아니지만 **담당자가 이 문장을 받아서 할 수 있는 일이 없습니다.**

#### 정리

| 본문 상황 | 지시 있음 | 지시 없음 |
|---|---|---|
| 숫자가 **있으면** (4번) | `공지에 없음` | **그 숫자를 집어 지어냄 — 위험** |
| 숫자가 **없으면** (8번) | `공지에 없음` | 뭉갬 — 쓸모없음 |
| 기계로 채점되나 | **예** | 아니오 |

> **배울 것 하나** — 모를 때 쓸 말을 정해 주면 모델이 **"모른다"를 정확히 말할 수 있습니다.**
> 그러지 않으면 모델은 빈칸을 **주변 숫자**나 **뭉뚱그린 문장**으로 메웁니다.
>
> **배울 것 둘** — **실패하는 방식은 입력에 따라 달라집니다.**
> 4번만 봤다면 "지어낸다", 8번만 봤다면 "안 지어낸다" — 둘 다 반쪽짜리 결론입니다.
> 그래서 **두 건을 다, 각각 세 번씩** 쟀습니다.

---

## Step 10. 결과 저장

```python
def save_markdown(filepath="exercise_result.md"):
    """점수표와 답변 전문을 markdown 으로 저장한다.

    results 는 Step 7, scores 는 Step 8 에서 만들어집니다.
    """
    for need, step in [("results", "Step 7 (전체 실행)"), ("scores", "Step 8 (점수표)")]:
        if need not in globals():
            raise RuntimeError(f"{need} 가 없습니다. {step} 셀을 먼저 실행하세요.")

    lines = [
        "# 보안 공지 요약 — 모델 비교 결과",
        "",
        f"_실행: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_",
        f"_공지 {len(advisories)}건 × 모델 {len(MODELS)}개 = {len(advisories) * len(MODELS)}회 호출_",
        "",
        "## 점수표",
        "",
        "| 모델 | 형식 | 제품 | 조치 | 지어냄 | 잘림 | 오류 | 입력토큰 | 출력토큰 | 총 초 |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    n = len(advisories)
    for name, s in scores.items():
        lines.append(
            f"| {name} | {s['형식']}/{n} | {s['제품']}/{n} | {s['조치']}/{n} | "
            f"**{s['지어냄']}** | {s['잘림']} | {s['오류']} | "
            f"{s['입력']:,} | {s['출력']:,} | {s['초']:.1f} |")

    lines += ["", "## 버전이 공지에 없는 두 건", ""]
    for no in (4, 8):
        label = next(a["label"] for a in advisories if a["no"] == no)
        lines += [f"### {no}번 — {label}", ""]
        for name in MODELS:
            r = results[name][no]
            action = "[오류]" if r["error"] else get_line(r["answer"], "조치:")
            lines.append(f"- **{name}**: {action}")
        lines.append("")

    lines += ["## 모델별 전체 답변", ""]
    for name in MODELS:
        lines += [f"### {name}", ""]
        for a in advisories:
            r = results[name][a["no"]]
            lines += [f"**{a['no']}. {a['cve_id']} ({a['label']})**", ""]
            lines += ["```", r["error"] or r["answer"], "```", ""]

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"저장: {filepath}  ({len(chr(10).join(lines)):,}자)")
    return filepath


save_markdown()
```

```
저장: exercise_result.md  (7,796자)
'exercise_result.md'
```

### 여기서 확인할 것

- **실행 시각을 반드시 적습니다.** 모델은 계속 바뀝니다. 시각 없는 점수표는 나중에 쓸모가 없습니다
- `encoding="utf-8"` 을 빼면 윈도우에서 한글이 깨집니다 (`1_4_llms`)
- **답변 전문을 다 저장합니다.** 점수만 남기면 나중에 "왜 틀렸지?" 를 확인할 수 없습니다

### `NameError: name 'scores' is not defined` 가 나온다면

함수 맨 앞의 네 줄이 이것을 막기 위한 것입니다.

```python
for need, step in [("results", "Step 7 (전체 실행)"), ("scores", "Step 8 (점수표)")]:
    if need not in globals():
        raise RuntimeError(f"{need} 가 없습니다. {step} 셀을 먼저 실행하세요.")
```

`results` 는 Step 7, `scores` 는 Step 8 에서 만들어집니다.
**커널을 재시작하면 둘 다 사라집니다** — 변수는 파일이 아니라 메모리에 있기 때문입니다.
노트북 파일에 **출력이 남아 있어도 변수는 없습니다.** 이 둘을 헷갈리기 쉽습니다.

> 노트북에서 가장 흔한 오류가 **셀 실행 순서**입니다.
> `NameError` 를 만나면 코드를 고치기 전에 **그 변수를 만드는 셀이 돌았는지** 먼저 보세요.
>
> 가드가 없으면 `NameError: name 'scores' is not defined` 만 나옵니다.
> 어느 셀을 실행해야 하는지는 알려 주지 않습니다. **에러 메시지는 다음 행동을 알려 줘야 합니다.**

---

## Step 11. 결론

```python
n = len(advisories)
print("정리\n")

# 호출이 전부 실패한 모델은 후보에서 뺍니다.
# 답이 하나도 없으면 '지어냄 0' 이 저절로 참이 되어 버리기 때문입니다.
answered = [name for name, s in scores.items() if s["오류"] < n]
clean = [name for name in answered if scores[name]["지어냄"] == 0]
print("답을 받은 모델    :", ", ".join(answered) or "없음 !!")
print("지어내지 않은 모델:", ", ".join(clean) or "없음 !!")

# 정확도 = 제품 + 조치
ranked = sorted(answered, key=lambda m: -(scores[m]["제품"] + scores[m]["조치"]))
print(f"\n정확도 순 (제품 + 조치, 만점 {n * 2}):")
for m in ranked:
    s = scores[m]
    print(f"  {m:16} {s['제품'] + s['조치']:2}/{n * 2}  "
          f"(제품 {s['제품']}/{n}, 조치 {s['조치']}/{n})  "
          f"토큰 {s['입력'] + s['출력']:>6,}  {s['초']:5.0f}초")

print("\n'지어냄 0' 만 보고 고르지 마세요.")
print("모든 공지에 \"공지에 없음\" 이라고만 답해도 지어냄은 0 입니다.")
print("조치 점수를 반드시 같이 보세요.")
```

```
정리

답을 받은 모델    : gpt-4.1-mini, gpt-4.1-nano, qwen2.5:3b, llama3.2
지어내지 않은 모델: gpt-4.1-mini, gpt-4.1-nano, qwen2.5:3b

정확도 순 (제품 + 조치, 만점 20):
  gpt-4.1-mini     20/20  (제품 10/10, 조치 10/10)  토큰  5,511     12초
  qwen2.5:3b       19/20  (제품 10/10, 조치 9/10)  토큰  5,991     49초
  gpt-4.1-nano     16/20  (제품 10/10, 조치 6/10)  토큰  5,403      8초
  llama3.2         14/20  (제품 10/10, 조치 4/10)  토큰  5,618    104초

'지어냄 0' 만 보고 고르지 마세요.
모든 공지에 "공지에 없음" 이라고만 답해도 지어냄은 0 입니다.
조치 점수를 반드시 같이 보세요.
```

### 숫자를 보고 고르기

**조건이 없다면 `gpt-4.1-mini`** 입니다. 조치 10/10, 지어냄 0. 흠잡을 데가 없습니다.

**공지를 외부로 보낼 수 없는 조직이라면 `qwen2.5:3b`** 입니다.
조치 9/10 으로 한 건 뒤질 뿐인데 **돈이 0원이고 데이터가 밖으로 나가지 않습니다.**
대신 **시간을 몇 배 더 씁니다.** 이 과제에서 치른 값은 그게 전부입니다.

### 재현되는 숫자와 흔들리는 숫자

이 노트북을 세 번 돌려 봤습니다.

| | 세 번 모두 | |
|---|---|---|
| **점수** | 10/10 · 6/10 · 9/10 · 4/10 로 **똑같았습니다** | `temperature=0` 덕분입니다 |
| **총 초** | 로컬 모델이 30초 ~ 100초로 **크게 달랐습니다** | 모델 적재 시간, GPU 사정에 따라 흔들립니다 |

> **흔들리는 숫자로 결론을 쓰면 다음 사람이 돌렸을 때 틀린 글이 됩니다.**
> 시간을 근거로 쓰려면 **여러 번 재서 범위로** 적으세요.
> 한 번 재고 "이 모델은 33초" 라고 쓰는 것이 가장 흔한 실수입니다.

`gpt-4.1-nano` 는 **돈을 내면서 무료 로컬 모델보다 못했습니다**(조치 6/10 vs 9/10).
빠른 건 맞지만, **틀린 답을 빨리 받는 것은 장점이 아닙니다.**

### `qwen2.5:3b` 가 놓친 한 건을 열어 보세요

10번 Zimbra 입니다. 답은 이랬습니다.

```
제품: Zimbra Collaboration (ZCS) before 10.1.20     <- 버전을 찾긴 찾았습니다
조치: 공지에 없음                                    <- 그런데 여기로 옮기지 못했습니다
```

**버전을 못 읽은 게 아니라 엉뚱한 줄에 넣었습니다.**
작은 모델이 자주 보이는 실패 방식입니다.

> 이런 오답을 보면 **"모델을 바꾼다" 전에 "프롬프트를 고친다"** 를 먼저 시도할 수 있습니다.
> 틀린 답을 **열어 보지 않으면** 이런 판단을 할 수 없습니다.
> 점수표만 보면 그냥 "9/10 짜리 모델" 로만 보입니다.

---

## 자주 만나는 오류

| 증상 | 원인 | 해결 |
|---|---|---|
| `APIConnectionError` (로컬만) | Ollama 가 안 떠 있음 | 터미널에서 `ollama list` 확인 |
| `model "qwen2.5:3b" not found` | 모델을 안 받음 | `ollama pull qwen2.5:3b` |
| `FileNotFoundError: advisories_sample.json` | 노트북과 다른 폴더 | 같은 폴더에 두거나 경로를 적기 |
| 로컬 모델이 너무 느림 | GPU 없이 CPU 로 도는 중 | 정상입니다. `seconds` 가 그 비용입니다 |
| 결과 파일 한글이 깨짐 | `encoding="utf-8"` 누락 | `open(..., encoding="utf-8")` |
| `잘림` 이 특정 모델만 많음 | `max_tokens` 부족 | 그 모델의 값만 올려 다시 실행 |
| 점수가 이상한데 에러는 없음 | **채점 코드 버그** | Step 6 을 다시 보세요 |
| `NameError: 'scores'` / `'results'` | **셀 실행 순서** | Step 7 · Step 8 을 먼저 실행 (Step 10 참고) |
| `NameError: 'advisories'` / `'MODELS'` | 커널 재시작 후 이어서 실행 | 처음부터 전체 실행 |

---

## 혼자 더 해 볼 것

1. `temperature` 를 `1` 로 바꿔 같은 공지를 세 번 돌려 보세요. 답이 흔들리나요?
2. 로컬 모델이 틀린 건을 골라 **공지를 짧게 줄여서** 다시 넣어 보세요.
   점수가 오른다면 문제는 모델이 아니라 **입력 길이**였던 것입니다 (`1_7_2_context_ollama`).
3. 더 큰 로컬 모델(`ollama pull qwen2.5:7b`)을 **딕셔너리에 한 줄** 추가해 보세요.
   점수는 얼마나 오르고, 시간은 몇 배가 되나요?
4. 10번 Zimbra 를 `qwen2.5:3b` 가 맞히도록 **프롬프트만** 고쳐 보세요. 가능한가요?

---

## 정리

| | |
|---|---|
| 형식을 좁히면 채점할 수 있다 | 자유 서술은 비교가 불가능합니다 |
| 클라우드와 로컬을 같은 코드로 | `base_url` 만 다릅니다 (Step 4) |
| **검사와 파싱은 같은 기준으로** | 다르면 점수가 거짓말을 합니다 (Step 6) |
| 모를 때 쓸 말을 미리 준다 | 안 주면 **주변 숫자를 집어 옵니다** (Step 9-2) |
| `지어냄 0` 만 보고 고르지 않는다 | 전부 "없음" 이라고 해도 0 입니다 |
| **비싸다고 잘하는 게 아니다** | 무료 `qwen2.5:3b` 가 유료 `gpt-4.1-nano` 를 이겼습니다 |
| **"로컬 모델"은 하나가 아니다** | 9/10 과 4/10 입니다 |
| 틀린 답은 열어 본다 | 점수표만 보면 고칠 방법을 못 찾습니다 |

## 다음 단계

이 과제에서 모델은 **공지 본문을 우리가 넣어 줘야만** 답할 수 있었습니다.
공지가 1만 건이라면 전부 넣을 수 없습니다.

**필요한 것만 찾아서 넣어 주는 방법** — 그것이 다음 과정 **RAG** 입니다.
