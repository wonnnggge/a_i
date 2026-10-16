# 따라 하기: 한글 소설로 배우는 청킹과 검색

이 문서를 처음부터 끝까지 따라 하면 `chunk_basic_ko2.ipynb`와 같은 노트북을 직접 만들 수 있습니다.
완성하면 **소설 한 편을 검색하고, 두 가지 청킹 방식을 나란히 비교하는 화면**이 됩니다.

문서는 현진건의 단편소설 **「운수 좋은 날」(1924)** 원문을 씁니다.
저작권이 만료됐고 교과서에도 실린 작품이라, **여러분이 이미 아는 이야기**입니다.
그래서 *"아내는 어떻게 되었나?"* 라고 물었을 때 돌아온 대목이 맞는지 **읽어 보면 바로 판단할 수 있습니다.**

## 무엇을 배우나

| 단계 | 배우는 것 |
|---|---|
| 청킹 | 자르는 방법 세 가지와, 글의 종류가 방법을 고른다는 것 |
| 한글과 토큰 | 한글이 영어보다 토큰을 훨씬 많이 쓴다는 것 |
| 임베딩·검색 | 벡터로 바꿔 "의미가 가까운 것"을 찾는 방법 |
| **점수 읽기** | 점수가 높다고 정답이 아니라는 것 |
| 벡터 DB | numpy 행렬 대신 Chroma에 저장하기 |
| Gradio | 두 방식을 나란히 비교하는 화면 만들기 |

## 전체 흐름

```
소설 내려받기 → ① 청킹(3가지) → ② 임베딩 → ③ 검색 → ④ 벡터 DB 저장 → ⑤ 비교 화면
```

> **이 문서에서 가장 중요한 두 곳**
>
> - **6번** — 점수가 더 높은데 틀린 사례
> - **7번** — `chunk_size`를 바꿨는데 결과가 안 바뀌는 사례
>
> 둘 다 "왜 그런지"까지 설명합니다. 코드만 따라 치고 넘어가지 마세요.

---

## 사전 준비

### 1. 패키지 설치

```bash
pip install openai chromadb tiktoken numpy requests python-dotenv gradio
```

### 2. API 키 준비

프로젝트 폴더(`llm_edu/`)에 `.env` 파일을 만들고 OpenAI API 키를 넣습니다.

```
OPENAI_API_KEY=sk-proj-...
```

### 3. 새 노트북 만들기

`rag/` 폴더에 새 주피터 노트북을 만듭니다.
이제부터 나오는 코드를 **셀 하나씩** 입력하고 실행하세요.

> **비용 안내**: 소설 전체가 약 11,000토큰입니다.
> 청크 크기를 바꿔 가며 여러 번 실험해도 **1센트(약 15원) 미만**입니다.

---

## Step 0. 준비

첫 셀에 필요한 도구를 불러옵니다.

```python
import re

import numpy as np
import requests
import tiktoken
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)
ai = OpenAI()

ENC = tiktoken.get_encoding("cl100k_base")
ntok = lambda t: len(ENC.encode(t))
```

`ntok`은 "이 글이 몇 토큰인가"를 세는 짧은 함수입니다. 앞으로 계속 씁니다.

---

## Step 1. 소설 내려받기

데이터 준비는 이 셀이 전부입니다. 데이터셋 라이브러리도, 스키마도 없습니다.

**위키문헌(Wikisource)** 은 저작권이 만료된 원문을 모아 둔 위키미디어 프로젝트입니다.
위키백과와 **API 주소 형식이 같아서** 도메인만 `ko.wikisource.org`로 바꾸면 됩니다.

```python
TITLE = "운수 좋은 날"

resp = requests.get(
    "https://ko.wikisource.org/w/api.php",   # 위키백과가 아니라 위키문헌(원문 저장소)
    params={
        "action": "query",
        "format": "json",
        "prop": "extracts",
        "explaintext": 1,     # 위키 문법을 제거한 순수 텍스트로 받기
        "redirects": 1,
        "titles": TITLE,
    },
    headers={"User-Agent": "llm-edu-notebook/1.0"},
    timeout=30,
)

pages = resp.json()["query"]["pages"]
doc = next(iter(pages.values()))["extract"].strip()

# 내려받은 원문 끝에는 위키문헌이 붙인 '== 라이선스 ==' 절이 딸려 온다.
# 작품 내용이 아니므로 잘라낸다. (실무에서도 머리말·꼬리말 제거는 늘 필요한 단계)
doc = re.split(r"^== 라이선스 ==$", doc, flags=re.M)[0].strip()

print(f"{len(doc):,}자   {ntok(doc):,}토큰")
print(f"절(==) {len(re.findall(r'^== .+ ==$', doc, re.M))}개")
print(f"줄 {len(doc.splitlines())}개 / 빈 줄로 나눈 덩어리 {len(re.split(r'\n\s*\n', doc))}개")
print()
print(doc[:400])
```

**실행 결과**

```
10,284자   10,998토큰
절(==) 0개
줄 90개 / 빈 줄로 나눈 덩어리 4개

🙝🙟
새침하게 흐린 품이 눈이 올 듯하더니 눈은 아니 오고 얼다가 만 비가 추적추적 내리었다.
이날이야말로 동소문 안에서 인력거꾼 노릇을 하는 김 첨지에게는 오래간만에도 닥친 운수 좋은 날이었다...
```

### 출력에서 꼭 볼 것 세 가지

| 숫자 | 의미 | 왜 중요한가 |
|---|---|---|
| **절(==) 0개** | 소설에는 절 제목이 없다 | Step 3의 `chunk_sections`가 무용지물이 됩니다 |
| **줄 90개** | 줄 바꿈은 많다 | 문단 청킹은 잘 동작합니다 |
| **빈 줄 덩어리 4개** | 빈 줄은 거의 없다 | `\n\s*\n`로 나누면 **청크가 4개밖에 안 나옵니다** |

마지막 줄이 함정입니다. 위키백과 문서는 문단 사이가 **빈 줄**이지만,
위키문헌 소설 원문은 **한 줄 바꿈**입니다. Step 3에서 이 차이를 반영합니다.

### 알아 둘 것

> `action=raw` 방식(`index.php?title=...&action=raw`)도 있지만, 그쪽은 JSON이 아니라
> 위키 문법 원문을 돌려줍니다. `resp.json()`을 호출하면 `JSONDecodeError`가 납니다.
> **`api.php`의 `extracts`** 를 쓰는 편이 간단합니다.

---

## Step 2. 한글은 토큰을 얼마나 쓸까

다음 셀로 넘어가기 전에 Step 1의 숫자를 다시 보세요. **10,284자인데 10,998토큰**입니다.

| | 글자 수 | 토큰 수 | 글자당 토큰 |
|---|---|---|---|
| 영어 (이상한 나라의 앨리스) | 144,599자 | 36,926토큰 | 약 0.26 |
| **한글 (운수 좋은 날)** | 약 10,300자 | 약 11,000토큰 | **약 1.07** |

**한글은 글자 수보다 토큰 수가 오히려 많습니다.**
`cl100k_base` 토크나이저가 영어 위주로 만들어져서, 한글은 글자 하나가 토큰 1개 이상을 쓰는 일이 많습니다.
영어는 글자 4개가 토큰 1개쯤 되니, 같은 글자 수라면 **한글이 토큰을 약 4배** 씁니다.

실무에서 중요한 점은 두 가지입니다.

1. 영어 예제에서 본 `chunk_size` 숫자를 한글에 그대로 쓰면 **글자 기준으로는 훨씬 짧은 내용**이 담깁니다.
2. 같은 분량의 문서라도 한글은 **비용과 컨텍스트를 더 많이 씁니다.**

> 토큰에 대한 자세한 내용은 `../llm_intro/1_5_tokenizer.ipynb`를 참고하세요.

---

## Step 3. 왜 잘라야 할까 — 직접 거절당해 보기

이유는 두 가지이고, 둘 다 구체적입니다.

1. **임베딩 모델에 입력 한계가 있습니다** — `text-embedding-3-small`은 8,192토큰까지만 받습니다.
   이 소설은 약 11,000토큰이라 **단편소설 한 편도 한 번에 넣을 수 없습니다.**
2. **들어간다고 해도 작품 전체를 벡터 하나로 만들면 쓸모가 없습니다.**
   임베딩은 텍스트 전체의 평균 같은 것입니다. 소설 전체를 벡터 하나로 만들면
   "가난한 인력거꾼 이야기"가 되어 버려서, 어떤 장면을 물어도 비슷하게 가깝고
   **어떤 장면도 콕 집어내지 못합니다.**

말로 읽는 것보다 직접 거절당해 보는 편이 낫습니다.

```python
# 문서 전체를 임베딩하면 어떻게 될까? 직접 시도해서 거절당하는 것을 확인합니다.
try:
    ai.embeddings.create(model="text-embedding-3-small", input=[doc])
except Exception as e:
    print(type(e).__name__)
    print(str(e)[:200])
```

**실행 결과**

```
BadRequestError
Error code: 400 - {'error': {'message': "Invalid 'input[0]': maximum input length is 8192 tokens.", ...}}
```

청킹은 문서를 **각 벡터가 한 장면만 담을 만큼** 작게 나누는 작업입니다.

---

## Step 4. 자르는 방법 세 가지

아래 함수들은 모두 **텍스트를 받아 문자열 리스트를 돌려줄 뿐**입니다.
청커(chunker)란 그게 전부입니다.

| 방법 | 자르는 기준 | 특징 |
|---|---|---|
| `chunk_fixed` | 토큰 개수 | 일정한 크기. 문장 중간에서 잘림 |
| `chunk_paragraphs` | 줄 바꿈(문단) | 문장을 자르지 않음. 크기가 들쭉날쭉 |
| `chunk_sections` | `== 절 제목 ==` | **이 소설에는 절 제목이 없어서 무용지물** |

```python
def chunk_fixed(text, size=200, overlap=0):
    """`size` 토큰마다 무조건 자른다. 문장이 어디서 끝나는지는 신경 쓰지 않는다."""
    ids = ENC.encode(text)
    step = size - overlap
    out = []
    for i in range(0, len(ids), step):
        piece = ids[i : i + size]
        if not piece:
            break
        out.append(ENC.decode(piece))
        if i + size >= len(ids):
            break
    return out


def chunk_paragraphs(text, target=200):
    """문단을 통째로 모아서 대략 `target` 토큰이 될 때까지 합친다."""
    # \n+ : 빈 줄이든 한 줄 바꿈이든 문단으로 인정
    paras = [p.strip() for p in re.split(r"\n+", text) if p.strip()]
    out, buf, n = [], [], 0
    for p in paras:
        t = ntok(p)
        if buf and n + t > target:
            out.append("\n\n".join(buf))
            buf, n = [], 0
        buf.append(p)
        n += t
    if buf:
        out.append("\n\n".join(buf))
    return out


def chunk_sections(text):
    """'== 제목 ==' 절 단위로 자른다. 자연스럽지만 검색에 쓰기에는 너무 크다."""
    parts = re.split(r"(?=^== .+ ==$)", text, flags=re.M)
    return [p.strip() for p in parts if p.strip()]
```

### 여기서 꼭 볼 것 — `\n+` 입니다

`chunk_paragraphs`가 `\n\s*\n`(빈 줄)이 아니라 **`\n+`(한 번 이상의 줄 바꿈)** 으로 나눕니다.

Step 1에서 "빈 줄로 나눈 덩어리 4개"를 확인했습니다.
빈 줄만 찾으면 **청크가 4개밖에 안 나와서 청킹이 사실상 동작하지 않습니다.**

> **글의 종류가 구분자를 고릅니다.** 위키백과 문서는 빈 줄로, 소설 원문은 한 줄 바꿈으로 문단이 나뉩니다.
> 남의 코드를 가져올 때 이 부분을 그대로 쓰면 조용히 망가집니다.

### 네 가지를 비교해 보기

```python
for name, chunks in [
    ("fixed-200",       chunk_fixed(doc, 200)),
    ("fixed-200/ov50",  chunk_fixed(doc, 200, 50)),
    ("paragraphs-200",  chunk_paragraphs(doc, 200)),
    ("sections",        chunk_sections(doc)),
]:
    sizes = [ntok(c) for c in chunks]
    print(f"{name:18s} {len(chunks):>4}개 청크   "
          f"중앙값 {int(np.median(sizes)):>4}토큰   최대 {max(sizes):>5}토큰")
```

**실행 결과**

```
fixed-200            55개 청크   중앙값  200토큰   최대   200토큰
fixed-200/ov50       73개 청크   중앙값  200토큰   최대   200토큰
paragraphs-200       57개 청크   중앙값  190토큰   최대   345토큰
sections              1개 청크   중앙값 10998토큰   최대 10998토큰
```

**`sections`가 1개입니다.** 절 제목이 없으니 작품 전체가 청크 하나가 됐습니다.
`chunk_sections`는 위키백과 문서(`chunk_basic_ko1.ipynb`)에서는 14개 절로 잘 나뉘지만,
소설에서는 쓸 수 없습니다. **문서 구조에 맞는 청커를 골라야 합니다.**

---

## Step 5. 잘린 자리를 들여다보기

여기가 가장 눈여겨볼 부분입니다.
고정 크기 청킹은 토큰 수만 세다가 자르기 때문에, **문장 중간이나 심하면 글자 중간**에서 끊깁니다.

```python
fixed = chunk_fixed(doc, 200)

print("=" * 72)
print("청크 5의 끝부분:")
print("=" * 72)
print("..." + fixed[5][-200:])
print()
print("=" * 72)
print("청크 6의 시작부분  <- 위 문장이 여기서 이어진다")
print("=" * 72)
print(fixed[6][:200] + "...")
```

**실행 결과** (일부)

```
청크 5의 끝부분:
...“에이, 오라질 년, 조롱복은 할 수가 없어, 못 먹어 병, 먹어서 병, 어쩌란 말이야!
왜 눈을 바루 뜨지 못해!”하고 김 첨지는 앓는 이의 뺨을 한 번 후려갈겼다. 홉
                                                                    ↑ 여기서 끊김
```

문단 청킹과 비교해 보세요.

```python
# 문단 청킹은 줄 바꿈에서만 자르기 때문에 문장이 잘리지 않는다.
paras = chunk_paragraphs(doc, 200)

print("=" * 72)
print("문단 청크 5의 끝부분:")
print("=" * 72)
print("..." + paras[5][-200:])
print()
print("=" * 72)
print("문단 청크 6의 시작부분  <- 깔끔하게 나뉜다")
print("=" * 72)
print(paras[6][:200] + "...")
```

**실행 결과**

```
문단 청크 5의 끝부분:
...홉뜬 눈은 조금 바루어졌건만 이슬이 맺히었다. 김 첨지의 눈시울도 뜨끈뜨끈하였다.
                                                                    ↑ 문장이 끝남
```

### 겹침(overlap)은 무엇을 해 주나

겹침은 앞 청크의 끝부분을 다음 청크의 앞에 다시 넣습니다.
그래서 반으로 잘린 문장도 **어딘가에는 온전한 형태로 존재하게** 됩니다.
대가는 중복입니다. 청크가 늘어나고, 벡터가 늘어나고, 비용이 늘어납니다.

```python
plain = chunk_fixed(doc, 200, 0)
over = chunk_fixed(doc, 200, 50)
print(f"겹침 없음 : {len(plain)}개 청크")
print(f"겹침 50   : {len(over)}개 청크  (저장·임베딩 비용 +{100 * (len(over) / len(plain) - 1):.0f}%)")
print()
print("청크 3의 마지막 50토큰이 청크 4의 앞부분에 다시 나타난다:")
print("---")
print(ENC.decode(ENC.encode(over[3])[-50:]))
print("---")
print(ENC.decode(ENC.encode(over[4])[:50]))
```

**실행 결과**

```
겹침 없음 : 55개 청크
겹침 50   : 73개 청크  (저장·임베딩 비용 +33%)

청크 3의 마지막 50토큰이 청크 4의 앞부분에 다시 나타난다:
---
 물론 약 한 첩 써 본 일이 없다. 구태여 쓰려면 못 쓸 바도 아니로되 그는 병이란 놈
---
 물론 약 한 첩 써 본 일이 없다. 구태여 쓰려면 못 쓸 바도 아니로되 그는 병이란 놈
```

**겹침 50토큰에 비용이 33% 늘었습니다.** 공짜가 아닙니다.

---

## Step 6. 임베딩하고 검색하기

벡터 데이터베이스를 쓰지 않습니다.
청크가 수십 개뿐일 때는 **작은 행렬 하나와 내적(dot product) 한 번**이면 검색이 끝납니다.
이 규모에서 DB는 오히려 군더더기입니다. (Step 10에서 DB로 옮깁니다.)

```python
def embed(texts, batch=256):
    out = []
    for i in range(0, len(texts), batch):
        r = ai.embeddings.create(model="text-embedding-3-small",
                                 input=texts[i : i + batch])
        out.extend(d.embedding for d in r.data)
    V = np.asarray(out, dtype=np.float32)
    V /= np.linalg.norm(V, axis=1, keepdims=True)   # 단위 벡터 -> 내적 == 코사인 유사도
    return V


INDEX = {}


def build(name, chunks):
    """한 번 임베딩한 결과를 기억해 둔다. (같은 이름은 다시 계산하지 않음)"""
    if name not in INDEX:
        print(f"임베딩 중: {name} ({len(chunks)}개 청크, 약 ${sum(map(ntok, chunks))/1e6*0.02:.4f})")
        INDEX[name] = (chunks, embed(chunks))
    return INDEX[name]


def search(query, name, k=3):
    chunks, V = INDEX[name]
    q = embed([query])[0]
    sims = V @ q
    top = np.argsort(-sims)[:k]
    return [(float(sims[i]), chunks[i]) for i in top]
```

### 코드에서 짚고 갈 두 줄

**`V /= np.linalg.norm(V, axis=1, keepdims=True)`**
모든 벡터의 길이를 1로 맞춥니다. 길이가 1이면 **내적이 곧 코사인 유사도**가 됩니다.
덕분에 `V @ q` 한 줄로 전체 청크와의 유사도를 한 번에 구할 수 있습니다.

**`top = np.argsort(-sims)[:k]`**
`argsort`는 값이 아니라 **번호(인덱스)** 를 돌려줍니다. `chunks[i]`로 본문을 꺼내야 하니까요.
`np.argsort`는 오름차순만 지원하므로 `-sims`로 부호를 뒤집어 큰 것부터 만듭니다.

> 이 한 줄의 자세한 설명은 `chunk_basic_ko1.ipynb`의 5장에 있습니다.

### 인덱스 두 개 만들기

```python
build("fixed-200", chunk_fixed(doc, 200))
build("paragraphs-200", chunk_paragraphs(doc, 200))
print("\n준비된 인덱스:", list(INDEX))
```

**실행 결과**

```
임베딩 중: fixed-200 (55개 청크, 약 $0.0002)
임베딩 중: paragraphs-200 (57개 청크, 약 $0.0002)

준비된 인덱스: ['fixed-200', 'paragraphs-200']
```

---

## Step 7. 질문해 보기 — 점수가 높다고 정답이 아닙니다

점수는 참고만 하고, **돌아온 대목을 직접 읽어서** 쓸만한지 판단해 보세요.

소설은 백과사전과 달리 **사실이 문장에 직접 적혀 있지 않고 묘사로 표현**됩니다.
그래서 점수가 전반적으로 낮게 나옵니다. **점수의 절대값보다 순위**를 보세요.

```python
def show(query, name, k=3, width=400):
    print("=" * 72)
    print(f"Q: {query}      [{name}]")
    print("=" * 72)
    for score, text in search(query, name, k):
        snippet = " ".join(text.split())[:width]
        print(f"\n[{score:.3f}] {snippet}...")


show("아내가 앓아누워 기침하는 대목", "paragraphs-200")
```

이어서 두 개를 더 던져 봅니다.

```python
show("설렁탕을 사 왔는데 왜 먹지를 못하니", "paragraphs-200")
```

```python
# 같은 내용을 다르게 물어보면? -- 점수와 순위를 잘 보세요.
show("김 첨지의 아내는 어떤 상태인가?", "paragraphs-200")
```

### 세 결과를 나란히 놓고 보세요

| 질문 | 1위 점수 | 1위로 돌아온 대목 | 맞았나? |
|---|---|---|---|
| 아내가 앓아누워 기침하는 대목 | 0.457 | "그의 아내가 기침으로 쿨럭거리기는 벌써 달포가 넘었다…" | **맞음** |
| 설렁탕을 사 왔는데 왜 먹지를 못하니 | 0.645 | 소설의 마지막 대사 | **맞음** |
| **김 첨지의 아내는 어떤 상태인가?** | **0.583** | 김 첨지가 술집에서 떡과 술을 먹는 장면 | **틀림** |

세 번째 질문은 첫 번째와 **묻는 내용이 사실상 같습니다.**
그런데 점수는 0.583으로 더 높은데, 돌아온 대목은 아내와 아무 상관없는 술집 장면입니다.

**왜 이런 일이 생길까요?**

질문에 `김 첨지`라는 인물 이름이 들어가자, **인물 이름과 대화가 빽빽하게 들어 있는 대목**이
의미상 더 가깝게 계산되었습니다. 소설은 백과사전과 달리 *"아내는 폐병을 앓고 있다"* 처럼
사실을 직접 진술하지 않고 **묘사로 돌려 말하기** 때문에, "어떤 상태인가" 같은 추상적인 질문은
특정 대목에 잘 달라붙지 않습니다.

### 여기서 얻을 교훈 두 가지

1. **점수는 질문끼리 비교할 수 없습니다.** 0.583이 0.457보다 크다고 해서 더 좋은 검색이 아닙니다.
   점수는 **같은 질문 안에서 순위를 매기는 용도**로만 의미가 있습니다.
2. **질문을 쓰는 방식이 검색 품질을 바꿉니다.** 같은 것을 물어도
   "~은 어떤 상태인가"(추상적)보다 "~하는 대목"(장면 묘사)이 훨씬 잘 찾습니다.
   실무에서는 사용자의 질문을 LLM으로 다시 쓰는 **질의 재작성(query rewriting)** 을 쓰기도 합니다.

---

## Step 8. 청크 크기를 바꿔 보기

같은 문서, 같은 질문, 같은 임베딩 모델입니다. **청크 크기만** 바뀝니다.

```python
QUESTION = "아내가 앓아누워 기침하는 대목"

for size in [100, 200, 400, 800]:
    name = f"para-{size}"
    build(name, chunk_paragraphs(doc, size))
    score, text = search(QUESTION, name, k=1)[0]
    snippet = " ".join(text.split())
    print("=" * 72)
    print(f"청크 크기 {size:>4}토큰  |  {len(INDEX[name][0]):>3}개 청크  |  "
          f"1위 점수 {score:.3f}  |  이 청크는 {ntok(text)}토큰")
    print("=" * 72)
    print(snippet[:600] + ("..." if len(snippet) > 600 else ""))
    print()
```

**실행 결과 요약**

| 청크 크기 | 청크 개수 | 1위 점수 | 돌아온 청크 |
|---|---|---|---|
| 100 | 76개 | 0.457 | 아내의 병을 묘사한 문단 (277토큰) |
| 200 | 57개 | 0.457 | **위와 완전히 같은 청크** |
| 400 | 36개 | 0.457 | **위와 완전히 같은 청크** |
| 800 | 17개 | 0.425 | 같은 문단으로 시작하지만 뒤에 다른 장면들이 붙은 788토큰 덩어리 |

### 100, 200, 400이 왜 똑같을까요?

`chunk_paragraphs`는 문단을 **쪼개지 않고 모으기만** 합니다.
`chunk_size`는 "이 크기로 자른다"가 아니라 **"이 크기를 넘지 않게 문단을 합친다"는 상한**입니다.

우리가 찾는 대목은 그 자체로 **277토큰짜리 문단 하나**입니다.
상한을 100으로 낮춰도 이 문단은 쪼개지지 않고 그대로 남습니다. 목표 200을 넘는데도 그렇습니다.

> **`chunk_size`를 줄였는데 결과가 그대로라면 청커가 무시하고 있는 것입니다.**
> 숫자만 바꾸지 말고, 청크가 몇 개 만들어졌는지(76 → 57 → 36 → 17개)와
> 실제로 돌아온 청크의 크기를 함께 확인하세요.

### 800에서는 왜 점수가 떨어졌을까요?

여러 문단이 하나로 합쳐지면서 아내의 병 묘사가 **다른 장면들에 희석**되었습니다.
임베딩은 텍스트 전체의 평균에 가깝기 때문에, 다른 내용이 섞일수록 유사도가 낮아집니다(0.457 → 0.425).
답이 청크 안에 들어 있긴 하지만, LLM에게 넘길 컨텍스트로는 788토큰 중 대부분이 군더더기입니다.

---

## Step 9. 고정 크기 vs 문단 경계

같은 질문, 같은 목표 크기입니다.
차이는 **문장 경계를 지키느냐 마느냐** 하나뿐입니다.

```python
for name in ["fixed-200", "paragraphs-200"]:
    score, text = search(QUESTION, name, k=1)[0]
    print("=" * 72)
    print(f"{name}   점수 {score:.3f}")
    print("=" * 72)
    print(" ".join(text.split())[:500])
    print()
```

**실행 결과**

```
fixed-200   점수 0.403
�하고 손바닥에 떨어질 제 거의 눈물을 흘릴 만큼 기뻤었다...
↑ 깨진 글자로 시작

paragraphs-200   점수 0.457
그의 아내가 기침으로 쿨럭거리기는 벌써 달포가 넘었다...
↑ 문단이 온전함
```

| | 1위 점수 | 돌아온 내용 |
|---|---|---|
| `fixed-200` | 0.403 | **깨진 글자(`�`)로 시작**합니다. 앞부분은 돈 이야기이고, 아내의 병 묘사는 뒤에 일부만 걸쳐 있습니다 |
| `paragraphs-200` | **0.457** | 아내의 병을 묘사한 문단이 처음부터 끝까지 온전히 |

**맨 앞의 깨진 글자를 보세요.** 한글은 글자 하나가 여러 토큰으로 쪼개지기 때문에,
토큰 개수만 세어 자르면 **글자 한가운데가 잘려 나갑니다.**
영어에서는 단어가 잘리는 정도지만, 한글에서는 **글자 자체가 깨집니다.**

**문장 경계를 지키는 것만으로 검색 품질이 올라갑니다.**

### 직접 질문을 바꿔 보세요

변수 하나만 두고 여러 질문을 시험해 보기 좋습니다.

```python
MY_QUESTION = "설렁탕을 사 왔는데 왜 먹지를 못하니"

show(MY_QUESTION, "paragraphs-200", k=3)
```

시도해 볼 만한 것들입니다.

- **작품 전체에 걸친 질문** (*"이 소설의 제목이 왜 반어적인가?"*)
  — 청크 하나에 답이 들어 있을 수 있을까요? 임베딩 검색의 한계가 드러납니다.
- **유명한 마지막 대사** (*"설렁탕을 사 왔는데 왜 먹지를 못하니"*)
  — 구체적인 문장은 잘 찾아냅니다. 점수 0.645로 이 노트북에서 가장 높습니다.
- **작품에 없는 내용** (*"파이썬으로 웹 서버 만드는 법은?"*) — 바로 아래에서 해 봅니다.

### 답이 없는 질문도 던져 보세요

```python
# 작품에 답이 없는 질문 -- 내용보다 점수를 보세요.
show("파이썬으로 웹 서버 만드는 법은?", "paragraphs-200", k=3)
```

**실행 결과**

```
[0.166] “젠장맞을 것! 이 비를 맞으며 빈 인력거를 털털거리고 돌아를 간담...
[0.116] 그는 불행에 다닥치기 전 시간을 얼마쯤이라도 늘리려고 버르적거렸다...
[0.116] 그는 몹시 홧...
```

작품에 답이 있는 질문은 0.45~0.65가 나왔는데, 파이썬 질문은 **0.166, 0.116, 0.116** 입니다.
그런데도 검색은 **빈손으로 돌아오지 않습니다.** 무조건 세 개를 가져옵니다.

> 실무에서는 이 점수에 **하한선(threshold)** 을 두어, 기준보다 낮으면
> "관련 내용을 찾지 못했습니다"라고 처리합니다.
> 그러지 않으면 LLM이 엉뚱한 대목을 근거로 그럴듯한 답을 지어냅니다.
>
> 다만 하한선은 **문서 종류마다 달라야 합니다.** 이 소설에서는 정답이 0.45 정도인데,
> `chunk_basic_ko1.ipynb`의 백과사전 문서에서는 정답이 0.5~0.7이었습니다.

---

## Step 10. 벡터 DB에 저장하기 (Chroma)

지금까지는 임베딩을 **numpy 행렬**에 담아 두고 내적으로 검색했습니다.
청크가 57개뿐이라 충분했지만, 실제 서비스에서는 두 가지가 아쉽습니다.

1. **커널을 껐다 켜면 사라집니다.** 매번 다시 임베딩해야 하고, 그때마다 비용이 듭니다.
2. **문서가 많아지면 느려집니다.** 전체를 훑는 방식이라 청크 수에 비례해 느려집니다.

**Chroma**는 파일로 저장되는 가벼운 벡터 DB입니다.
두 청킹 방식을 **각각 별도의 컬렉션**으로 저장해서, 같은 질문을 두 컬렉션에 던져 비교할 것입니다.

> 이미 Step 6에서 임베딩을 계산해 `INDEX`에 담아 두었습니다.
> 그 벡터를 그대로 DB에 넣으므로 **추가 임베딩 비용은 0원**입니다.

```python
import chromadb
from chromadb.errors import NotFoundError

DB_PATH = "chroma_chunk_ko2"

client = chromadb.PersistentClient(path=DB_PATH)

collections = {}
for name in ["fixed-200", "paragraphs-200"]:
    chunks, V = INDEX[name]          # Step 6에서 만들어 둔 청크와 임베딩 벡터

    # 같은 이름의 컬렉션이 이미 있으면 지우고 새로 만든다. (이 셀을 몇 번이든 다시 실행할 수 있도록)
    try:
        client.delete_collection(name)
        print(f"{name:16s} 기존 컬렉션 삭제")
    except NotFoundError:
        pass                          # 없으면 그냥 새로 만들면 된다

    col = client.create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},   # 코사인 거리로 비교
    )
    col.add(
        ids=[f"{name}-{i}" for i in range(len(chunks))],
        documents=chunks,
        embeddings=V.tolist(),               # 이미 계산한 벡터를 재사용 (재임베딩 안 함)
        metadatas=[{"chunk_id": i, "tokens": ntok(c)} for i, c in enumerate(chunks)],
    )
    collections[name] = col
    print(f"{name:16s} {col.count():>3}개 청크 저장")

print(f"\n저장 위치: {DB_PATH}/")
```

**실행 결과**

```
fixed-200        기존 컬렉션 삭제
fixed-200         55개 청크 저장
paragraphs-200   기존 컬렉션 삭제
paragraphs-200    57개 청크 저장

저장 위치: chroma_chunk_ko2/
```

### 폴더를 직접 지우면 안 됩니다

실습을 반복하려고 `shutil.rmtree("chroma_chunk_ko2")`로 폴더를 통째로 지우면 이런 오류가 납니다.

```
InternalError: Collection [fixed-200] already exists
InternalError: Error creating hnsw segment reader: Nothing found on disk
```

커널에 살아 있는 Chroma 클라이언트가 **"컬렉션이 있다"는 정보를 메모리에 들고 있는데**
디스크의 파일만 사라져서, 앞뒤가 맞지 않는 상태가 되기 때문입니다.

폴더가 아니라 **`client.delete_collection(name)`으로 컬렉션을 지워야** 합니다.
(커널을 재시작한 뒤라면 폴더를 지워도 괜찮습니다.)

### DB에서 검색하기

Chroma는 유사도가 아니라 **거리(distance)** 를 돌려줍니다.
벡터를 길이 1로 정규화해 두었으므로 `유사도 = 1 - 거리` 로 환산하면
Step 6에서 numpy로 계산한 값과 같아집니다.

```python
def search_db(query, name, k=3):
    """벡터 DB에서 검색한다. (점수, 본문, 청크번호, 토큰수) 리스트를 돌려준다."""
    qv = embed([query])[0]                       # 질문을 벡터로
    res = collections[name].query(query_embeddings=[qv.tolist()], n_results=k)
    return [
        (1 - dist, text, meta["chunk_id"], meta["tokens"])
        for dist, text, meta in zip(res["distances"][0], res["documents"][0], res["metadatas"][0])
    ]


# numpy 방식과 결과가 같은지 확인
q = "아내가 앓아누워 기침하는 대목"
print("numpy :", f"{search(q, 'paragraphs-200', k=1)[0][0]:.3f}")
print("chroma:", f"{search_db(q, 'paragraphs-200', k=1)[0][0]:.3f}")
```

**실행 결과**

```
numpy : 0.457
chroma: 0.457
```

**두 값이 같아야 합니다.** 다르다면 정규화를 빠뜨렸거나 거리 방식(`hnsw:space`)이 다른 것입니다.

---

## Step 11. Gradio로 두 방식 비교하기

질문을 입력하면 **두 컬렉션에 같은 질문을 던져** 결과를 나란히 보여 주고,
무엇이 어떻게 다른지 **문장으로 정리해 주는** 화면을 만듭니다.

비교 문장은 세 가지를 자동으로 판단합니다.

1. **점수** — 어느 쪽 1위 점수가 높은가
2. **같은 대목인가** — 두 방식이 찾아온 본문이 얼마나 겹치는가
3. **잘렸는가** — 청크가 문장 중간에서 끊겼는지, 한글 글자가 깨졌는지

```python
from difflib import SequenceMatcher


def diagnose(text):
    """청크가 잘렸는지 진단한다."""
    problems = []
    if "\ufffd" in text[:5]:
        problems.append("글자가 깨진 채 시작")
    if not text.rstrip().endswith((".", "!", "?", "”", "\"", "…", "-")):
        problems.append("문장 중간에서 끝남")
    return problems


def build_summary(query, fixed, paras):
    """두 결과를 비교하는 문장을 만든다."""
    fs, ft = fixed[0][0], fixed[0][1]
    ps, pt = paras[0][0], paras[0][1]

    lines = [f"### 「{query}」 비교 결과", ""]

    # 1) 점수
    winner = "문단 청킹" if ps > fs else "고정 크기 청킹"
    lines.append(f"- **점수**: 고정 크기 `{fs:.3f}` vs 문단 `{ps:.3f}` "
                 f"→ **{winner}**이 `{abs(ps - fs):.3f}` 높습니다.")

    # 2) 같은 대목을 찾았는가
    overlap = SequenceMatcher(None, ft, pt).ratio()
    if overlap > 0.3:
        lines.append(f"- **내용**: 두 방식이 **같은 대목**을 찾았습니다 (본문 일치도 {overlap:.0%}). "
                     f"어디서 잘랐는지만 다릅니다.")
    else:
        lines.append(f"- **내용**: 두 방식이 **서로 다른 대목**을 가져왔습니다 (본문 일치도 {overlap:.0%}). "
                     f"직접 읽고 어느 쪽이 질문에 맞는지 판단해 보세요.")

    # 3) 잘림 진단
    fp, pp = diagnose(ft), diagnose(pt)
    if fp:
        lines.append(f"- **잘림**: 고정 크기 1위 청크는 {', '.join(fp)}. "
                     f"한글은 글자 하나가 여러 토큰이라 토큰 경계로 자르면 글자가 깨질 수 있습니다.")
    if not pp:
        lines.append("- **잘림**: 문단 청크는 문장이 온전합니다.")
    elif pp:
        lines.append(f"- **잘림**: 문단 1위 청크도 {', '.join(pp)} (대화체라 따옴표로 끝나는 경우가 있습니다).")

    # 4) 크기
    lines.append(f"- **크기**: 고정 크기 {fixed[0][3]}토큰 / 문단 {paras[0][3]}토큰")
    return "\n".join(lines)


def format_results(title, results):
    out = [f"### {title}", ""]
    for rank, (score, text, chunk_id, tokens) in enumerate(results, 1):
        body = " ".join(text.split())
        out.append(f"**{rank}위 · 점수 {score:.3f} · 청크 {chunk_id} · {tokens}토큰**")
        out.append("")
        out.append(f"> {body[:400]}{'...' if len(body) > 400 else ''}")
        out.append("")
    return "\n".join(out)


def compare(query, k):
    if not query.strip():
        return "질문을 입력하세요.", "", ""
    k = int(k)
    fixed = search_db(query, "fixed-200", k)
    paras = search_db(query, "paragraphs-200", k)
    return (build_summary(query, fixed, paras),
            format_results("고정 크기 청킹 (fixed-200)", fixed),
            format_results("문단 청킹 (paragraphs-200)", paras))


# UI 없이 함수만 먼저 확인
summary, _, _ = compare("아내가 앓아누워 기침하는 대목", 3)
print(summary)
```

**실행 결과**

```
### 「아내가 앓아누워 기침하는 대목」 비교 결과

- **점수**: 고정 크기 `0.403` vs 문단 `0.457` → **문단 청킹**이 `0.054` 높습니다.
- **내용**: 두 방식이 **서로 다른 대목**을 가져왔습니다 (본문 일치도 22%).
- **잘림**: 고정 크기 1위 청크는 글자가 깨진 채 시작, 문장 중간에서 끝남.
- **잘림**: 문단 청크는 문장이 온전합니다.
- **크기**: 고정 크기 200토큰 / 문단 277토큰
```

> **UI를 붙이기 전에 함수부터 확인하세요.** Gradio 안에서 난 오류는 추적하기 번거롭습니다.
> 함수가 제대로 도는 것을 확인한 뒤 화면을 씌우는 편이 훨씬 빠릅니다.

### 화면 만들기

```python
import gradio as gr

with gr.Blocks(title="청킹 방식 비교 검색") as demo:
    gr.Markdown("# 청킹 방식 비교 검색\n"
                "「운수 좋은 날」에서 같은 질문을 **두 가지 청킹 방식**으로 검색하고 결과를 비교합니다.")

    with gr.Row():
        question = gr.Textbox(label="질문", value="아내가 앓아누워 기침하는 대목", scale=4)
        k = gr.Slider(1, 5, value=3, step=1, label="가져올 청크 수 (k)", scale=1)

    btn = gr.Button("검색", variant="primary")

    gr.Examples(
        examples=[
            ["설렁탕을 사 왔는데 왜 먹지를 못하니"],
            ["김 첨지의 아내는 어떤 상태인가?"],
            ["김 첨지가 친구 치삼과 술을 마시는 장면"],
            ["비 오는 날씨 묘사"],
            ["파이썬으로 웹 서버 만드는 법은?"],
        ],
        inputs=question,
    )

    summary_out = gr.Markdown()
    with gr.Row():
        fixed_out = gr.Markdown()
        paras_out = gr.Markdown()

    outputs = [summary_out, fixed_out, paras_out]
    btn.click(compare, inputs=[question, k], outputs=outputs)
    question.submit(compare, inputs=[question, k], outputs=outputs)

demo.launch(inbrowser=True)
```

끝나면 서버를 내립니다.

```python
demo.close()
```

### 화면에서 확인해 볼 것

- **예시 질문을 차례로 눌러 보세요.** 질문 종류에 따라 승자가 바뀝니다.
- **`k`를 1로 줄여 보세요.** 1위만 봤을 때 답을 놓치는 경우가 생깁니다.
- **"파이썬으로 웹 서버 만드는 법은?"** 을 넣어 보세요.
  점수가 0.2 아래로 떨어지지만, 두 방식 모두 **무언가를 돌려준다**는 점을 확인할 수 있습니다.
- **같은 내용을 다르게 물어보세요.** Step 7에서 본 것처럼, 질문 표현만 바꿔도 결과가 완전히 달라집니다.

---

## 자주 만나는 오류

| 증상 | 원인 | 해결 |
|---|---|---|
| `JSONDecodeError` | `action=raw` 주소를 썼다 | `api.php`의 `extracts`를 쓰세요 (Step 1) |
| `KeyError: 'extract'` | 작품 제목이 정확하지 않다 | [ko.wikisource.org](https://ko.wikisource.org)에서 정확한 제목을 확인하세요 |
| 청크가 4~5개밖에 안 나옴 | `\n\s*\n`(빈 줄)로 나눴다 | `\n+`로 바꾸세요 (Step 4) |
| `sections`가 1개 | 소설에는 `== 제목 ==`이 없다 | 정상입니다. 소설에는 쓰지 않습니다 |
| `BadRequestError: maximum input length is 8192` | 문서 전체를 임베딩하려 했다 | 청킹이 필요한 이유입니다 (Step 3) |
| `Collection [...] already exists` | DB 폴더를 직접 지웠다 | `client.delete_collection(name)`을 쓰거나 커널을 재시작하세요 (Step 10) |
| `Nothing found on disk` | 위와 같음 | 위와 같음 |
| 포트 7860 충돌 | 이전 Gradio 서버가 살아 있다 | `demo.close()`를 실행하세요 |

---

## 정리

| | 배운 것 |
|---|---|
| **글의 종류가 청커를 고른다** | 절 제목이 없는 소설에서 `chunk_sections`는 무용지물 |
| **문단 구분자를 확인하라** | 빈 줄이냐 한 줄 바꿈이냐에 따라 청크가 4개 vs 57개 |
| **한글은 토큰을 많이 쓴다** | 글자당 약 1.07토큰. 영어의 약 4배 |
| **문장 경계를 지켜라** | 토큰으로 자르면 한글은 **글자가 깨진다** |
| **점수는 질문끼리 비교 못 한다** | 0.583이 0.457보다 큰데 틀린 답이었다 |
| **`chunk_size`는 상한일 뿐** | 줄였는데 결과가 같다면 청커가 무시하고 있는 것 |
| **검색은 빈손으로 안 돌아온다** | 관련 없어도 k개를 가져온다. 하한선이 필요하다 |

## 다음 단계

- **다른 작품으로 바꿔 보세요.** `TITLE`만 바꾸면 됩니다.
  예: `"메밀꽃 필 무렵"`(이효석), `"날개"`(이상), `"벙어리 삼룡이"`(나도향)
- **백과사전 문서와 비교해 보세요.** `chunk_basic_ko1.ipynb`는 같은 코드를
  한국어 위키백과 「인공지능」 문서로 돌립니다.
  소설과 설명문에서 **검색 점수와 청크 모양이 어떻게 다른지** 비교해 보면 좋습니다.
- **문서 여러 개를 다루기** — `chunk_basic_ko3.ipynb`에서 보안 문서 4개를 다루고,
  찾아온 청크를 **LLM에게 넘겨 답변까지** 만듭니다.
- **눈으로 보지 말고 측정하기** — 이 노트북은 눈으로 읽고 판단했습니다.
  질문이 100개라면 그럴 수 없습니다.
  `chunk_basic_ko4.ipynb`에서 **채점표를 만들어 숫자로** 비교합니다.
- **LLM까지 연결하려면** — 이 노트북은 검색까지만 다룹니다.
  전체 RAG 흐름은 `rag_basic_ko.ipynb`에 있습니다.
