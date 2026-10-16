# 따라 하기: 청킹 → 임베딩 → LLM 답변 만들기

이 문서를 처음부터 끝까지 따라 하면 `chunk_basic_ko3.ipynb`와 같은 노트북을 직접 만들 수 있습니다.
완성하면 **보안 문서 4개를 검색해서 근거와 함께 답변하는 프로그램**이 됩니다.

## 무엇을 배우나

| 단계 | 배우는 것 |
|---|---|
| 청킹 | 긴 문서를 왜, 어떻게 자르는가 |
| 임베딩 | 문장을 숫자 벡터로 바꿔 "의미가 가까운 것"을 찾는 방법 |
| LLM 답변 | 찾아온 문서를 근거로 LLM이 답하게 만드는 방법 |

## 전체 흐름

```
[준비] 문서 4개 → ① 청킹 → ② 임베딩 → ③ 벡터 DB 저장
[질문] 질문 → ④ 관련 청크 검색 → ⑤ 질문 + 청크를 LLM에 전달 → 답변
```

---

## 사전 준비

### 1. 패키지 설치

터미널에서 실행합니다.

```bash
pip install openai chromadb tiktoken numpy requests python-dotenv
```

### 2. API 키 준비

프로젝트 폴더에 `.env` 파일을 만들고 OpenAI API 키를 넣습니다.

```
OPENAI_API_KEY=sk-proj-...
```

### 3. 새 노트북 만들기

`rag/` 폴더에 새 주피터 노트북을 만듭니다. 이제부터 나오는 코드를 **셀 하나씩** 입력하고 실행하세요.

> **비용 안내**: 이 실습 전체를 끝까지 실행해도 1센트(약 15원) 미만입니다.

---

## Step 0. 준비

첫 셀에 필요한 도구를 불러오고 설정을 정합니다.

```python
import re
import time

import numpy as np
import requests
import tiktoken
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)
ai = OpenAI()

ENC = tiktoken.get_encoding("cl100k_base")
ntok = lambda t: len(ENC.encode(t))

EMBED_MODEL = "text-embedding-3-small"
CHAT_MODEL = "gpt-4.1-mini"
```

- `ntok()`는 글자가 아니라 **토큰** 수를 세는 함수입니다. 청크 크기는 토큰 기준으로 관리합니다.
- 모델은 두 개를 씁니다. 하나는 **문장을 벡터로 바꾸는 모델**, 하나는 **답변을 만드는 모델**입니다.

✅ **확인**: 오류 없이 실행되면 됩니다. `OPENAI_API_KEY` 오류가 나면 `.env` 파일 위치를 확인하세요.

---

## Step 1. 문서 내려받기

한국어 위키백과에서 보안 문서 4개를 받습니다.

```python
TITLES = ["정보 보안", "피싱", "SQL 삽입", "크로스 사이트 스크립팅"]

session = requests.Session()
session.headers.update({"User-Agent": "llm-edu-notebook/1.0"})   # 한글 금지 (latin-1만 허용)


def fetch_wiki(title, retries=4):
    """위키백과에서 문서 한 개를 순수 텍스트로 받아온다. 429가 오면 기다렸다 재시도."""
    for attempt in range(retries):
        resp = session.get(
            "https://ko.wikipedia.org/w/api.php",
            params={
                "action": "query", "format": "json", "prop": "extracts",
                "explaintext": 1, "redirects": 1, "titles": title,
            },
            timeout=30,
        )
        if resp.status_code == 429:          # 요청이 너무 잦음 -> 기다렸다 재시도
            wait = 3 * (attempt + 1)
            print(f"  429 Too Many Requests — {wait}초 대기 후 재시도")
            time.sleep(wait)
            continue
        page = next(iter(resp.json()["query"]["pages"].values()))
        return page["title"], page["extract"].strip()
    raise RuntimeError(f"{title} 내려받기 실패")


docs = {}
for t in TITLES:
    title, text = fetch_wiki(t)
    docs[title] = text
    print(f"{title:14s} {len(text):>7,}자 {ntok(text):>7,}토큰")
    time.sleep(1.5)                          # 위키백과에 대한 예의이자 429 예방

print(f"\n합계 {sum(len(t) for t in docs.values()):,}자 "
      f"{sum(ntok(t) for t in docs.values()):,}토큰 ({len(docs)}개 문서)")
```

**실행 결과**

```
정보 보안            4,065자   3,462토큰
피싱               5,120자   4,363토큰
SQL 삽입           2,397자   1,438토큰
사이트 간 스크립팅       2,324자   1,817토큰

합계 13,906자 11,080토큰 (4개 문서)
```

### 알아 둘 것

- `explaintext=1`을 주면 위키 문법이 제거된 **순수 텍스트**가 옵니다. 따로 파싱할 필요가 없습니다.
- `크로스 사이트 스크립팅`으로 요청했는데 `사이트 간 스크립팅`이 돌아옵니다. `redirects=1` 덕분에 위키백과가 **넘겨주기를 따라가** 실제 문서를 찾아 준 것입니다.
- **한글은 글자 수보다 토큰이 많습니다.** 13,906자에 11,080토큰이니 글자당 약 0.8토큰입니다. 영어는 보통 글자당 0.25토큰 정도입니다.

✅ **확인**: 네 문서가 모두 0자가 아니어야 합니다. 0자라면 문서 제목이 틀린 것입니다.

---

## Step 2. 청킹 — 문서 자르기

### 왜 자르나

1. 임베딩 모델에 **입력 한계**가 있습니다(`text-embedding-3-small`은 8,192토큰). 문서 하나도 다 못 넣는 경우가 있습니다.
2. 넣을 수 있어도 **문서 전체를 벡터 하나로 만들면 쓸모가 없습니다.** 벡터가 "보안 전반"을 뜻하게 되어 어떤 질문에도 어중간하게 가깝습니다.

청킹은 **각 벡터가 한 가지 이야기만 담도록** 문서를 나누는 작업입니다.

### 두 가지 방법을 만들어 비교합니다

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


def chunk_all(docs, chunker, **kw):
    """문서마다 따로 청킹한 뒤 합친다. 각 청크에 출처를 붙인다."""
    items = []
    for title, text in docs.items():
        for piece in chunker(text, **kw):
            items.append({"text": piece, "source": title, "tokens": ntok(piece)})
    return items
```

> **중요**: `chunk_all`은 **문서마다 따로** 자릅니다.
> 「피싱」의 끝부분과 「SQL 삽입」의 앞부분이 한 청크에 섞이면 그 청크는 어느 쪽 내용도 제대로 담지 못합니다.
> 그리고 각 청크에 **출처(`source`)** 를 붙여 둡니다. 나중에 답변에 출처를 표시할 때 씁니다.

### 실행해서 비교하기

```python
CHUNKINGS = {
    "fixed-200": chunk_all(docs, chunk_fixed, size=200),
    "paragraphs-200": chunk_all(docs, chunk_paragraphs, target=200),
}

for name, items in CHUNKINGS.items():
    sizes = [it["tokens"] for it in items]
    per_doc = {t: sum(1 for it in items if it["source"] == t) for t in docs}
    print(f"{name:16s} {len(items):>3}개 청크  중앙값 {int(np.median(sizes)):>3}토큰  "
          f"최대 {max(sizes):>4}토큰")
    print(f"{'':16s} 문서별: {per_doc}")
```

**실행 결과**

```
fixed-200         58개 청크  중앙값 200토큰  최대  201토큰
                 문서별: {'정보 보안': 18, '피싱': 22, 'SQL 삽입': 8, '사이트 간 스크립팅': 10}
paragraphs-200    64개 청크  중앙값 170토큰  최대  536토큰
                 문서별: {'정보 보안': 22, '피싱': 25, 'SQL 삽입': 7, '사이트 간 스크립팅': 10}
```

### 두 방식의 차이

| | 고정 크기(`fixed-200`) | 문단(`paragraphs-200`) |
|---|---|---|
| 자르는 기준 | 토큰 200개마다 기계적으로 | 문단 경계 |
| 크기 | 일정함(모두 200토큰) | 들쭉날쭉(최대 536토큰) |
| 문장 | **중간에서 잘림** | 온전함 |

고정 크기는 토큰만 세다가 자르기 때문에 문장 중간에서 끊깁니다. 한글은 글자 하나가 여러 토큰이라 **글자 자체가 깨지기도** 합니다.

✅ **확인**: 청크 수가 각각 58개, 64개 근처면 정상입니다.

💡 **직접 해 보기**: `size=200`을 `100`이나 `400`으로 바꿔 청크 수가 어떻게 변하는지 보세요.

---

## Step 3. 임베딩과 벡터 DB 저장

### 임베딩이란

문장을 **숫자 벡터**로 바꾸는 것입니다. 의미가 비슷한 문장은 벡터 공간에서 가까운 자리에 놓입니다.
그래서 "암호"로 검색해도 "비밀번호"가 적힌 청크를 찾을 수 있습니다. 키워드가 아니라 **의미**로 찾기 때문입니다.

```python
def embed(texts, batch=256):
    out = []
    for i in range(0, len(texts), batch):
        r = ai.embeddings.create(model=EMBED_MODEL, input=texts[i : i + batch])
        out.extend(d.embedding for d in r.data)
    V = np.asarray(out, dtype=np.float32)
    V /= np.linalg.norm(V, axis=1, keepdims=True)   # 단위 벡터 -> 내적 == 코사인 유사도
    return V
```

- 청크를 한 번에 하나씩 보내면 느리므로 **256개씩 묶어** 보냅니다.
- 벡터의 길이를 1로 맞춰 두면(정규화) 나중에 유사도 계산이 곱셈 한 번으로 끝납니다.

### 벡터 DB에 저장

```python
import chromadb
from chromadb.errors import NotFoundError

DB_PATH = "chroma_chunk_ko3"
client = chromadb.PersistentClient(path=DB_PATH)

collections = {}
for name, items in CHUNKINGS.items():
    texts = [it["text"] for it in items]
    V = embed(texts)
    print(f"{name:16s} 임베딩 완료 (약 ${sum(it['tokens'] for it in items) / 1e6 * 0.02:.4f})")

    # 이미 있으면 지우고 새로 만든다. (셀을 몇 번이든 다시 실행할 수 있도록)
    try:
        client.delete_collection(name)
    except NotFoundError:
        pass

    col = client.create_collection(name=name, metadata={"hnsw:space": "cosine"})
    col.add(
        ids=[f"{name}-{i}" for i in range(len(items))],
        documents=texts,
        embeddings=V.tolist(),
        metadatas=[{"source": it["source"], "chunk_id": i, "tokens": it["tokens"]}
                   for i, it in enumerate(items)],
    )
    collections[name] = col
    print(f"{name:16s} {col.count():>3}개 청크 저장")

print(f"\n저장 위치: {DB_PATH}/")
```

**실행 결과**

```
fixed-200        임베딩 완료 (약 $0.0002)
fixed-200         58개 청크 저장
paragraphs-200   임베딩 완료 (약 $0.0002)
paragraphs-200    64개 청크 저장

저장 위치: chroma_chunk_ko3/
```

### 알아 둘 것

- 청크 본문뿐 아니라 **메타데이터(출처·번호·토큰 수)** 를 함께 저장합니다. 나중에 "어느 문서에서 나온 답인지" 보여 줄 때 씁니다.
- 두 청킹 방식을 **각각 별도 컬렉션**으로 저장했습니다. 같은 질문을 둘 다에 던져 비교하기 위해서입니다.

> ⚠️ **폴더를 직접 지우지 마세요.**
> 실습을 다시 하려고 `shutil.rmtree("chroma_chunk_ko3")`로 폴더를 통째로 지우면 이런 오류가 납니다.
>
> ```
> InternalError: Collection [fixed-200] already exists
> InternalError: Error creating hnsw segment reader: Nothing found on disk
> ```
>
> 커널에 살아 있는 클라이언트가 "컬렉션이 있다"는 정보를 메모리에 들고 있는데 파일만 사라져서 앞뒤가 안 맞기 때문입니다.
> 위 코드처럼 **`client.delete_collection(name)`으로 컬렉션을 지워야** 합니다.

✅ **확인**: 저장된 청크 수가 Step 2의 청크 수와 같아야 합니다.

---

## Step 4. 검색 — 질문과 가까운 청크 찾기

```python
def search_db(query, name, k=3):
    """(점수, 본문, 출처, 토큰수) 리스트를 돌려준다."""
    qv = embed([query])[0]
    res = collections[name].query(query_embeddings=[qv.tolist()], n_results=k)
    return [
        {"score": 1 - dist, "text": text, "source": meta["source"], "tokens": meta["tokens"]}
        for dist, text, meta in zip(res["distances"][0], res["documents"][0], res["metadatas"][0])
    ]


for q in ["피싱 메일을 어떻게 구별하나요?", "SQL 인젝션을 막는 방법은?"]:
    print(f"Q: {q}")
    for hit in search_db(q, "paragraphs-200", k=3):
        print(f"  [{hit['score']:.3f}] ({hit['source']}) {' '.join(hit['text'].split())[:70]}...")
    print()
```

**실행 결과**

```
Q: 피싱 메일을 어떻게 구별하나요?
  [0.601] (피싱) 웹 사이트를 만드는 기술 이외의 특별한 기술은 아무것도 필요가 없다. 피싱 사기를 하는 방법으로...
  [0.534] (피싱) 백신 소프트웨어에 검출되지 않는 경우가 있다. 피싱 사기의 경우 아무런 특색 없는 단순한 메일...
  [0.492] (피싱) 메일을 이용해서 신뢰할 수 있는 메일 주소로 가장한다. 피싱 메일은 대부분 송신자를 사칭하고...

Q: SQL 인젝션을 막는 방법은?
  [0.457] (SQL 삽입) SQL 삽입(영어: SQL Injection, SQL 인젝션, SQL 주입)은 응용 프로그램...
  [0.432] (SQL 삽입) Blind SQL 삽입은 평범한 SQL 삽입과 같이 원하는 데이터를 가져올 쿼리를 삽입하는...
```

### 알아 둘 것

- Chroma는 유사도가 아니라 **거리**를 돌려줍니다. 벡터를 정규화해 두었으므로 `유사도 = 1 - 거리`입니다.
- 질문에 "SQL 인젝션"이라고 썼는데 문서의 표현은 "SQL 삽입"입니다. 그래도 찾아냅니다. **의미로 찾기** 때문입니다.
- `k`는 몇 개를 가져올지 정하는 값입니다. 이 값이 곧 **LLM이 읽게 될 자료의 개수**입니다.

✅ **확인**: 피싱 질문에는 「피싱」 문서가, SQL 질문에는 「SQL 삽입」 문서가 올라오면 정상입니다.

---

## Step 5. LLM으로 답변 만들기

여기까지가 **검색(Retrieval)** 이었습니다. 이제 **생성(Generation)** 을 붙이면 RAG가 완성됩니다.

```python
SYSTEM_PROMPT = """당신은 정보보안 교육 자료를 안내하는 도우미입니다.

아래 [자료]에 있는 내용만 근거로 답변하세요.
- [자료]에 없는 내용은 추측하지 말고 "제공된 자료에서 찾을 수 없습니다"라고 답하세요.
- 문장 끝에 근거가 된 자료 번호를 [1], [2] 형식으로 표시하세요.
- 한국어로, 3~5문장으로 간결하게 답하세요.

[자료]
{context}
"""


def build_context(hits):
    """검색 결과를 번호와 출처가 붙은 컨텍스트 문자열로 만든다."""
    blocks = []
    for i, hit in enumerate(hits, 1):
        blocks.append(f"[{i}] (출처: {hit['source']})\n{hit['text']}")
    return "\n\n".join(blocks)


def answer(query, name="paragraphs-200", k=3):
    """검색 -> 컨텍스트 구성 -> LLM 답변 생성."""
    hits = search_db(query, name, k)
    response = ai.chat.completions.create(
        model=CHAT_MODEL,
        temperature=0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT.format(context=build_context(hits))},
            {"role": "user", "content": query},
        ],
    )
    return response.choices[0].message.content, hits
```

### 프롬프트에서 중요한 세 가지

1. **"주어진 자료만 근거로"** — 모델이 아는 지식으로 답하지 않게 막습니다.
2. **"없으면 없다고 하라"** — 환각을 줄입니다. 이 문장이 없으면 모델은 지어냅니다.
3. **번호와 출처 붙이기** — `[1] (출처: 피싱)` 형태로 넣어 주면 모델이 `[1]`처럼 인용할 수 있어 검증이 쉬워집니다.

### 실행

```python
text, hits = answer("피싱 공격은 어떤 방식으로 이루어지나요?")
print(text)
print("\n--- 근거로 사용한 청크 ---")
for i, hit in enumerate(hits, 1):
    print(f"  [{i}] ({hit['source']}) 점수 {hit['score']:.3f} · {hit['tokens']}토큰")
```

**실행 결과**

```
피싱 공격은 전자우편이나 메신저를 이용해 신뢰할 수 있는 사람이나 기업이 보낸 것처럼 가장하여
비밀번호, 신용카드 정보 등 기밀 정보를 부정하게 얻으려는 소셜 엔지니어링 기법입니다. ...
최근에는 컴퓨터뿐 아니라 전화를 이용한 보이스피싱도 등장하는 등 다양한 형태가 있습니다[1][3].

--- 근거로 사용한 청크 ---
  [1] (피싱) 점수 0.453 · 181토큰
  [2] (피싱) 점수 0.400 · 148토큰
  [3] (피싱) 점수 0.397 · 264토큰
```

**🎉 여기까지가 RAG의 전부입니다.** 문서를 자르고, 벡터로 만들고, 질문과 가까운 것을 찾아, LLM에게 넘겼습니다.

### 자료에 없는 질문도 해 보세요

```python
text, hits = answer("랜섬웨어에 감염되면 몇 분 안에 신고해야 하나요?")
print(text)
print("\n--- 검색된 청크 (점수가 낮습니다) ---")
for hit in hits:
    print(f"  [{hit['score']:.3f}] ({hit['source']})")
```

**실행 결과**

```
제공된 자료에서 랜섬웨어 감염 시 몇 분 안에 신고해야 하는지에 대한 정보는 찾을 수 없습니다[1][3].

--- 검색된 청크 (점수가 낮습니다) ---
  [0.368] (피싱)
  [0.343] (피싱)
  [0.338] (정보 보안)
```

점수가 0.33~0.37로 낮습니다. 답이 있는 질문은 0.45~0.6이 나왔던 것과 비교해 보세요.
**검색은 빈손으로 돌아오지 않습니다.** 관련 자료가 없어도 무조건 3개를 가져옵니다. 점수가 유일한 단서입니다.

✅ **확인**: 없는 내용을 지어내지 않고 "찾을 수 없습니다"라고 답하면 성공입니다.

---

## Step 6. (심화) 청킹 방식이 답변을 바꾸는가

같은 질문, 같은 모델, 같은 프롬프트입니다. **컨텍스트를 만든 청킹 방식만** 다릅니다.

```python
QUESTIONS = [
    "정보 보안의 세 가지 핵심 요소는 무엇인가요?",   # 답이 한 곳에 명확히 있음
    "피싱 메일을 어떻게 구별하나요?",               # 답이 여러 곳에 흩어져 있음
]

for question in QUESTIONS:
    print("#" * 72)
    print(f"# {question}")
    print("#" * 72)
    for name in ["fixed-200", "paragraphs-200"]:
        text, hits = answer(question, name, k=3)
        print(f"\n[{name}]  1위 점수 {hits[0]['score']:.3f}  "
              f"출처: {', '.join(h['source'] for h in hits)}")
        print(text)
    print()
```

**결과 요약**

- **정의를 묻는 질문**(정보 보안 3요소): 두 방식의 답이 거의 같습니다. 답이 한 문장에 명확히 있으면 어떻게 잘라도 그 청크가 1위로 올라옵니다.
- **정보가 흩어진 질문**(피싱 메일 구별): 답의 강조점이 갈립니다. 어떤 청크가 들어갔느냐가 곧 답변 내용이 됩니다.

> **청킹은 검색 단계의 문제처럼 보이지만, 실제로는 최종 답변을 결정합니다.**

---

## Step 7. (심화) "모른다"고 답할 때 — 정말 자료에 없을까

```python
question = "SQL 삽입 공격을 막으려면 어떻게 해야 하나요?"

for name in ["fixed-200", "paragraphs-200"]:
    text, hits = answer(question, name, k=3)
    print(f"[{name}] 1위 점수 {hits[0]['score']:.3f}")
    print(text)
    print()
```

양쪽 모두 "자료에서 찾을 수 없습니다"라고 답합니다. 그런데 문서를 확인해 보세요.

```python
print("「SQL 삽입」 문서의 절 제목:")
for title in re.findall(r"^==+ .+ ==+$", docs["SQL 삽입"], re.M):
    print("  ", title)
```

```
   == 예 ==
   == Blind SQL 삽입 ==
   == 방어 ==              ← 답이 여기 있다
   === 준비된 선언 ===
   === 이스케이프 ===
```

**답이 문서에 있습니다.** 검색이 못 찾은 것입니다. 상위 10개를 뽑아 순위를 확인해 보세요.

```python
hits = search_db(question, "paragraphs-200", k=10)

for rank, hit in enumerate(hits, 1):
    mark = "   ← 방어 방법이 여기 있다!" if "준비된 선언" in hit["text"] else ""
    head = " ".join(hit["text"].split())[:45]
    print(f"{rank:2}위 [{hit['score']:.3f}] ({hit['source']:9s}) {head}{mark}")
```

「방어」 절 청크는 **6위**입니다. `k=3`은 물론 `k=5`로도 가져오지 못합니다.

**왜 밀렸을까요?** 질문은 "막으려면 어떻게"라는 **목적 표현**인데, 문서는 "준비된 선언", "PHP 5.2" 같은 **구현 용어**로 쓰여 있습니다. 임베딩은 표현이 비슷할수록 가깝다고 판단하므로 어휘가 다르면 밀립니다. 1위를 차지한 것은 문서 도입부의 정의 문단입니다.

질문을 문서 어휘에 맞춰 바꾸면 해결됩니다.

```python
text, hits = answer("준비된 선언으로 SQL 삽입을 막는 방법", "paragraphs-200", k=3)
print(text)
```

> **RAG가 "모른다"고 하면 프롬프트부터 고치지 마세요. 먼저 검색 결과를 눈으로 확인해야 합니다.**

---

## 자주 만나는 오류

| 오류 메시지 | 원인 | 해결 |
|---|---|---|
| `OpenAIError: Missing credentials` | API 키를 못 찾음 | `.env` 파일 위치 확인, `load_dotenv()` 실행 여부 확인 |
| `429 Too Many Requests` | 위키백과에 너무 빨리 요청 | `time.sleep(1.5)`를 빼지 마세요 |
| `UnicodeEncodeError: 'latin-1' codec` | User-Agent에 한글을 넣음 | HTTP 헤더는 영문만 가능합니다 |
| `Collection [...] already exists` | 폴더를 직접 지움 | `client.delete_collection()` 사용, 또는 커널 재시작 |
| `Error creating hnsw segment reader` | 위와 같은 원인 | 커널을 재시작하고 처음부터 실행 |
| `maximum input length is 8192 tokens` | 청킹 없이 문서 전체를 임베딩 | 청킹 후 임베딩하세요 |

---

## 정리

| 단계 | 한 일 | 핵심 |
|---|---|---|
| 1 | 문서 내려받기 | 요청 간격을 두고, 순수 텍스트로 받는다 |
| 2 | 청킹 | 문서 경계를 넘지 않게 자르고 출처를 붙인다 |
| 3 | 임베딩 · 저장 | 의미를 벡터로 바꿔 메타데이터와 함께 보관한다 |
| 4 | 검색 | 질문과 가까운 청크 k개를 가져온다 |
| 5 | 답변 생성 | "자료만 근거로, 없으면 없다고" 지시하고 출처를 인용시킨다 |

**기억할 것**

- RAG의 품질은 **검색**이 좌우합니다. 엉뚱한 청크를 가져오면 LLM도 엉뚱하게 답합니다.
- 답변이 이상하면 프롬프트보다 **검색 결과를 먼저** 확인하세요.
- 출처를 함께 보여 주면 사용자가 검증할 수 있고 환각도 빨리 발견됩니다.

## 스스로 해 보기

1. `TITLES`에 「랜섬웨어」를 추가해 보세요. 청크 수와 임베딩 비용이 얼마나 늘어나나요?
2. `SYSTEM_PROMPT`에서 "없으면 찾을 수 없다고 답하라" 문장을 지우고 문서에 없는 질문을 해 보세요. 모델이 어떻게 답하나요?
3. `answer()`의 `k`를 1과 5로 바꿔 보세요. 답변이 어떻게 달라지나요?
4. 검색 점수가 0.3 미만이면 LLM을 호출하지 않고 "관련 자료가 없습니다"라고 바로 답하도록 `answer()`를 고쳐 보세요.

## 다음 단계

- **완성본 확인**: `chunk_basic_ko3.ipynb`
- **검색을 개선하고 측정하기**: `chunk_basic_ko4.ipynb` — 채점표를 만들어 개선 기법의 효과를 숫자로 확인합니다
- **LangChain으로 같은 흐름 만들기**: `rag_basic_ko.ipynb`
- **실제 보안 데이터 다루기**: `security_rag/` — CVE와 CWE로 하는 실전 RAG
