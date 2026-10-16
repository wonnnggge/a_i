<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->
# security_rag_advance — 프로세스 및 데이터 흐름

> CVE ID를 키로 삼되, **벤더 어드바이저리와 위험도 신호를 더해**
> "그래서 지금 무엇을 해야 하는가"까지 답하는 RAG 파이프라인
> 작성 기준: 2026-09-10 / 현재 데이터 상태 반영

---

## 1. 1단계 프로젝트와 무엇이 다른가

[security_rag](../security_rag/)는 CWE 문서 하나만 검색했습니다.
이 프로젝트는 **성격이 다른 두 종류의 지식**을 함께 다룹니다.

| | `scope=type` | `scope=instance` |
|---|---|---|
| 내용 | CWE 유형 문서 (MITRE) | 벤더 어드바이저리 (OSV·Red Hat·KEV) |
| 성격 | **유형 지식** — 여러 CVE가 공유 | **사건 지식** — 이 CVE 전용 |
| 필터 키 | `cwe_id` | `cve_id` |
| 답하는 질문 | 왜 위험한가, 근본 예방책은 | **무엇을 해야 하는가** |
| 현재 청크 | 3,653개 (CWE 1,391개 전부) | 167개 (CVE 30건분) |

여기에 **벡터 검색을 쓰지 않는 재료**가 추가됩니다.

| 재료 | 얻는 방법 | 답하는 질문 |
|---|---|---|
| 위험도 (CVSS·EPSS·KEV) | `cve_core.json`에서 **그대로 읽음** | 얼마나 급한가 |
| 버전 판정 | OSV 범위를 **부등호로 비교** | 내 버전이 위험한가 |

> **숫자와 버전을 LLM에게 계산시키지 않는 것**이 이 프로젝트의 핵심 원칙입니다.
> `2.14.1`과 `2.15.0`은 임베딩 공간에서 거의 같은 위치라, 검색 결과만 보고
> 답하게 하면 **안전한 버전을 취약하다고 말할 수 있습니다.**

---

## 2. 한눈에 보기

```
┌───────────────────────── 준비 단계 (한 번만) ─────────────────────────┐
│                                                                        │
│  [0] 수집               [1] 청킹           [2] 임베딩·저장             │
│  0_fetch_advisories.py  1_chunk.py         2_embed_and_store.py       │
│         │                    │                    │                    │
│         ▼                    ▼                    ▼                    │
│  cve_core.json          chunks.json          chroma_db/                │
│  advisories.json        (3,820 청크)         (3,820 벡터)              │
│  cwe_catalog.json        type 3,653          embedding_config.json     │
│                          instance 167                                  │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────── 사용 단계 (질문마다) ────────────────────────┐
│                                                                        │
│   3_query.py  (하드 게이트)        4_query.py  (소프트 라우팅)         │
│        └──────────── 같은 벡터 DB·같은 부품 공유 ──────────┘           │
│                                                                        │
│   common.py — 경로 / 임베딩 백엔드 / 청킹 유틸 / 질의 정리             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 전체 데이터 흐름

### 수집 — 여섯 소스에서 세 파일로

```
  CVE ID (--cve-ids / --from-kev)
    │
    ├─▶ NVD API ──────────▶ CWE 매핑, CVSS, 참조 URL ─┐
    ├─▶ CISA KEV ─────────▶ 필수 조치, 기한, 랜섬웨어 ─┼─▶ cve_core.json
    ├─▶ FIRST EPSS ───────▶ 악용 확률 예측 ───────────┘     (30건)
    │
    ├─▶ OSV.dev ──────────▶ 영향/수정 버전, details ──┐
    └─▶ Red Hat ──────────▶ statement, 우회책, RHSA ──┴─▶ advisories.json
                                                            (38건)

  MITRE CWE XML ──────────▶ 유형 문서 ───────────────────▶ cwe_catalog.json
    (CVE와 무관)                                             (1,391개)
```

### 왜 파일을 셋으로 나누는가 — 이 프로젝트의 핵심 설계

**세 데이터의 수명 주기가 다르기 때문입니다.**

| 파일 | 바뀌는 주기 | 소유 | 크기 |
|---|---|---|---|
| `cwe_catalog.json` | 분기~연 단위 | **여러 CVE가 공유** | 큼 (1,391개) |
| `advisories.json` | 패치가 나올 때마다 | CVE 전용 | 작음 |
| `cve_core.json` | **EPSS는 매일 갱신** | CVE 전용 | 작음 |

한 파일에 섞으면 어드바이저리 하나가 바뀔 때마다 **CWE 3,653청크까지 다시
임베딩**하게 됩니다. 이 분리가 2단계의 **부분 갱신(upsert)** 을 가능하게 만듭니다.

### 청킹 — 두 지식을 한 컬렉션에, 메타데이터로 구분

```
cwe_catalog.json ──▶ chunk_cwe_catalog()   ──▶ scope="type"      3,653
advisories.json  ──▶ chunk_advisories()    ──▶ scope="instance"    137
cve_core.json    ──▶ chunk_kev_actions()   ──▶ scope="instance"     30
                                                              ─────────
                                              chunks.json      3,820
```

**소스마다 분할 전략이 다릅니다.** 문서 구조가 다르므로 같은 방식으로 자르면 안 됩니다.

| 소스 | 분할 방식 | 이유 |
|---|---|---|
| CWE | **섹션 단위** (정의/상세/완화/사례) | MITRE 표준 구조가 이미 의미 단위 |
| OSV `details` | 문단 경계, 최대 1,200자 | 서술형 긴 글 |
| Red Hat `mitigation`/`details` | **필드 하나 = 청크 하나** | 이미 짧고 독립적 |
| KEV `required_action` | **필드 하나 = 청크 하나** | 조치 문장 하나가 완결됨 |

각 청크에 붙는 메타데이터가 3단계 검색의 재료입니다.

```
chunk_id, text, header, scope, source_type, cve_id, cwe_id, vendor, section, fetched_at
                          └─ 필터 키 ─┘   └───── 필터 키 ─────┘
```

---

## 4. 질의 시점의 상세 흐름 (`3_query.py`)

```
사용자 질문  "CVE-2021-44228 우리는 2.14.1을 씁니다"
   │
   ▼
┌──────────────────────────────────────────────────────┐
│ extract_cve_id()  /  cve_from_history()              │
│   문장에서 CVE ID를 찾고, 없으면 직전 대화에서 이어받음 │
└──────────────────┬───────────────────────────────────┘
                   │
      ┌────────────┴────────────┐
      │ 못 찾음                  │ 찾음
      ▼                         ▼
 역방향 조회 시도        ┌──────────────────────────────┐
 answer_reverse_         │ cve_core.json 에 있나?        │
 lookup()                └───────┬──────────────────────┘
 (유형 → CVE 목록)               │
                     ┌───────────┴───────────┐
                     │ 있음                   │ 없음
                     ▼                       ▼
        ┌────────────────────┐   ┌────────────────────────────┐
        │ 수집 데이터 사용     │   │ answer_uncollected_cve()   │
        └────────┬───────────┘   │  NVD·KEV·EPSS 실시간 조회   │
                 │               │  (1~2초, 저장하지 않음)     │
                 │               └────────┬───────────────────┘
                 └───────────┬────────────┘
                             ▼
   ┌─────────────────────────────────────────────────────────┐
   │  [계산으로 얻는 사실]  ← 벡터 검색 안 씀                  │
   │    format_risk()     CVSS · EPSS · KEV                  │
   │    check_version()   introduced <= 내 버전 < fixed       │
   └─────────────────────────┬───────────────────────────────┘
                             │
   ┌─────────────────────────▼───────────────────────────────┐
   │  [검색으로 얻는 근거]  ← 벡터 검색                        │
   │    retrieve()  — 쿼터를 나눠 두 번 질의                   │
   │      ① where scope=instance AND cve_id=…   → 3개         │
   │      ② where scope=type AND cwe_id in […]  → 2개         │
   └─────────────────────────┬───────────────────────────────┘
                             ▼
                  ┌──────────────────────┐
                  │ generate_answer()    │
                  │  <위험도>            │ ← 확정 사실, 재계산 금지
                  │  <버전 판정>         │ ← 확정 사실, 재계산 금지
                  │  <어드바이저리>       │ ← 검색 근거
                  │  <취약점 유형>        │ ← 검색 근거
                  └──────────┬───────────┘
                             ▼
                  답변 + 위험도 + 판정 + 접어둔 근거
```

### 왜 쿼터를 나눠 두 번 질의하나

한 번에 섞어서 상위 5개를 뽑으면 **한쪽이 결과를 독점합니다.**

현재 `type` 3,653개 vs `instance` 167개로 **22배 차이**입니다.
필터 없이 검색하면 어드바이저리는 거의 올라오지 못합니다.
그런데 좋은 답에는 두 종류가 모두 필요합니다.

```
어드바이저리 = "무엇을 해야 하는가"  (올릴 버전, 우회책)
CWE 유형     = "왜 그런가"          (근본 원인, 예방책)
```

---

## 5. 수집하지 않은 CVE의 처리

**두 지식의 커버리지가 다릅니다.**

```
scope=type      CWE 1,391개 전부  ← CVE 수집량과 무관하게 완비
scope=instance  수집한 30건분만
```

그래서 모르는 CVE라도 **CWE 번호만 알면 절반은 답할 수 있습니다.**

```
질문: CVE-2019-0708은 왜 위험한가요?
  │
  ├─ cve_core.json 에 없음
  ▼
fetch_cve_live()   NVD + KEV(캐시) + EPSS  →  1~2초
  │                CWE-416 / CVSS 9.8 / KEV 등재 / EPSS 0.99999
  ▼
색인된 CWE-416 문서로 답변 생성
  │
  ▼
"> 수집되지 않은 CVE입니다. …
 > 벤더 어드바이저리가 없어 패치 버전·우회책·조치 기한은 답할 수 없습니다."
```

| 답할 수 있는 것 | 답할 수 없는 것 |
|---|---|
| 어떤 유형의 취약점인가 | 어느 버전으로 올려야 하나 |
| 왜 위험한가, 근본 예방책 | 당장 못 올릴 때의 우회책 |
| CVSS · EPSS · KEV 위험도 | 벤더가 정한 조치 기한 |

> **실시간 조회 결과는 파일로 저장하지 않습니다.** 채팅 한 번 때문에 `data/`와
> 벡터 DB를 건드리면 색인 상태를 예측할 수 없게 됩니다.
>
> **`--cwe-scope all`이 이 기능의 전제입니다.** `mapped`로 수집하면 CWE 카탈로그가
> 참조된 것만 남아(1,391 → 수십 개) 실시간 폴백이 무력화됩니다.

### 확인하지 않은 것을 "없다"고 하지 않습니다

```
CISA KEV 등재됨       — 확인했고, 있다
CISA KEV 미등재       — 확인했고, 없다
CISA KEV 확인하지 못함 — 확인 자체를 못 했다   ← 이 구분이 중요
```

KEV 조회에 실패했는데 "미등재"라고 표시하면, **실제로 악용 중인 취약점을
안심하고 미루게 됩니다.**

---

## 6. 두 가지 라우팅 — `3_query.py` vs `4_query.py`

**완전히 같은 벡터 DB와 같은 계산 부품을 씁니다.** 다른 것은 라우팅뿐입니다.

| | `3_query.py` 하드 게이트 | `4_query.py` 소프트 라우팅 |
|---|---|---|
| 의도 분류의 역할 | **접근 권한**처럼 작동 | 정확도를 높이는 **최적화** |
| 신호를 못 찾으면 | 검색을 시작하지 않고 안내 | 넓게 검색해서 답함 |
| 장점 | 답변이 정확하고 일관됨 | 답할 수 있는 질문을 거절하지 않음 |
| 단점 | **답할 수 있는데도 거절** | 엉뚱한 답을 할 여지 |

### 실제 사례

```
질문: "Can you describe about CWE-1021?"

3_query.py → 'CVE 목록 요청'으로 분류 → "수집된 데이터에 이 유형의 CVE가 없습니다"
             (그런데 CWE-1021 문서는 4개 청크로 멀쩡히 색인돼 있었다)

4_query.py → 구조화 신호(CWE-1021) 발견 → 정확 조회 → 클릭재킹 설명 + CSP 완화책
```

### 왜 '전부 벡터 검색'은 답이 아닌가

```
"describe CWE-1021" 무필터 검색 결과
  X CWE-225   거리 0.338   ← 오답인데 거리가 더 낮다
  X CWE-217   거리 0.368
  O CWE-1021  거리 0.499   ← 정확 조회로 찾은 정답
```

임베딩은 `CWE-1021`과 `CWE-1022`를 구별하지 못합니다.
**정확히 지정된 식별자는 검색이 아니라 조회(lookup)로 처리해야 합니다.**

```
어느 문서를 찾을까  →  벡터 검색 (넓게, 쿼터로)
어떤 연산을 할까    →  구조화 조회 / 계산       ← 검색으로 대체 불가
  · ID 정확 조회 (CWE-1021)  →  카탈로그 사전 조회
  · 목록·개수                →  cve_core 훑기
  · 버전 판정                →  부등호 비교
  · 범위 제한                →  메타데이터 필터
```

---

## 7. 파일 의존 관계

```
                    ┌──────────────┐
                    │  common.py   │  경로 · 임베딩 백엔드 · 청킹 유틸 · 질의 정리
                    └──────┬───────┘
        ┌──────────┬───────┼───────┬──────────┐
        ▼          ▼       ▼       ▼          ▼
  0_fetch_    1_chunk.py  2_embed  3_query.py  4_query.py
  advisories.py             _and_       │           │
        │          │       _store.py    │           │
        ▼          ▼          │         │           │
  cve_core.json    │          │         │      q3의 부품 재사용
  advisories.json ─┤          │         │      (check_version,
  cwe_catalog.json─┘          │         │       format_risk, _query,
        │                     │         │       fetch_cve_live …)
        │              chunks.json      │           │
        │                     │         │           │
        │                chroma_db/ ────┴───────────┘
        │                embedding_config.json
        │
        └─▶ 3_query.py 가 실시간 조회 시 import
            (fetch_nvd_cve, fetch_kev_catalog, fetch_epss, build_cve_core)
```

**`4_query.py`가 `3_query.py`를 import 하는 이유** — 비교가 공정하려면
바뀐 변수가 **라우팅 하나여야** 합니다. 계산·검색 부품은 그대로 가져다 씁니다.

**`3_query.py`가 `0_fetch_advisories.py`를 import 하는 이유** — 수집하지 않은
CVE를 실시간 조회할 때 같은 파싱 로직을 써야 결과가 일관됩니다.

---

## 8. 실행 옵션

### 0_fetch_advisories.py — 수집

| 옵션 | 값 | 기본 | 설명 |
|---|---|---|---|
| `--cve-ids` | CVE ID 여러 개 | 없음 | 수집할 CVE 목록 |
| `--from-kev` | 정수 N | `0` | KEV에서 최근 추가된 N건을 대상에 추가 |
| `--cwe-scope` | `mapped` \| `all` | `mapped` | `all`이어야 실시간 폴백이 동작 |
| `--no-cache` | 플래그 | 끔 | CWE XML·KEV 캐시 무시하고 다시 받음 |

```bash
# 현재 데이터를 만든 명령 (유명 CVE 5건 + KEV 최근 25건 = 30건)
python src/0_fetch_advisories.py \
  --cve-ids CVE-2021-44228 CVE-2021-45046 CVE-2022-22965 CVE-2017-5638 CVE-2014-6271 \
  --from-kev 25 --cwe-scope all
```

> **이 스크립트는 세 JSON을 덮어씁니다.** 기존 CVE를 유지하려면 `--cve-ids`에
> 함께 적어야 합니다.

### 1_chunk.py — 청킹

옵션 없음.

### 2_embed_and_store.py — 임베딩·저장

| 옵션 | 설명 |
|---|---|
| (없음) | **upsert** — 있으면 갱신, 없으면 추가 (빠름) |
| `--full` | 컬렉션을 지우고 전체를 새로 만듦 |

> **upsert는 사라진 청크를 지우지 못합니다.** 수집 범위를 줄였다면
> 반드시 `--full`을 쓰세요. 그러지 않으면 예전 CVE의 어드바이저리가 남아
> "데이터에 없다"면서 어드바이저리는 나오는 **모순된 답변**이 만들어집니다.
>
> 정합성 확인: `len(chunks.json) == collection.count()`

### 3_query.py — 검색·답변 (하드 게이트)

| 형태 | 동작 |
|---|---|
| `python src/3_query.py` | 데모 CVE 하나로 실행 |
| `python src/3_query.py <CVE-ID>` | 그 CVE 조회 |
| `python src/3_query.py <CVE-ID> "<질문>"` | 질문 지정 |
| `... --answer` | LLM 답변까지 생성 |
| `... --weakness "<유형>"` | 역방향 조회 (유형 → CVE 목록) |
| `--ui` / `--ui --share` | gradio 챗봇 |

```bash
python src/3_query.py CVE-2021-44228 "우리는 2.14.1을 쓰는데 어떻게 하나요?" --answer
python src/3_query.py --weakness "SQL injection"
python src/3_query.py --ui
```

### 4_query.py — 검색·답변 (소프트 라우팅)

| 형태 | 동작 |
|---|---|
| `python src/4_query.py "<질문>"` | 질문 하나를 답함 |
| `--ui` / `--ui --share` | gradio 챗봇 |

```bash
python src/4_query.py "Can you describe about CWE-1021?"
python src/4_query.py --ui

# 두 챗봇을 동시에 띄워 비교하려면 포트를 다르게
GRADIO_SERVER_PORT=7861 python src/4_query.py --ui
```

### 환경변수

| 변수 | 쓰는 곳 | 기본 | 설명 |
|---|---|---|---|
| `OPENAI_API_KEY` | 2, 3, 4 | — | 임베딩·답변 생성 |
| `NVD_API_KEY` / `NVD_KEY` | 0, 3 | 없음 | 있으면 6초 → 0.7초 (두 이름 모두 인식) |
| `EMBEDDING_BACKEND` | 2, 3, 4 | `openai` | `openai` \| `tfidf` \| `sentence-transformers` |
| `EMBEDDING_MODEL` | 2, 3, 4 | 백엔드별 | 예: `text-embedding-3-small` |
| `CHAT_MODEL` | 3, 4 | `gpt-4.1-nano` | 답변 생성 LLM |

색인과 검색의 백엔드가 다르면 `common.check_backend_match()`가 실행 전에 막아줍니다.

---

## 9. 실행 순서

```bash
# 준비
python src/0_fetch_advisories.py --from-kev 30 --cwe-scope all   # 2~4분
python src/1_chunk.py                                            # 1초 미만
python src/2_embed_and_store.py --full                           # 수 분

# 사용
python src/3_query.py CVE-2021-44228 --answer
python src/4_query.py "SQL injection 관련 CVE가 뭐야?"
python src/3_query.py --ui
```

**재수집했다면 1·2단계도 반드시 다시 실행하세요.** 특히 수집 범위를 줄였다면 `--full`이 필수입니다.

---

## 10. 현재 데이터 규모

| 항목 | 값 |
|---|---|
| CVE (cve_core) | 30건 |
| 어드바이저리 | 38건 (OSV 16 · Red Hat 12 · Maven 4 · PyPI 3 · 기타 3) |
| CWE 카탈로그 | 1,391개 (`--cwe-scope all`) |
| 청크 | 3,820 (type 3,653 + instance 167) |
| 벡터 DB | 3,820 (**일치**) |
| 임베딩 | `openai` / text-embedding-3-small / 1536차원 |
| 답변 생성 | `gpt-4.1-nano` |

---

## 관련 문서

- [README.md](README.md) — 프로젝트 개요와 설계 배경
- [TESTING.md](TESTING.md) — 테스트 시나리오
- [../additional_info.md](../additional_info.md) — CVE ID 체계와 데이터 구조
- [../security_rag/flow.md](../security_rag/flow.md) — 1단계 프로젝트 흐름도
- 노트북 — [1_fetch](1_fetch.ipynb) · [2_chunk](2_chunk.ipynb) · [3_embed](3_embed.ipynb) · [4_query](4_query.ipynb) · [5_routing](5_routing.ipynb)
