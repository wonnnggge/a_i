# CVE 키 → CWE 설명 검색 RAG (취약점 유형 학습/교육용)

CVE ID를 키로 삼아 연결된 CWE(취약점 유형) 설명을 검색하는 RAG 파이프라인입니다.
목적은 "이 CVE는 어떤 유형의 취약점이고, 왜 위험하며, 어떻게 예방하는가"를
학습·교육 관점에서 답하는 것입니다. (제품별 실제 영향도·패치 버전 등은
CWE 문서에 없으므로 이 파이프라인의 범위 밖입니다.)

**데이터는 실제 MITRE CWE 카탈로그와 NVD CVE API에서 직접 받아옵니다.** 샘플이
아니라 원문입니다. 따라서 CWE 문서 본문은 영문입니다.

> **흐름도** — 단계별 프로세스와 데이터 흐름은 [flow.md](flow.md) 에 그려 두었습니다.
>
> **교육용 CVE** — 수업 실습에 쓸 CVE 5건과 선정 근거는
> [cve_recommend.md](cve_recommend.md) 에 정리해 두었습니다.
>
> **배경 지식** — CVE ID 체계(연도가 다르면 같은 번호도 다른 취약점), 공식 CVE
> 저장소의 디렉토리 규칙, CVE 데이터 구조는
> [../additional_info.md](../additional_info.md) 에 정리해 두었습니다.

## 교육생용 노트북

각 단계를 눈으로 확인하며 배울 수 있도록 노트북을 준비했습니다.
`.py` 파일과 **같은 함수를 그대로 import 해서 쓰므로 결과가 동일합니다.**

| 노트북 | 대응 `.py` | 배우는 것 |
|---|---|---|
| [1_fetch.ipynb](1_fetch.ipynb) | `0_fetch_real_data.py` | CVE와 CWE의 관계, 왜 CWE만 임베딩하는가 |
| [2_chunk.ipynb](2_chunk.ipynb) | `1_chunk.py` | 청크 크기가 검색 품질을 좌우하는 이유 |
| [3_embed.ipynb](3_embed.ipynb) | `2_embed_and_store.py` | 임베딩이란, TF-IDF vs OpenAI 품질 비교 |
| [4_query.ipynb](4_query.ipynb) | `3_query.py` | 메타데이터 필터 + 의미 검색, 답변 생성 |

노트북은 `security_rag/` 폴더에서 실행합니다. 순서대로 보면 됩니다.

**데이터는 이미 수집·색인되어 있어 그대로 실행하면 됩니다.**
재수집·재청킹·재색인이 필요하면 각 노트북의 `RECOLLECT`, `SAVE_CHUNKS`,
`REINDEX` 플래그를 `True` 로 바꾸세요. 기본값은 모두 `False` 입니다.

## 구조

```
data/
  cwe_catalog.json       MITRE CWE 원문 (0단계 산출물)
  cve_cwe_mapping.json   CVE ID -> CWE ID 매핑 + 제품/CVSS/공개일 (0단계 산출물)
  raw/cwec_latest.xml    MITRE 원본 XML 캐시 (재다운로드 방지)
  chunks.json            1단계 산출물
  chroma_db/             2단계 산출물 (벡터 DB)
  tfidf_vectorizer.pkl   TF-IDF 백엔드일 때 질의 임베딩에 재사용
  embedding_config.json  색인에 쓴 임베딩 백엔드 기록
  sample/                원래 있던 가상 샘플 데이터 (참고용, 파이프라인은 안 씀)

src/
  0_fetch_real_data.py   MITRE CWE XML + NVD API에서 실데이터 수집
  1_chunk.py             CWE 문서를 섹션 단위로 청크 분할
  2_embed_and_store.py   임베딩 생성 후 Chroma에 저장
  3_query.py             CVE ID로 CWE 문서 검색
```

## 실행 순서

```bash
python src/0_fetch_real_data.py     # 실데이터 수집 (네트워크 필요, 수 분 소요)
python src/1_chunk.py
python src/2_embed_and_store.py
python src/3_query.py
```

---

## 실행 옵션 정리

네 스크립트 중 **명령줄 옵션을 받는 것은 `0_fetch_real_data.py`와 `3_query.py`뿐**입니다.
`1_chunk.py`와 `2_embed_and_store.py`는 인자를 받지 않으며, 붙여도 **조용히 무시하고
그냥 실행**됩니다(`--help`를 붙여도 도움말 대신 작업이 실행되니 주의하세요).

### 0_fetch_real_data.py — 데이터 수집

| 옵션 | 값 | 기본 | 설명 |
|---|---|---|---|
| `--source` | `kev` \| `recent` | `kev` | `kev`=악용이 확인된 취약점, `recent`=최근 N일 공개 CVE |
| `--days` | 정수 (최대 120) | `30` | `--source recent`일 때 조회 기간 |
| `--severity` | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` | 없음 | CVSS v3 심각도 필터 |
| `--max-cves` | 정수 | `200` | 수집할 CVE 최대 개수 |
| `--cve-ids` | CVE ID 여러 개 | 없음 | 특정 CVE를 반드시 포함 |
| `--cwe-scope` | `mapped` \| `all` | `mapped` | `mapped`=참조되는 CWE만, `all`=전체 1,391개 |
| `--no-cache` | 플래그 | 끔 | CWE XML 캐시를 무시하고 다시 받음 |

```bash
# 기본 — KEV 200건 + 거기서 참조되는 CWE만
python src/0_fetch_real_data.py

# 유명한 CVE를 콕 집어 포함시키기
python src/0_fetch_real_data.py --cve-ids CVE-2021-44228 CVE-2014-0160 CVE-2014-6271

# 최근 30일 CRITICAL 등급 CVE 400건
python src/0_fetch_real_data.py --source recent --days 30 --severity CRITICAL --max-cves 400

# CWE 카탈로그 전체(1,391개) 저장
python src/0_fetch_real_data.py --cwe-scope all
```

> **`--cve-ids`와 조회 옵션은 함께 쓸 수 있습니다.** 지정한 CVE를 먼저 넣고,
> 그 뒤에 `--max-cves` 만큼 더 채웁니다(중복은 제거).
>
> **주의: 이 스크립트는 기존 파일을 덮어씁니다.** 이미 수집해둔 CVE를 유지하려면
> `--cve-ids`에 함께 적어야 합니다.

### 1_chunk.py — 청킹

옵션 없음. `cwe_catalog.json`을 읽어 `chunks.json`을 만듭니다.

```bash
python src/1_chunk.py
```

### 2_embed_and_store.py — 임베딩·저장

명령줄 옵션은 없고 **환경변수로 제어**합니다.

```bash
python src/2_embed_and_store.py
```

> 실행할 때마다 컬렉션을 **지우고 새로 만듭니다**(멱등성).
> 이때 컬렉션 UUID가 바뀌므로, 챗봇이 떠 있었다면 재시작하는 편이 안전합니다.

### 3_query.py — 검색·답변

argparse가 아니라 **위치 인자**를 씁니다.

| 형태 | 동작 |
|---|---|
| `python src/3_query.py` | 데이터에서 CVE 3건을 골라 데모 실행 |
| `python src/3_query.py <CVE-ID>` | 그 CVE를 기본 질문으로 조회 |
| `python src/3_query.py <CVE-ID> "<질문>"` | 그 CVE를 지정한 질문으로 조회 |
| `python src/3_query.py --ui` | gradio 챗봇 실행 (http://127.0.0.1:7860) |
| `python src/3_query.py --ui --share` | 외부 공유 주소까지 생성 |

```bash
python src/3_query.py
python src/3_query.py CVE-2008-2992
python src/3_query.py CVE-2008-2992 "how should developers prevent this?"
python src/3_query.py --ui
```

> **`--help`는 지원하지 않습니다.** 첫 인자를 CVE ID로 해석하므로
> `--help`를 CVE ID로 착각해 "매핑 정보가 없습니다"를 출력합니다.

### 환경변수 (`.env` 또는 셸에서 지정)

| 변수 | 쓰는 스크립트 | 기본값 | 설명 |
|---|---|---|---|
| `OPENAI_API_KEY` | 2, 3 | — | 임베딩과 답변 생성에 필요 |
| `NVD_API_KEY` 또는 `NVD_KEY` | 0 | 없음 | 있으면 요청 간격 6초 → 0.7초 (두 이름 모두 인식) |
| `EMBEDDING_BACKEND` | 2, 3 | `openai` | `openai` \| `tfidf` \| `sentence-transformers` |
| `EMBEDDING_MODEL` | 2, 3 | 백엔드별 기본 | 예: `text-embedding-3-small`, `BAAI/bge-m3` |
| `CHAT_MODEL` | 3 | `gpt-4.1-nano` | 답변 생성 LLM |

**`EMBEDDING_BACKEND`는 2단계와 3단계에 같은 값을 써야 합니다.**
다르면 3단계가 `embedding_config.json`을 읽어 에러로 막아줍니다.

```powershell
# PowerShell — TF-IDF로 바꿔 품질을 비교해 보기
$env:EMBEDDING_BACKEND = "tfidf"
python src/2_embed_and_store.py
python src/3_query.py CVE-2008-2992
```

```bash
# bash — 한 번만 적용
EMBEDDING_BACKEND=tfidf python src/2_embed_and_store.py
```

NVD는 API 키가 없으면 요청 간 6초를 쉬어야 해서 느립니다.
[무료 키](https://nvd.nist.gov/developers/request-an-api-key)를 발급받아
프로젝트 루트 `.env`에 `NVD_API_KEY=...` 또는 `NVD_KEY=...`로 넣어두면
자동으로 사용합니다.

---

## 검색 예시

인자 없이 실행하면 데이터에 들어 있는 CVE 중 몇 개를 골라 보여줍니다.
특정 CVE를 조회하려면 `data/cve_cwe_mapping.json`에 있는 것이어야 합니다.

```bash
python src/3_query.py CVE-2008-2992 "how should developers prevent this?"
```

```
[CVE 조회] CVE-2008-2992
  제품: adobe acrobat
  CVSS: 7.8 (HIGH)   공개일: 2008-11-04
  연결된 CWE: CWE-787

[검색된 근거 청크]
  - CWE-787 / potential_mitigations  (거리 0.528)
    Out-of-bounds Write
    [Requirements] Use a language that does not allow this weakness to occur ...
```

CVE ID로 먼저 후보 CWE를 좁히고(메타데이터 필터) 그 안에서만 의미 검색을 하는
구조라, 무관한 CWE 문서가 딸려 오지 않습니다.

## 챗봇 UI (gradio)

```bash
python src/3_query.py --ui            # http://127.0.0.1:7860
python src/3_query.py --ui --share    # 외부 공유 주소까지 생성
```

명령줄 조회는 검색된 근거를 그대로 보여주지만, 챗봇은 그 근거를 LLM에 넘겨
한국어 답변까지 생성합니다. 즉 여기서 RAG의 R(검색)과 G(생성)이 모두 갖춰집니다.

- 질문 안에 CVE ID를 적으면 자동으로 인식합니다 (`CVE-2021-44228은 왜 위험한가요?`).
- 답변 아래 **검색된 근거 보기**를 펼치면 어느 CWE 문서의 어느 섹션에서 나온
  답인지, 거리 값이 얼마인지 확인할 수 있습니다.
- 답변 생성 모델은 기본 `gpt-4.1-nano`이며 `CHAT_MODEL` 환경변수로 바꿉니다.
- `OPENAI_API_KEY`가 없으면 답변 생성만 건너뛰고 검색된 근거는 그대로 보여줍니다.

### 검색어에서 CVE ID를 제거하는 이유

챗봇을 붙이면서 발견한 문제입니다. 사용자가 쓴 문장을 그대로 검색어로 넘기면
엉뚱한 섹션이 걸립니다.

| 검색어 | 검색 결과 |
|---|---|
| `CVE-2021-44228은 개발자가 어떻게 예방하나요?` | observed_examples 3개 (거리 0.495~0.514) |
| `은 개발자가 어떻게 예방하나요?` | potential_mitigations 3개 (거리 0.686~0.711) |

`observed_examples` 섹션의 본문이 온통 CVE 번호 나열이라, 검색어에 CVE ID가
있으면 '예방 방법'이라는 의도 대신 'CVE 번호가 많은 글'과 매칭됩니다. 거리
0.495는 의도가 아니라 글자 모양이 닮아 나온 가짜 점수입니다. CVE ID는 이미
메타데이터 필터로 쓰이고 있으므로, 의미 검색에는 의도가 담긴 문장만 넘깁니다
(`clean_query()`).

## 임베딩 백엔드 선택

`EMBEDDING_BACKEND` 환경변수로 바꿉니다. 2단계와 3단계에 같은 값을 써야 하며,
다르면 3단계가 에러로 알려줍니다.

| 값 | 설명 |
|---|---|
| `openai` (기본) | OpenAI 임베딩 API(text-embedding-3-small). `.env`의 `OPENAI_API_KEY` 사용 |
| `tfidf` | scikit-learn TF-IDF. 설치·키 불필요, 단어 일치 기반이라 품질이 낮음 |
| `sentence-transformers` | 로컬 신경망 모델(기본 BAAI/bge-m3). 첫 실행 시 모델 다운로드 |

품질 차이는 큽니다. 같은 질문("how should developers prevent this?")과 같은
후보 청크에 대해 측정한 코사인 거리입니다.

| 백엔드 | 상위 3개 거리 | 결과 |
|---|---|---|
| OpenAI | 0.56 ~ 0.57 | `potential_mitigations` 를 정확히 찾음 |
| TF-IDF | 0.95 ~ 0.98 | 사실상 무매칭 |

TF-IDF는 **키 없이도 파이프라인을 돌려보거나 품질 차이를 비교하는 용도**로
남겨두었습니다. 비교해 보려면 이렇게 바꿉니다.

```bash
EMBEDDING_BACKEND=tfidf python src/2_embed_and_store.py
EMBEDDING_BACKEND=tfidf python src/3_query.py CVE-2008-2992
```

비교가 끝나면 반드시 기본값(openai)으로 다시 색인하세요.

## 알아둘 점

1. **CWE는 재사용 자원입니다.** CWE 문서는 CWE당 한 번만 임베딩해 저장하고,
   CVE 쪽은 매핑 테이블(`cve_cwe_mapping.json`)로만 연결하는 구조를 유지하세요.
   CVE마다 CWE 본문을 복제해서 임베딩하면 저장 공간과 비용이 불필요하게 늘어납니다.

2. **모든 CVE에 CWE가 붙어 있지는 않습니다.** NVD가 `NVD-CWE-noinfo`로
   남겨둔 CVE가 꽤 있고(CVE-2017-0144, CVE-2018-11776 등), 이런 항목은 수집
   단계에서 제외됩니다. `--cve-ids`로 지정해도 마찬가지입니다.

3. **NVD는 상위 Category로 매핑하기도 합니다.** CWE-264(권한/접근 제어) 같은
   Category는 개별 Weakness가 아니라 XML의 `<Categories>`에 들어 있고 본문도
   요약 한 줄뿐입니다. 수집 코드가 이것까지 담지만, 검색 결과의 정보량은 적습니다.

4. **`product` 필드는 첫 번째 CPE 항목입니다.** 한 CVE가 수십 개 제품에
   영향을 줄 때 그중 하나만 보여주므로(예: Log4Shell이 Siemens 펌웨어로 표시됨),
   영향 범위 판단에는 쓰지 마세요.
