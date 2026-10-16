# 2단계: CWE + 벤더 어드바이저리 결합 RAG (실무 적용형)

CVE ID를 키로 삼는 것은 1단계([../security_rag](../security_rag))와 같지만,
**검색 대상 문서에 벤더 어드바이저리를 추가**해서 "그래서 지금 무엇을 해야 하는가"까지
답하는 것을 목표로 합니다.

## 1단계와 무엇이 다른가

1단계는 CWE 문서만 검색했기 때문에 구조적인 한계가 있었습니다.
CWE는 취약점의 **유형**을 설명할 뿐, 특정 제품에서 이 CVE가 어떻게 터졌고
어느 버전으로 올려야 하는지는 담고 있지 않습니다.

| 질문 | 1단계 (CWE만) | 2단계 (CWE + 어드바이저리) |
|---|---|---|
| 이건 어떤 유형의 취약점인가? | 답변 가능 | 답변 가능 |
| 왜 위험한가? 일반적 예방책은? | 답변 가능 | 답변 가능 |
| 내가 쓰는 2.14.1 버전이 영향받나? | **불가** | 답변 가능 (OSV 버전 범위) |
| 어느 버전으로 올려야 하나? | **불가** | 답변 가능 (OSV fixed / RHSA) |
| 당장 못 올리면 우회책은? | **불가** | 답변 가능 (Red Hat mitigation) |
| 실제로 공격에 쓰이고 있나? | **불가** | 답변 가능 (KEV, EPSS) |
| 언제까지 조치해야 하나? | **불가** | 답변 가능 (KEV dueDate) |

즉 1단계가 **교육용**이었다면 2단계는 **대응 판단용**입니다.

---

## CVE · CWE · 어드바이저리 — 셋은 무엇이고 어떻게 다른가

이 프로젝트를 이해하려면 세 개념의 차이를 먼저 잡아야 합니다.
셋은 경쟁 관계가 아니라 **서로 다른 질문에 답하는 서로 다른 자료**입니다.

| | 정체 | 답하는 질문 | 예 | 성격 |
|---|---|---|---|---|
| **CVE** | 개별 취약점 '사건' 번호 | 어떤 사건인가? | `CVE-2021-44228` | 사건 1건 = 번호 1개 |
| **CWE** | 취약점 '유형' 사전 | 왜 생기고 어떻게 막나? | `CWE-502` | 여러 사건이 공유 |
| **어드바이저리** | 만든 쪽의 대응 지침 | 지금 뭘 해야 하나? | `GHSA-jfh8-...`, `RHSA-2021:5137` | 사건별, 수시 갱신 |

한 문장으로 요약하면 이렇습니다.

> **CVE**는 "무슨 일이 터졌는지"의 이름표,
> **CWE**는 "그런 일이 왜 생기는지"의 교과서,
> **어드바이저리**는 "그래서 뭘 해야 하는지"의 지시서입니다.

---

### CVE (Common Vulnerabilities and Exposures)

전 세계가 같은 취약점을 같은 이름으로 부르기 위한 **식별 번호**입니다.
이것이 없으면 "log4j 그 문제"라고 불러야 하는데, 서로 다른 문제를 같은 이름으로
말하거나 같은 문제를 다르게 불러 혼선이 생깁니다.

**번호 형식**: `CVE-2021-44228`

| 부분 | 의미 | 주의 |
|---|---|---|
| `CVE` | 고정 접두사 | |
| `2021` | **번호를 예약한 연도** | 발견·공개 연도가 아닙니다. 2021년에 예약한 번호가 2023년에 공개되기도 합니다 |
| `44228` | 일련번호 | 4자리 이상이며 길이가 고정이 아닙니다. 번호가 크다고 더 위험한 것도, 더 최신인 것도 아닙니다 |

일련번호 길이가 고정이 아니라는 점은 코드에도 영향을 줍니다.
`common.py`의 정규식이 `\d{4,}`로 열려 있는 이유가 이것입니다.

**누가 발급하나**: MITRE와 전 세계 CNA(CVE Numbering Authority)들이 발급합니다.
Apache, Microsoft, GitHub 같은 조직이 자기 제품의 CVE 번호를 직접 발급합니다.

**CVE가 담는 것** (`cve_core.json`으로 저장):
- 영문 설명, CVSS 점수와 심각도
- 영향 제품 목록(CPE), 참조 URL
- 연결된 CWE 번호

**CVE가 담지 않는 것** — 이것이 2단계를 만든 이유입니다:
- 취약점 유형에 대한 설명 → **CWE**가 담당
- 정확한 수정 버전, 우회책 → **어드바이저리**가 담당

---

### CWE (Common Weakness Enumeration)

개별 사건이 아니라 **취약점의 '종류'를 정리한 사전**입니다.
MITRE가 관리하며 현재 카탈로그에 **1391개 항목**이 들어 있습니다.

**핵심 성질: 재사용된다**

CWE-502(신뢰할 수 없는 데이터의 역직렬화) 문서 하나를 Log4Shell도 쓰고,
전혀 다른 제품의 역직렬화 취약점도 함께 씁니다. 그래서 이 프로젝트는
CWE 문서를 CVE마다 복제하지 않고 **한 번만 임베딩해 공유**합니다
(청크의 `scope="type"`이 이 뜻입니다).

**번호에는 의미가 없습니다.** CWE-20이 CWE-502보다 먼저 만들어졌을 뿐,
더 중요하거나 더 상위 개념이라는 뜻이 아닙니다. 대신 별도의 **추상화 수준**이
있습니다.

| 수준 | 개수 | 의미 | 예 |
|---|---|---|---|
| Pillar | 10 | 가장 추상적인 최상위 분류 | |
| Class | 114 | 언어·기술과 무관한 일반적 결함 | `CWE-20` 부적절한 입력 검증 |
| Base | 539 | 구체적인 결함 유형 (가장 많이 쓰임) | `CWE-502` 역직렬화 |
| Variant | 299 | 특정 기술에 한정된 세부 유형 | |
| Compound | 7 | 여러 결함이 결합된 형태 | |
| Category | 422 | 계층이 아니라 주제별 '묶음' | |

Category는 다른 것들과 성격이 다릅니다. 실제 결함이 아니라 관련 항목을
모아둔 폴더에 가까워서 본문이 요약 한 줄뿐입니다. 그런데 NVD가 CVE를
Category에 매핑해두는 경우가 있어, 수집 코드가 `<Categories>`까지
읽지 않으면 그런 CVE는 검색할 문서가 없어집니다.

**CWE 문서의 구조** — 모든 항목이 같은 규격을 따릅니다.

| 섹션 | 내용 |
|---|---|
| `description` | 한 문단 정의 |
| `extended_description` | 더 자세한 설명 |
| `potential_mitigations` | 예방·완화 방법 (개발 단계별) |
| `observed_examples` | 이 유형에 해당하는 실제 CVE 사례들 |

이 규격이 있기 때문에 청킹을 "500자마다 자르기"가 아니라 **섹션 단위**로
할 수 있습니다. 덕분에 청크 하나가 곧 하나의 완결된 주제가 되고,
"어떻게 예방하나"라는 질문에 `potential_mitigations` 청크가 정확히 걸립니다.

**한 CVE가 여러 CWE를 가리킬 수 있습니다.** Log4Shell이 그 예입니다.

```
CVE-2021-44228 ─┬─ CWE-20  (Class) Improper Input Validation
                ├─ CWE-400 (Class) Uncontrolled Resource Consumption
                ├─ CWE-502 (Base)  Deserialization of Untrusted Data
                └─ CWE-917 (Base)  Expression Language Injection
```

하나의 사건이 여러 결함의 **연쇄**로 일어났다는 뜻입니다. 입력 검증이
없었고(CWE-20), 그 결과 EL 주입이 가능했고(CWE-917), 역직렬화로
이어졌습니다(CWE-502). 그래서 검색할 때 이 4개 CWE를 모두 범위에 넣습니다.

---

### 어드바이저리 (Security Advisory)

제품을 만든 쪽 또는 생태계가 내는 **대응 지침**입니다.
CVE와 CWE가 답하지 못하는 "그래서 뭘 해야 하나"를 담습니다.

이 프로젝트가 쓰는 세 종류입니다.

| 종류 | 발행 주체 | 담는 것 | 이 프로젝트에서 |
|---|---|---|---|
| **GHSA** (GitHub Security Advisory) | GitHub / 오픈소스 생태계 | 영향 버전 범위, 수정 버전, 패키지 이름 | OSV.dev API로 수집 |
| **RHSA** (Red Hat Security Advisory) | Red Hat | 우회책, 제품별 수정 패키지 | Red Hat API로 수집 |
| **KEV** (Known Exploited Vulnerabilities) | 미국 CISA (정부) | 필수 조치, 조치 기한, 랜섬웨어 악용 여부 | CISA 피드로 수집 |

KEV는 엄밀히는 벤더 어드바이저리가 아니라 **정부의 조치 지시**입니다.
미국 연방기관에는 법적 구속력이 있고, 무엇보다 "실제 공격에 쓰인 것이
확인됐다"는 사실을 알려줍니다.

**어드바이저리만 답할 수 있는 것**

```
"우리는 log4j-core 2.14.1을 씁니다"
   → GHSA: 2.13.0 이상 2.15.0 미만이 취약 → 2.14.1은 영향받음, 2.15.0으로 올릴 것
   → RHSA: 당장 못 올리면 log4j2.formatMsgNoLookups 시스템 속성을 true로
   → KEV : 2021-12-24까지 조치 필수, 랜섬웨어에 사용된 것 확인됨
```

CWE 문서로는 "역직렬화는 위험하니 허용 목록을 쓰세요" 정도까지만 갈 수 있습니다.
**버전 번호는 어드바이저리에만 있습니다.**

**성격이 CWE와 정반대입니다**

| | CWE | 어드바이저리 |
|---|---|---|
| 적용 범위 | 여러 CVE가 공유 | 이 CVE 전용 |
| 갱신 주기 | 분기~연 단위 | 패치가 나올 때마다 |
| 신선도 | 거의 무관 | **매우 중요** (어제 "패치 없음"이 오늘 바뀜) |
| 청크 `scope` | `type` | `instance` |

이 차이 때문에 파일을 셋으로 나누고(`cwe_catalog` / `advisories` / `cve_core`),
색인도 어드바이저리만 골라 갱신할 수 있게 만들었습니다.

---

### 셋을 합치면 답이 완성된다

```
                    CVE-2021-44228  (사건 식별자)
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
   [위험도 신호]      [CWE 4개]        [어드바이저리 3건]
   CVSS 10.0         왜 위험한가        무엇을 해야 하나
   EPSS 0.99999      근본 예방책        2.15.0으로 올릴 것
   KEV 등재          (scope=type)      우회책: formatMsgNoLookups
   기한 2021-12-24                     (scope=instance)
        │                 │                 │
        └───────── 계산 ──┴─── 벡터 검색 ───┘
                          │
                     최종 답변
```

왼쪽(위험도)은 **조회한 사실**이라 계산해서 그대로 넣고,
오른쪽 둘은 **검색한 근거**라 질문에 맞는 부분만 뽑아 넣습니다.
이 구분이 `3_query.py` 프롬프트가 구획을 나눠 놓은 이유입니다.

---

### 현실: 어드바이저리가 없는 CVE도 많습니다

모든 CVE에 구조화된 어드바이저리가 있는 것은 아닙니다.
실제로 KEV 최신 항목 위주로 수집해보면 절반 이상이 비어 있습니다.

```
수집한 CVE 31건 중 어드바이저리가 하나도 없는 CVE: 17건 (55%)
```

이유는 커버리지 편중입니다.

- **OSV**는 오픈소스 패키지(Maven, npm, PyPI 등)에 강합니다.
  Log4j, Spring, Struts 같은 라이브러리는 잘 나옵니다.
- **Red Hat**은 자사 제품에 한정됩니다.
- **상용 폐쇄 소프트웨어, IoT 펌웨어, 네트워크 장비**는 어느 API에도
  구조화된 데이터가 없습니다. 벤더가 PDF나 웹페이지로만 공지하기 때문입니다.

그래서 어드바이저리가 없는 CVE는 **1단계와 같은 CWE 기반 답변으로 자동 축소**됩니다.
"이 유형은 이런 것이고 일반적으로 이렇게 막는다"까지는 답하되, 버전과 패치는
NVD 참조 링크를 확인하도록 안내합니다. 학습용으로 이 프로젝트를 돌려볼 때는
`--cve-ids`로 유명한 오픈소스 CVE를 지정하는 편이 결과가 잘 나옵니다.

---

## 데이터 소스

아래 표의 API는 모두 **실제로 호출해 응답을 확인**했습니다.
Log4Shell(CVE-2021-44228)로 검증한 결과를 함께 적었습니다.

| 소스 | 인증 | 얻는 것 | 검증 결과 |
|---|---|---|---|
| **MITRE CWE** | 불필요 | 취약점 유형 정의·완화·사례 | 1391개 항목 (1단계에서 사용 중) |
| **NVD CVE API 2.0** | 선택(키 있으면 빠름) | CVE→CWE 매핑, CVSS, CPE, 참조 URL | 참조 103개, `Vendor Advisory`/`Patch`/`Mitigation` 태그 부착 |
| **OSV.dev** | 불필요 | 영향 버전 범위, **수정 버전**, 서술형 details | `introduced 2.13.0 → fixed 2.15.0` |
| **CISA KEV** | 불필요 | 필수 조치, 기한, 랜섬웨어 악용 여부 | `requiredAction`, `dueDate 2021-12-24`, `랜섬웨어: Known` |
| **Red Hat Security Data** | 불필요 | 벤더 statement·details·**우회책**, RHSA별 수정 패키지 | `mitigation` 본문 확보, 영향 릴리스 43개 |
| **EPSS (FIRST)** | 불필요 | 향후 30일 악용 확률 예측 | `epss=0.99999, percentile=1.0` |

### 소스 선택 근거

- **NVD 참조 URL을 그대로 크롤링하지 않습니다.** 태그로 벤더 어드바이저리 URL을
  골라낼 수는 있지만, 벤더마다 HTML이 제각각이고 JS 렌더링이 필요한 곳도 있어
  파싱이 깨지기 쉽습니다. 대신 **구조화된 JSON을 주는 API**(OSV, Red Hat, KEV)를
  1순위로 쓰고, 참조 URL은 출처 링크로만 저장합니다.
- **OSV는 CVE ID로도, GHSA ID로도 조회됩니다.** 다만 같은 취약점이라도
  CVE 레코드(details 713자, 패키지 1개)보다 GHSA 레코드(details 3014자, 패키지 다수)가
  훨씬 풍부합니다. 그래서 CVE로 조회한 뒤 `aliases`의 GHSA ID를 따라가 한 번 더
  받아오는 방식을 씁니다.
- **EPSS와 KEV는 "예측" 요구사항에 직접 대응합니다.** EPSS는 악용 확률을 숫자로,
  KEV는 실제 악용 확인 여부를 사실로 제공합니다.

---

## 구조

1단계와 같은 `data/` + `src/` 구성을 따릅니다.

```
data/
  cwe_catalog.json          MITRE CWE 원문                    (0단계 산출물)
  cve_core.json             CVE 기본 정보 + CWE 매핑 + 위험도   (0단계 산출물)
  advisories.json           벤더 어드바이저리 본문              (0단계 산출물)
  raw/                      원본 응답 캐시 (재요청 방지)
  chunks.json               1단계 산출물
  chroma_db/                2단계 산출물 (벡터 DB)
  tfidf_vectorizer.pkl      TF-IDF 백엔드일 때 재사용
  embedding_config.json     색인에 쓴 임베딩 백엔드 기록

src/
  common.py                 공용: 경로, 임베딩 백엔드, 청킹 유틸, 질의 정리
  0_fetch_advisories.py     6개 소스에서 수집 → 위 3개 JSON 생성
  1_chunk.py                소스 유형별로 다른 전략으로 청크 분할
  2_embed_and_store.py      임베딩 생성 후 Chroma에 저장 (부분 갱신 지원)
  3_query.py                검색 + 버전 판정 + 답변 생성 (+ gradio 챗봇 UI)
```

> **흐름도** — 단계별 프로세스, 데이터 흐름, 실행 옵션은
> [advanced_flow.md](advanced_flow.md) 에 그려 두었습니다.
>
> **배경 지식** — CVE ID 체계, 공식 CVE 저장소의 디렉토리 규칙, CVE 데이터 구조
> (MITRE 원본 vs NVD 가공본), 세 위험도 신호(CVSS·EPSS·KEV)의 차이는
> [../additional_info.md](../additional_info.md) 에 정리해 두었습니다.

## 교육생용 노트북

각 단계를 눈으로 확인하며 배울 수 있도록 노트북을 준비했습니다.
`.py` 파일과 **같은 함수를 그대로 import 해서 쓰므로 결과가 동일합니다.**

| 노트북 | 대응 `.py` | 배우는 것 |
|---|---|---|
| [1_fetch.ipynb](1_fetch.ipynb) | `0_fetch_advisories.py` | 6개 소스, 파일을 셋으로 나누는 이유(수명 주기) |
| [2_chunk.ipynb](2_chunk.ipynb) | `1_chunk.py` | `scope=type` vs `scope=instance` |
| [3_embed.ipynb](3_embed.ipynb) | `2_embed_and_store.py` | 부분 갱신(upsert) vs `--full` |
| [4_query.ipynb](4_query.ipynb) | `3_query.py` | **계산으로 얻은 사실 vs 검색으로 얻은 근거** |
| [5_routing.ipynb](5_routing.ipynb) | `3_query.py` vs `4_query.py` | 하드 게이트 vs 소프트 라우팅 비교 |

노트북은 `security_rag_advance/` 폴더에서 실행합니다.

**데이터는 이미 수집·색인되어 있어 그대로 실행하면 됩니다.**
재수집·재청킹·재색인이 필요하면 각 노트북의 `RECOLLECT`, `SAVE_CHUNKS`,
`REINDEX` 플래그를 `True` 로 바꾸세요. 기본값은 모두 `False` 입니다.

## 실행 순서

임베딩 백엔드 기본값이 `openai`이므로 환경변수를 따로 줄 필요가 없습니다.

```bash
python src/0_fetch_advisories.py                       # 기본 예제 5건
python src/1_chunk.py
python src/2_embed_and_store.py --full
python src/3_query.py CVE-2021-44228 "2.14.1을 쓰는데 어떻게 하나요?"
python src/3_query.py --ui
```

명령줄 조회는 위험도·버전 판정·검색 근거를 보여줍니다.
`--answer`를 붙이면 LLM 답변까지 생성하고, `--ui`는 gradio 챗봇을 띄웁니다.

### 실행 결과 (실제 출력)

```
$ python src/0_fetch_advisories.py
[KEV] 1695건 (갱신일 2026-09-04)
[CVE-2021-44228] CWE 4개 | 어드바이저리 3건 | KEV | EPSS 1.000
[CVE-2021-45046] CWE 1개 | 어드바이저리 3건 | KEV | EPSS 1.000
...
  cwe_catalog.json   CWE 7개      cve_core.json  CVE 5건      advisories.json  14건

$ python src/1_chunk.py
청크 98개 생성 완료
  scope=type     (CWE 유형 문서)       49개
  scope=instance (벤더 어드바이저리)    44개
  scope=instance (CISA KEV 조치)        5개

$ python src/3_query.py CVE-2021-44228 "우리는 2.14.1을 쓰는데 어떻게 해야 하나요?"
[위험도 — 조회된 사실]
  CVSS 10.0 (CRITICAL)
  EPSS 0.99999 — 향후 30일 악용 '확률 예측' (전체 CVE 중 백분위 100.0%)
  CISA KEV 등재됨 — 실제 악용이 '확인된 사실' (등재 2021-12-10, 조치 기한 2021-12-24)
  랜섬웨어 캠페인에 사용된 것이 확인됨
[버전 판정 — 계산된 사실] 입력 버전: 2.14.1
  2.14.1은(는) 영향받습니다.
  org.apache.logging.log4j:log4j-core (Maven): 2.14.1은 취약 → 2.15.0 이상으로 올리세요
```

---

## 실행 옵션 정리

다섯 스크립트 중 **argparse로 옵션을 받는 것은 `0_fetch_advisories.py`와
`2_embed_and_store.py`뿐**입니다. 두 질의 스크립트는 `sys.argv`를 직접 읽고,
`1_chunk.py`는 인자를 받지 않습니다.

| 스크립트 | 인자 처리 | `--help` |
|---|---|---|
| `0_fetch_advisories.py` | argparse | 정상 동작 |
| `1_chunk.py` | 없음 | 무시하고 **그냥 실행됨** |
| `2_embed_and_store.py` | argparse | 정상 동작 |
| `3_query.py` | `sys.argv` 직접 | 지원 안 함 (CVE ID로 오인) |
| `4_query.py` | `sys.argv` 직접 | 지원 안 함 (사용법 안내 출력) |

### 0_fetch_advisories.py — 수집

| 옵션 | 값 | 기본 | 설명 |
|---|---|---|---|
| `--cve-ids` | CVE ID 여러 개 | 없음 | 수집할 CVE 목록 |
| `--from-kev` | 정수 N | `0` | KEV에서 최근 추가된 N건을 대상에 추가 |
| `--cwe-scope` | `mapped` \| `all` | `mapped` | `mapped`=참조되는 CWE만, `all`=전체 1,391개 |
| `--no-cache` | 플래그 | 끔 | CWE XML·KEV 캐시를 무시하고 다시 받음 |

```bash
# 옵션 없이 실행하면 기본 예제 CVE 목록을 씁니다
python src/0_fetch_advisories.py

# 특정 CVE만
python src/0_fetch_advisories.py --cve-ids CVE-2021-44228 CVE-2014-6271

# KEV 최근 30건
python src/0_fetch_advisories.py --from-kev 30 --cwe-scope all

# 현재 데이터를 만든 명령 (유명 CVE 5건 + KEV 최근 25건 = 30건)
python src/0_fetch_advisories.py \
  --cve-ids CVE-2021-44228 CVE-2021-45046 CVE-2022-22965 CVE-2017-5638 CVE-2014-6271 \
  --from-kev 25 --cwe-scope all
```

> **`--cve-ids`와 `--from-kev`는 함께 쓸 수 있습니다.** 지정한 CVE를 먼저 넣고
> KEV 최근 N건을 더합니다(중복 제거).
>
> **주의 1 — 세 JSON을 덮어씁니다.** 이미 수집해둔 CVE를 유지하려면 `--cve-ids`에
> 함께 적어야 합니다.
>
> **주의 2 — `--cwe-scope all`이 실시간 폴백의 전제입니다.** `mapped`로 수집하면
> CWE 카탈로그가 참조된 것만 남아(1,391 → 수십 개), 수집하지 않은 CVE에 답하는
> 기능이 무력화됩니다.

### 1_chunk.py — 청킹

옵션 없음. 세 JSON을 읽어 `chunks.json`을 만듭니다.

```bash
python src/1_chunk.py
```

### 2_embed_and_store.py — 임베딩·저장

| 옵션 | 설명 |
|---|---|
| (없음) | **upsert** — 있으면 갱신, 없으면 추가 (빠름) |
| `--full` | 컬렉션을 지우고 전체를 새로 만듦 |

```bash
python src/2_embed_and_store.py           # 어드바이저리만 갱신됐을 때
python src/2_embed_and_store.py --full    # 수집 범위·백엔드가 바뀌었을 때
```

> **upsert는 사라진 청크를 지우지 못합니다.** 수집 범위를 줄였는데 `--full` 없이
> 돌리면 예전 CVE의 어드바이저리가 남아, 위험도는 "데이터에 없다"면서
> 어드바이저리는 나오는 **모순된 답변**이 만들어집니다.
>
> 정합성 확인: `len(chunks.json) == collection.count()`

### 3_query.py — 하드 게이트 방식

| 형태 | 동작 |
|---|---|
| `python src/3_query.py` | 데모 CVE 하나로 실행 |
| `python src/3_query.py <CVE-ID>` | 그 CVE를 기본 질문으로 조회 |
| `python src/3_query.py <CVE-ID> "<질문>"` | 질문 지정 |
| `... --answer` | 검색 근거에 더해 **LLM 답변까지 생성** |
| `--weakness "<유형>"` | **역방향 조회** (유형 → CVE 목록) |
| `--ui` | gradio 챗봇 (http://127.0.0.1:7860) |
| `--ui --share` | 외부 공유 주소까지 생성 |

```bash
python src/3_query.py CVE-2021-44228
python src/3_query.py CVE-2021-44228 "우리는 2.14.1을 쓰는데 어떻게 하나요?" --answer
python src/3_query.py --weakness "SQL injection"
python src/3_query.py --ui
```

옵션이 붙지 않은 인자를 위치 인자로 보므로, `--answer`는 어느 위치에 넣어도 됩니다.

### 4_query.py — 소프트 라우팅 방식

| 형태 | 동작 |
|---|---|
| `python src/4_query.py "<질문>"` | 질문 하나를 답함 |
| `--ui` | gradio 챗봇 |
| `--ui --share` | 외부 공유 주소까지 생성 |

```bash
python src/4_query.py "Can you describe about CWE-1021?"
python src/4_query.py "SQL injection 관련 CVE가 뭐야?"
python src/4_query.py "CVE-2021-44228 우리는 2.14.1을 씁니다"
python src/4_query.py --ui
```

질문 없이 실행하면 사용법을 안내하고 종료합니다.

```bash
# 두 챗봇을 동시에 띄워 라우팅을 비교하려면 포트를 다르게 준다
python src/3_query.py --ui                              # 7860
GRADIO_SERVER_PORT=7861 python src/4_query.py --ui      # 7861
```

### 환경변수 (`.env` 또는 셸에서 지정)

| 변수 | 쓰는 스크립트 | 기본값 | 설명 |
|---|---|---|---|
| `OPENAI_API_KEY` | 2, 3, 4 | — | 임베딩과 답변 생성에 필요 |
| `NVD_API_KEY` 또는 `NVD_KEY` | 0, 3 | 없음 | 있으면 요청 간격 6초 → 0.7초 (두 이름 모두 인식) |
| `EMBEDDING_BACKEND` | 2, 3, 4 | `openai` | `openai` \| `tfidf` \| `sentence-transformers` |
| `EMBEDDING_MODEL` | 2, 3, 4 | 백엔드별 기본 | 예: `text-embedding-3-small`, `BAAI/bge-m3` |
| `CHAT_MODEL` | 3, 4 | `gpt-4.1-nano` | 답변 생성 LLM |
| `GRADIO_SERVER_PORT` | 3, 4 | `7860` | 챗봇 포트 (두 개를 동시에 띄울 때) |

**`EMBEDDING_BACKEND`는 색인과 검색에 같은 값을 써야 합니다.**
다르면 `common.check_backend_match()`가 실행 전에 막고 무엇을 고치면 되는지 알려줍니다.
`3_query.py`는 `--weakness`에서도 이 검사를 거칩니다.

```powershell
# PowerShell — TF-IDF로 바꿔 품질을 비교해 보기
$env:EMBEDDING_BACKEND = "tfidf"
python src/2_embed_and_store.py --full
python src/3_query.py CVE-2021-44228
```

```bash
# bash — 한 번만 적용
EMBEDDING_BACKEND=tfidf python src/2_embed_and_store.py --full
```

> 비교가 끝나면 반드시 기본값(`openai`)으로 **`--full` 재색인**하세요.

---

## 0단계: 수집

CVE ID 하나를 받아 6개 소스를 순회하며, 세 개의 JSON으로 나눠 저장합니다.

```
CVE ID
  ├─ NVD          → CWE 매핑, CVSS, CPE, 참조 URL      ┐
  ├─ CISA KEV     → 필수 조치, 기한, 랜섬웨어 악용      ├→ cve_core.json
  ├─ EPSS         → 악용 확률                          ┘
  ├─ OSV          → 버전 범위, 수정 버전, details      ┐
  ├─ Red Hat      → statement, mitigation, RHSA       ├→ advisories.json
  └─ (MITRE CWE)  → 유형 문서 (CVE와 무관하게 일괄)    → cwe_catalog.json
```

### 수집 옵션은 '선택지'입니다 (순서대로 실행하는 단계가 아님)

실행할 때마다 세 JSON 파일을 **덮어씁니다.** 이어붙이지 않으므로,
아래처럼 차례로 실행하면 앞의 결과는 사라지고 마지막 것만 남습니다.

```bash
python src/0_fetch_advisories.py --cve-ids CVE-2021-44228   # 이 결과는
python src/0_fetch_advisories.py --from-kev 30              # 여기서 덮어써짐
```

옵션은 성격이 다른 두 축으로 나뉩니다.

| 축 | 옵션 | 성격 |
|---|---|---|
| 어떤 CVE를 모을까 | `--cve-ids`, `--from-kev` | **서로 더해집니다.** 한 명령에 같이 쓰면 합집합 |
| CWE 문서를 얼마나 담을까 | `--cwe-scope` | 별개의 축. 위 어느 것과도 함께 쓸 수 있음 |

여러 조건을 합치려면 **한 번의 명령**에 함께 주세요.

```bash
python src/0_fetch_advisories.py --cve-ids CVE-2021-44228 --from-kev 30 --cwe-scope all
```

실제로 `--cve-ids CVE-2014-0160 --from-kev 2`를 주면 대상이 3건이 되고,
이전에 수집해 둔 5건은 파일에서 사라집니다.

### 왜 파일을 셋으로 나누는가

**수명 주기가 다르기 때문**입니다. 이것이 2단계 설계에서 가장 중요한 지점입니다.

| 파일 | 성격 | 갱신 주기 | 재사용성 |
|---|---|---|---|
| `cwe_catalog.json` | 유형 문서 | 분기~연 단위 | **여러 CVE가 공유** |
| `advisories.json` | 사건별 문서 | 수시(패치 나올 때마다) | CVE 전용 |
| `cve_core.json` | 숫자·상태 필드 | 매일(EPSS는 일 단위 갱신) | CVE 전용 |

CWE는 한 번 임베딩해두면 오래 쓰지만, 어드바이저리는 수정 버전이 추가되면
내용이 바뀝니다. 한 파일에 섞어두면 CWE까지 매번 다시 임베딩하게 되어
시간과 비용이 낭비됩니다.

### cve_core.json 스키마

```json
{
  "cve_id": "CVE-2021-44228",
  "cwe_ids": ["CWE-20", "CWE-400", "CWE-502", "CWE-917"],
  "cvss_score": 10.0,
  "severity": "CRITICAL",
  "published": "2021-12-10",
  "epss": 0.99999,
  "epss_percentile": 1.0,
  "kev": {
    "listed": true,
    "date_added": "2021-12-10",
    "due_date": "2021-12-24",
    "required_action": "For all affected software assets ...",
    "ransomware": "Known"
  },
  "references": [
    {"url": "https://...", "tags": ["Vendor Advisory", "Patch"]}
  ],
  "fetched_at": "2026-09-05T16:00:00"
}
```

### advisories.json 스키마

```json
[
  {
    "advisory_id": "GHSA-jfh8-c2jp-5v3q",
    "cve_id": "CVE-2021-44228",
    "source": "osv",
    "vendor": "Apache",
    "summary": "Remote code injection in Log4j",
    "details": "Apache Log4j2 2.0-beta9 through 2.15.0 ...",
    "affected": [
      {"ecosystem": "Maven",
       "package": "org.apache.logging.log4j:log4j-core",
       "introduced": "2.13.0", "fixed": "2.15.0"}
    ],
    "url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    "fetched_at": "2026-09-05T16:00:00"
  },
  {
    "advisory_id": "RHSA-2021:5137",
    "cve_id": "CVE-2021-44228",
    "source": "redhat",
    "vendor": "Red Hat",
    "statement": "...",
    "mitigation": "For Log4j versions >=2.10 set the system property log4j2.formatMsgNoLookups ...",
    "affected_releases": [
      {"product": "OpenShift Logging 5.0",
       "package": "openshift-logging/elasticsearch6-rhel8:v5.0.10-1",
       "advisory": "RHSA-2021:5137"}
    ]
  }
]
```

---

## 1단계: 청킹

**소스 유형마다 다른 전략**을 씁니다. 문서 구조가 다르기 때문입니다.

| 소스 | 분할 기준 | 이유 |
|---|---|---|
| CWE | 섹션 단위 (정의 / 상세 / 완화 / 사례) | MITRE 표준 구조가 있어 그대로 살리면 청크 하나가 하나의 주제가 됨 |
| OSV `details` | 문단 단위, 최대 1200자 | 서술형 산문이라 문단이 자연스러운 경계 |
| Red Hat `mitigation` / `statement` | 필드 하나 = 청크 하나 | 이미 짧고 목적이 분명해 더 자를 이유가 없음 |
| KEV `required_action` | 필드 하나 = 청크 하나 | 조치 지시문 한 덩어리가 온전해야 의미가 있음 |

1단계 프로젝트에서 쓴 `split_long_section()`(줄 경계 분할)을 그대로 재사용하고,
문단 경계 분할만 추가합니다.

### 청크 스키마

```json
{
  "chunk_id": "GHSA-jfh8-c2jp-5v3q::details::0",
  "text": "[Apache Log4j2 - 어드바이저리 상세]\n본문...",
  "source_type": "vendor_advisory",
  "scope": "instance",
  "cve_id": "CVE-2021-44228",
  "cwe_id": "",
  "vendor": "Apache",
  "section": "details",
  "fetched_at": "2026-09-05T16:00:00"
}
```

메타데이터에서 **2단계의 핵심은 `scope` 필드**입니다.

- `scope: "type"` — CWE 청크. 여러 CVE가 공유하는 유형 지식. `cwe_id`로 필터.
- `scope: "instance"` — 어드바이저리 청크. 이 CVE 전용. `cve_id`로 필터.

두 종류를 **하나의 컬렉션**에 넣되 이 필드로 구분합니다. 컬렉션을 나누면
질의를 두 번 날려야 하고 거리 값을 비교할 기준도 달라져 관리가 번거롭습니다.

---

## 2단계: 임베딩 → 벡터 DB 저장

1단계와 동일한 구조를 그대로 씁니다. `EMBEDDING_BACKEND` 환경변수로 교체합니다.

| 값 | 설명 |
|---|---|
| `openai` **(기본)** | `.env`의 `OPENAI_API_KEY` 사용. text-embedding-3-small, 1536차원 |
| `tfidf` | 의존성 없이 동작. 단어 일치 기반이라 품질 낮음 (비교 실습용) |
| `sentence-transformers` | 로컬 신경망 모델 |

색인과 검색은 반드시 같은 백엔드여야 하며, `common.check_backend_match()`가
불일치를 실행 전에 잡아 안내합니다.

### 갱신 전략 (1단계에 없던 부분)

1단계는 매번 컬렉션을 통째로 지우고 다시 만들었습니다. 어드바이저리가 들어오면
그 방식은 낭비이므로 **부분 갱신**을 지원합니다.

```python
# 이 CVE의 어드바이저리 청크만 지우고 다시 넣는다. CWE 청크는 그대로 둔다.
collection.delete(where={"$and": [
    {"cve_id": cve_id},
    {"scope": "instance"},
]})
collection.add(...)
```

`--full` 옵션을 주면 1단계처럼 전체를 다시 만듭니다.

> ### ⚠ upsert만으로는 사라진 데이터가 지워지지 않습니다
>
> upsert는 **같은 ID를 덮어쓸 뿐**입니다. 수집 범위를 줄이면 예전 청크가 그대로 남습니다.
>
> ```
> cve_core.json         : 5건
> 벡터 DB의 어드바이저리 : 35건   ← 유령 30건이 남아 검색됨
> chunks.json 3,702 ≠ 벡터 DB 3,825
> ```
>
> 위험도는 "데이터에 없다"면서 어드바이저리는 나오는 **모순된 답변**이 만들어집니다.
> **수집 범위를 줄였거나 데이터를 새로 받았다면 반드시 `--full`로 재색인하세요.**
> 일치 여부는 `len(chunks.json) == collection.count()` 로 확인합니다.

---

## 수집하지 않은 CVE는 어떻게 되나

이 프로젝트가 다루는 두 종류의 지식은 **커버리지가 다릅니다.**

| 지식 | 범위 | 답하는 질문 |
|---|---|---|
| `scope=type` — CWE 유형 문서 | **1,391개 전부** | 왜 위험한가, 근본 예방책은 |
| `scope=instance` — 벤더 어드바이저리 | **수집한 CVE 것만** | 어느 버전으로 올리나, 기한은 |

CWE 카탈로그는 MITRE에서 통째로 받아오므로 **CVE 수집량과 무관하게 완비**되어 있습니다.
그래서 수집하지 않은 CVE라도 **절반은 답할 수 있습니다.**

`3_query.py`와 `4_query.py`는 수집 데이터에 없는 CVE를 만나면
**NVD·KEV·EPSS를 그 자리에서 조회**해 CWE 번호와 위험도를 얻고,
**이미 색인된 CWE 유형 문서**로 답합니다. 1~2초면 끝납니다.

```
질문: CVE-2019-0708은 왜 위험한가요?
  → 수집 데이터에 없음
  → 실시간 조회  →  CWE-416, CVSS 9.8, KEV 등재, EPSS 0.99999
  → 색인된 CWE-416 문서로 답변 생성
  → "어드바이저리가 없어 패치 버전·기한은 답할 수 없습니다" 명시
```

| 답할 수 있는 것 | 답할 수 없는 것 |
|---|---|
| 어떤 유형의 취약점인가 | 어느 버전으로 올려야 하나 |
| 왜 위험한가, 근본 예방책 | 당장 못 올릴 때의 우회책 |
| CVSS · EPSS · KEV 위험도 | 벤더가 정한 조치 기한 |

전체 대응 정보가 필요하면 그 CVE를 수집하면 됩니다.

```bash
python src/0_fetch_advisories.py --cve-ids CVE-2019-0708
python src/1_chunk.py && python src/2_embed_and_store.py --full
```

**실시간 조회 결과는 파일로 저장하지 않습니다.** 채팅 한 번 때문에 `data/`와 벡터 DB를
건드리면 색인 상태를 예측할 수 없게 되기 때문입니다. 수집은 명시적인 명령으로만 합니다.

### 확인하지 않은 것을 "없다"고 하지 않습니다

KEV 조회에 실패했는데 "미등재"라고 표시하면, **실제로 악용 중인 취약점을 안심하고
미루게 됩니다.** 그래서 셋을 구분합니다.

```
CISA KEV 등재됨       — 확인했고, 있다
CISA KEV 미등재       — 확인했고, 없다
CISA KEV 확인하지 못함 — 확인 자체를 못 했다   ← 이 구분이 중요
```

---

## 3단계: 검색

### 쿼터 기반 하이브리드 검색

1단계는 CWE 문서만 있어서 한 번 질의하면 끝이었지만, 2단계는
**두 종류에서 각각 정해진 개수를 가져옵니다.**

```python
advisory_hits = collection.query(
    query_texts=[clean_query(question)], n_results=3,
    where={"$and": [{"cve_id": cve_id}, {"scope": "instance"}]},
)
cwe_hits = collection.query(
    query_texts=[clean_query(question)], n_results=2,
    where={"$and": [{"cwe_id": {"$in": cwe_ids}}, {"scope": "type"}]},
)
```

여기에 더해 **같은 섹션이 결과를 독점하지 않도록** 후보를 3배로 받아
섹션마다 하나씩 먼저 고릅니다. 구현 중 실제로 이런 문제가 있었습니다.

> "당장 업그레이드가 어렵습니다. 임시 우회책이 있나요?"라고 물었는데
> 제품 목록·버전 범위 청크가 상위 3개를 모두 차지하고, 정작 답인
> Red Hat `mitigation` 청크(`log4j2.formatMsgNoLookups`)가 밀려났습니다.
> 거리 차이는 0.759 대 0.782로 근소했지만, 목록성 청크가 **개수로** 눌러버린 것입니다.

그래서 목록성 데이터는 청크를 잘게 쪼개지 않고 하나로 압축했고(1단계 청킹),
검색에서는 섹션 다양성을 확보했습니다(3단계). 두 조치 후 우회책 청크가
정상적으로 검색되고 답변에도 반영됩니다.

**한 번에 섞어서 상위 5개를 뽑지 않는 이유:**

- 어드바이저리 본문에는 제품명·버전·CVE 번호가 반복되어, 질문에 그런 단어가
  섞이면 상위를 독점합니다. 반대로 CWE 문서 수가 훨씬 많아 일반적인 질문에서는
  CWE가 독점하기도 합니다. 어느 쪽이든 한쪽만 남습니다.
- 좋은 답은 **두 종류가 모두** 필요합니다.
  어드바이저리 = "무엇을 해야 하나", CWE = "왜 그런가, 근본 예방책은".
- 쿼터를 고정하면 질문이 어떻든 두 관점이 항상 답에 들어옵니다.

### 검색어에서 CVE ID 제거 (1단계의 교훈 계승)

1단계에서 확인한 문제입니다. 질문에 CVE ID가 들어 있으면
CVE 번호가 나열된 섹션과 글자만 매칭되어 엉뚱한 결과가 나옵니다.

| 검색어 | 결과 |
|---|---|
| `CVE-2021-44228은 개발자가 어떻게 예방하나요?` | observed_examples (거리 0.495~0.514) |
| `은 개발자가 어떻게 예방하나요?` | potential_mitigations (거리 0.686~0.711) |

CVE ID는 이미 메타데이터 필터로 쓰이므로 의미 검색에는 넘기지 않습니다.
2단계는 어드바이저리 본문에도 CVE 번호가 많아 이 처리가 **더 중요합니다.**

### 버전 판정은 벡터 검색으로 하지 않습니다

**반드시 지켜야 할 설계 원칙입니다.**

"우리는 2.14.1을 쓰는데 영향받나요?"는 의미 검색으로 답할 수 없습니다.
2.14.1과 2.15.0은 임베딩 공간에서 거의 같은 위치에 있어서, LLM이 근거를
잘못 읽으면 안전한 버전을 취약하다고 하거나 그 반대로 말할 수 있습니다.

그래서 버전 판정은 **OSV의 구조화 필드로 정확히 계산**해 그 결과를
문장으로 만들어 프롬프트에 주입합니다.

```python
def check_version(cve_id: str, package: str, version: str) -> str:
    # introduced <= version < fixed 를 실제 버전 비교로 판정
    # 결과 예: "log4j-core 2.14.1은 영향받습니다. 2.15.0 이상으로 올리세요."
```

같은 이유로 EPSS·CVSS·KEV 기한 같은 숫자도 검색이 아니라
`cve_core.json`에서 그대로 읽어 프롬프트에 넣습니다.
**LLM이 숫자를 지어내지 않게 하는 가장 확실한 방법은 계산을 맡기지 않는 것입니다.**

### 역방향 조회: 유형 → CVE

기본 방향은 `CVE ID → 정보`지만, 반대 방향 질문도 자주 나옵니다.

> "SQL injection 관련 CVE가 뭐야?"

이건 CVE ID가 없어서 정방향 경로로는 답할 수 없습니다. 그래서 별도 경로를 둡니다.

```
질문 → CWE 청크(scope=type) 의미 검색 → CWE-89
     → cve_core에서 CWE-89를 가리키는 CVE 찾기 (구조화 조회)
     → NVD에 cweId=CWE-89로 전체 건수 조회 (범위 명시용)
```

키워드 표를 따로 만들지 않고 **이미 색인해둔 CWE 문서를 사전처럼** 씁니다.
"SQL injection"이라는 자연어를 CWE-89로 옮기는 일을 기존 RAG가 그대로 해줍니다.

**범위를 반드시 밝힙니다.** 수집된 CVE는 수십 건뿐이라 대표성이 없습니다.

```
### CWE-89 — Improper Neutralization ... ('SQL Injection')
수집된 데이터에서 1건 찾았습니다.
- CVE-2026-9586 (CVSS 9.8 · KEV 등재)
> 참고: NVD 전체에는 이 유형의 CVE가 11,585건 있습니다.
```

"1건입니다"만 답하면 그게 더 잘못된 답입니다.

### 대화 맥락 이어받기

역방향 조회를 넣으면 자연스럽게 2턴 대화가 됩니다.

```
1턴  "SQL injection 관련 CVE가 뭐야?"  → CVE-2026-9586
2턴  "그거 어떻게 막아?"                → 이 CVE를 이어받아야 함
```

`chat_fn`이 대상 CVE를 정하는 **순서**가 중요합니다.

| 순서 | 조건 | 동작 |
|---|---|---|
| 1 | 메시지에 CVE ID가 있음 | 그것을 사용 |
| 2 | '유형 → CVE' 의도가 감지됨 | 역방향 조회 |
| 3 | 직전 대화에 CVE가 있음 | **이어받기** |
| 4 | 그 외 | 사용법 안내 |

**2를 3보다 먼저 두는 이유**: Log4Shell을 얘기하다가 "SQL injection CVE 알려줘"라고
물으면, 이어받기가 먼저 걸릴 경우 엉뚱하게 Log4Shell을 계속 붙들게 됩니다.

**전역 변수가 아니라 history를 쓰는 이유**
- gradio가 매 호출마다 기록을 넘겨주므로 추가 비용이 0입니다.
- 기록이 곧 진실이라, 사용자가 재시도·되돌리기를 눌러도 동작이 따라갑니다.
- 전역 변수는 `--share`로 여러 사람이 접속하면 **서로의 CVE를 덮어씁니다.**

**답변 본문의 CVE 번호를 집으면 안 됩니다.** 답변에는 CWE '실제 사례' 섹션이
딸려오는데 거기에 무관한 CVE 번호가 잔뜩 있습니다(`CVE-2020-9054: ...`).
그래서 답변 첫 줄에 표식을 남기고 그것만 읽습니다.

```
**대상 CVE: CVE-2026-9586** (직전 대화에서 이어받음 — 다른 CVE라면 ID를 직접 적어주세요)
```

이 줄은 사람에게도 보이므로, 엉뚱한 CVE를 짚었을 때 바로 알아챌 수 있습니다.
보안 도구가 조용히 추측해서 다른 CVE의 조치를 안내하면 위험하기 때문입니다.

**여러 건이면 자동으로 고르지 않습니다.** 역방향 조회 결과가 2건 이상이면
"그거"가 모호하므로 표식을 남기지 않고 사용자에게 지정을 요청합니다.

### 프롬프트 구성

```
<위험도>            ← cve_core.json에서 그대로 (계산 결과)
  CVSS 10.0 CRITICAL / EPSS 0.99999 (상위 100%)
  CISA KEV 등재됨 · 랜섬웨어 악용 확인 · 조치 기한 2021-12-24

<버전 판정>         ← check_version() 결과 (계산 결과)
  log4j-core 2.14.1은 영향받습니다. 2.15.0 이상으로 올리세요.

<벤더 어드바이저리>  ← 벡터 검색 결과 3개
<취약점 유형 설명>   ← 벡터 검색 결과 2개
```

계산으로 얻은 사실과 검색으로 얻은 근거를 **구획을 나눠** 넣습니다.
LLM에게는 "위험도와 버전 판정은 확정된 사실이니 그대로 전달하고,
설명은 아래 근거 안에서만 하라"고 지시합니다.

---

## 1단계에서 가져온 것

아래는 [../security_rag/src](../security_rag/src)에서 검증된 코드를
`src/common.py`에 모아 재사용합니다. 1단계 모듈을 직접 import하지 않는 이유는,
그쪽 코드의 경로가 `security_rag/data`로 박혀 있어 그대로 쓰면 이 프로젝트가
아니라 1단계의 데이터를 읽고 쓰기 때문입니다.

- `build_embedding_function()` — 임베딩 백엔드 3종 교체 구조
- `TfidfEmbeddingFunction` 등 임베딩 함수 클래스
- `split_long_section()` — 줄 경계 분할
- `clean_query()` — 검색어에서 CVE ID 제거
- `extract_cve_id()` — 문장에서 CVE ID 정규식 추출
- 백엔드 불일치 검사 (`embedding_config.json`)
- gradio 챗봇 UI 골격 (`chat_fn`, `launch_ui`)

## 새로 만들어야 하는 것

- `0_fetch_advisories.py` — OSV / Red Hat / KEV / EPSS 수집
- 소스 유형별 청킹 분기
- `scope` 메타데이터와 쿼터 기반 이중 질의
- `check_version()` — 버전 범위 판정
- 부분 갱신(`collection.delete(where=...)`)
- 계산 결과와 검색 근거를 구획으로 나눈 프롬프트

---

## 한계와 주의

1. **벤더 커버리지가 고르지 않습니다.** OSV는 오픈소스 패키지(Maven, npm, PyPI 등)에
   강하고 Red Hat은 자사 제품만 다룹니다. 상용 폐쇄 소프트웨어나 IoT 펌웨어는
   어느 API에도 구조화된 데이터가 없어, NVD 참조 URL만 남습니다.
   그런 CVE는 1단계와 같은 CWE 기반 답변으로 자동 축소(fallback)됩니다.

2. **어드바이저리는 시점 데이터입니다.** 오늘 "패치 없음"이던 것이 내일 바뀝니다.
   모든 청크에 `fetched_at`을 남기고 답변에도 함께 표시해, 사용자가
   정보의 신선도를 판단할 수 있게 합니다. 오래된 데이터는 재수집을 권고합니다.

3. **EPSS는 확률이지 사실이 아닙니다.** "악용 확률 0.97"은 높은 위험 신호일 뿐
   실제 공격을 받았다는 뜻이 아닙니다. 반대로 KEV 등재는 **확인된 사실**입니다.
   프롬프트에서 이 둘을 명확히 구분해 표현해야 합니다.

4. **이 시스템은 판단을 보조할 뿐 대체하지 않습니다.** 실제 패치 적용 여부는
   운영 환경, 호환성, 서비스 영향을 함께 봐야 하는 결정입니다.
   답변에는 항상 원본 어드바이저리 링크를 함께 제시해 사람이 확인하도록 합니다.

5. **NVD rate limit.** API 키가 없으면 요청 간 6초를 쉬어야 합니다.
   CVE를 수백 건 수집하려면 [무료 키](https://nvd.nist.gov/developers/request-an-api-key)를
   발급받아 `.env`에 `NVD_API_KEY=...` 또는 `NVD_KEY=...`로 넣어두세요
   (두 이름 모두 인식합니다).
