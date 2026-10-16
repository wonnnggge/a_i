"""
3단계(대안): 소프트 라우팅 검색 — 3_query.py와 비교하기 위한 구현

3_query.py와 무엇이 다른가
--------------------------
3_query.py는 **하드 게이트** 방식이다. 질문에서 CVE ID를 못 찾으면 검색을
시작하지도 않고 "CVE ID를 적어주세요"로 끝난다. 의도 분류가 사실상
접근 권한처럼 작동한다.

    문제 사례: "Can you describe about CWE-1021?"
      -> CWE 번호가 있으니 'CVE 목록 요청'으로 분류
      -> "수집된 데이터에는 이 유형의 CVE가 없습니다"
      -> 그런데 CWE-1021 문서는 4개 청크로 멀쩡히 색인돼 있었다.
         데이터가 없어서가 아니라 라우팅이 막은 것이다.

4_query.py는 **소프트 라우팅**이다. 분류는 정확도를 높이는 최적화일 뿐,
접근 조건이 아니다. 의도를 못 잡아도 거절하지 않고 세 카테고리를 넓게
검색해서 답한다.

    1. 구조화 신호(CVE ID, CWE 번호, 버전)를 먼저 본다 -> 정확 조회
    2. 의도가 잡히면 전용 경로로 (목록 요청 / 유형 설명 / CVE 대응)
    3. 못 잡아도 차단하지 않고 전 카테고리를 쿼터로 검색
    4. "이렇게 이해했다"를 밝히고 다른 해석 경로를 함께 제안

왜 '전부 벡터 검색'이 답은 아닌가 (실측 근거)
---------------------------------------------
"세 카테고리를 다 색인했으니 그냥 다 검색하면 되지 않나"는 자연스러운
발상이지만, 실제로 돌려보면 안 되는 것들이 있다.

  [실험1] "describe CWE-1021" 무필터 검색
          -> CWE-225, CWE-217, CWE-866... CWE-1021은 top-5에 없음
          임베딩은 'CWE-1021'과 'CWE-225'를 비슷한 토큰으로 본다.
          ID 정확 조회는 유사도 문제가 아니다.

  [실험4] 같은 문서를 개념으로 검색("rendered UI layers frames clickjacking")
          -> CWE-1021이 1·2·3위 독점 (0.335~0.362)
          색인은 멀쩡하다. 질의의 '종류'가 문제였을 뿐이다.

  [실험2] "SQL injection 관련 CVE가 뭐야?" 무필터 검색
          -> CWE-89의 observed_examples가 1위.
          거기 적힌 CVE 번호는 MITRE의 과거 예시이지 우리가 수집한 목록이 아니다.
          열거(목록·개수)는 유사도로 답할 수 없다.

  [실험3] "어떤 버전으로 올려야 하나요?" 무필터 검색
          -> 1위는 Log4Shell이지만 4·5위에 무관한 CVE의 수정 패키지가 섞임
             (0.663 대 0.679로 근소)
          범위 필터를 빼면 다른 CVE의 조치를 섞어 안내하게 된다.

그래서 이렇게 나눈다.

    어느 문서를 찾을까  -> 벡터 검색 (넓게, 쿼터로)      ... 확장 가능
    어떤 연산을 할까    -> 구조화 조회 / 계산            ... 검색으로 대체 불가
      - ID 정확 조회 (CWE-1021)  -> 카탈로그 사전 조회
      - 목록·개수                -> cve_core 훑기
      - 버전 판정                -> 버전 비교 계산
      - 범위 제한                -> 메타데이터 필터

3_query.py와 부품을 공유한다
----------------------------
비교가 공정하려면 바뀐 변수가 '라우팅' 하나여야 한다. 그래서 계산·검색
부품(check_version, format_risk, _query, cves_for_cwe 등)은 3_query.py의 것을
그대로 가져다 쓰고, 이 파일은 라우팅과 답변 구성만 새로 짠다.

3_query.py의 기능 셋을 여기에 옮길 때 (중요)
--------------------------------------------
3_query.py에 나중에 추가한 세 기능을 이 파일에도 넣었다. 다만 **분기로
옮기지 않았다.** 그렇게 하면 소프트 라우팅이 하드 라우팅으로 되돌아가
두 파일을 비교하는 의미가 사라진다. 대신 이렇게 나눠 넣었다.

    3_query.py의 방식              4_query.py에서는
    --------------------------     ----------------------------------------
    if asks_by_product(msg):       extract_signals에 product 신호를 하나 더
        return answer_product(...)   collect_facts가 그 결과를 사실로 담는다
    if has_description_intent():   유사도가 높으면 대상으로 삼고,
        return answer_desc(...)      애매하면 후보로만 보여주고 계속 진행

핵심 차이는 **판단하는 위치**다. 3_query는 입구에서 판단해 못 넘으면
거절했고, 여기서는 일단 다 해보고 출구에서 확신도를 붙여 보여준다.
예를 들어 설명 검색은 유사도 0.70 이상이면 대상으로 확정하고, 그 아래면
'확정 아님'이라고 써서 후보만 보여준 뒤 넓은 검색으로 답을 만든다.

3_query.py에는 있지만 여기에 옮기지 않은 것도 있다. '설명 -> CWE' 분기와
'이 CVE의 CWE는?' 분기다. 소프트 라우팅에서는 guess_cwes와 core_for가
이미 같은 일을 하므로 분기를 더할 이유가 없다.

사용 예:
    python src/4_query.py "Can you describe about CWE-1021?"
    python src/4_query.py "SQL injection 관련 CVE가 뭐야?"
    python src/4_query.py "CVE-2021-44228 우리는 2.14.1을 씁니다"
    python src/4_query.py "웹 프레임 관련 취약점이 뭔가요?"     # 신호 없음 -> 넓은 검색
    python src/4_query.py "mit kerberos 관련된 CVE가 있나요?"   # 제품 -> NVD 실시간
    python src/4_query.py --ui

    # 3_query.py와 동시에 띄워 비교하려면 포트를 다르게 준다
    GRADIO_SERVER_PORT=7861 python src/4_query.py --ui
"""
import os
import re
import sys
from importlib import import_module
from pathlib import Path

import common

sys.path.insert(0, str(Path(__file__).parent))
# 계산·검색 부품 재사용. 라우팅만 다르게 하려는 것이므로 아래 함수들은
# 3_query.py의 것을 그대로 쓴다.
q3 = import_module("3_query")

CHAT_MODEL = os.getenv("CHAT_MODEL", "gpt-4.1-nano")

# 검색 쿼터. 신호가 있으면 그쪽에 더 많이 배분한다.
QUOTA_ADVISORY = 3
QUOTA_CWE = 3

# 설명을 보고 CVE를 '대상으로 확정'할 유사도 기준.
#
# 3_query.py에서 실측한 값을 그대로 쓴다.
#     붙여넣은 설명이 실제 그 CVE일 때   0.869
#     비슷하지만 수집 데이터에 없을 때    0.598
#     전혀 무관할 때                     0.120
#
# 3_query.py는 이 값을 '거절할지' 판단하는 데 썼다. 여기서는 '대상으로
# 삼을지'를 판단하는 데 쓴다. 기준에 못 미쳐도 거절하지 않고, 후보로만
# 보여주고 넓은 검색으로 답을 만든다. 같은 숫자를 반대 방향으로 쓰는 셈이다.
DESC_ADOPT = q3.DESCRIPTION_STRONG   # 0.70
DESC_TOP_K = 3

# 제품 이름으로 NVD를 실시간 조회할 때 보여줄 건수.
PRODUCT_NVD_MAX = 5

# 유형 '추정'을 믿을 수 있는 거리의 한계.
#
# 소프트 라우팅의 가장 큰 위험은 거절이 아니라 **틀린 유형을 확신하며 설명하는
# 것**이다. 3_query.py는 모르면 거절했지만, 이 파일은 항상 답하므로 잘못 짚으면
# 엉뚱한 취약점을 자신 있게 설명하게 된다. 그래서 확신도를 함께 봐야 한다.
#
# 다행히 거리가 신호를 준다. 실측한 값이다.
#     "deserialization of untrusted data" -> CWE-502  0.241  (정답)
#     "clickjacking"                      -> CWE-1021 0.484  (정답)
#     "역직렬화가 왜 위험한가요?"           -> CWE-787  0.719  (오답)
#     "웹 페이지가 프레임에 갇히는 문제"     -> CWE-830  0.639  (오답)
#
# 맞을 때는 0.5 아래, 틀릴 때는 0.6 위로 갈렸다. 한국어 질의가 영문 CWE 문서와
# 잘 안 맞아서 생기는 현상이다(문서가 전부 MITRE 원문 영어다).
# 표본이 작으므로 절대적인 값은 아니고, 데이터가 바뀌면 조정해야 한다.
GUESS_DISTANCE_LIMIT = 0.60

# 'CVE 목록을 달라'는 열거 요청인지 판단. 열거는 벡터 검색으로 답할 수 없어
# 구조화 조회로 넘겨야 하므로, 이 판단만은 명시적으로 한다.
ENUMERATION_PATTERN = re.compile(
    r"(어떤|무슨|어떠한|관련된?|해당하는?|목록|리스트|몇\s*건|몇\s*개|which|what|list|how many)"
    r"[\s\S]{0,25}cve|cve[\s\S]{0,25}(목록|리스트|list|알려|찾아)",
    re.IGNORECASE,
)

# 사용자에게 보이는 문구. 질문 언어를 따라간다.
T4 = {
    "ko": {
        "target": "대상 CVE", "inherited": "직전 대화에서 이어받음",
        "specified": "지정된 유형", "guessed": "추정한 유형",
        "low_conf": "추정한 유형(신뢰도 낮음, 거리 {d:.2f})",
        "low_warn": "— 아래 답이 질문과 맞지 않으면 무시하세요",
        "version_in": "입력 버전", "no_signal": "신호 없음 — 전체 문서에서 넓게 검색했습니다",
        "risk_block": "위험도(조회된 사실) — ", "verdict_block": "버전 판정(계산된 사실) — 입력",
        "list_block": "CVE 목록(구조화 조회) — ",
        "sources": "검색된 근거 보기", "advisory": "어드바이저리",
        "weakness": "취약점 유형", "distance": "거리",
        "next": "이어서 해볼 수 있는 것",
        "s_list": "이 유형의 CVE 목록: `{c} 관련 CVE 목록`",
        "s_version": "쓰는 버전을 알려주시면 영향 여부를 정확히 판정합니다",
        "s_specify": "유형이 다르면 번호로 지정하세요 (예: `{c}이 뭐야?`)",
        "s_english": "영어 용어로 물어보면 훨씬 잘 찾습니다 (예: `deserialization of untrusted data`)",
        "s_bynum": "유형을 아신다면 번호로 지정하세요 (예: `CWE-502가 뭐야?`)",
        "found": "수집된 데이터에서 {n}건",
        "nvd_total": "({c}는 NVD 전체로는 {n:,}건)",
        "no_facts": "(확정된 사실 없음)",
        "skip": "답변 생성을 건너뜁니다",
        # 설명 -> CVE
        "from_desc": "설명으로 찾음, 유사도 {s:.2f}",
        "desc_block": "설명이 비슷한 CVE(유사도 계산) — 확정 아님",
        "desc_none": "설명과 뚜렷하게 맞는 CVE를 수집 데이터에서 찾지 못했습니다.",
        "s_confirm": "위 후보 중 맞는 것이 있으면 CVE 번호로 다시 물어보세요",
        # 제품 -> CVE
        "product": "제품으로 이해",
        "product_block": "제품 이름으로 찾기(조회) — ",
        "product_local": "수집된 데이터에서 {n}건",
        "product_empty": "수집된 데이터에는 없습니다",
        "product_nvd": "NVD 전체로는 {n:,}건 (최근 순)",
        "product_nvd_none": "NVD에서도 찾지 못했습니다",
        "product_nvd_fail": "NVD 조회에 실패했습니다 (네트워크 또는 요청 제한)",
        "corpus": "이 앱이 수집한 CVE는 {n}건입니다. '없다'는 답은 그 범위 안에서의 이야기입니다.",
        "s_fetch": "필요하면 수집해서 색인할 수 있습니다: `python src/0_fetch_advisories.py --cve-ids <CVE-ID>`",
        # 대화 이어받기
        "version_inherited": "직전 대화에서 이어받음",
    },
    "en": {
        "target": "Target CVE", "inherited": "carried over from previous turn",
        "specified": "Specified weakness", "guessed": "Inferred weakness",
        "low_conf": "Inferred weakness (LOW CONFIDENCE, distance {d:.2f})",
        "low_warn": "— ignore the answer below if it does not match your question",
        "version_in": "Input version", "no_signal": "No signal — searched broadly across all documents",
        "risk_block": "Risk (looked up) — ", "verdict_block": "Version verdict (computed) — input",
        "list_block": "CVE list (structured lookup) — ",
        "sources": "Show retrieved evidence", "advisory": "Advisory",
        "weakness": "Weakness type", "distance": "distance",
        "next": "What you can try next",
        "s_list": "CVEs of this type: `list CVEs for {c}`",
        "s_version": "Tell me the version you run and I will judge exposure precisely",
        "s_specify": "If the weakness is different, give the number (e.g. `what is {c}?`)",
        "s_english": "English terms match much better (e.g. `deserialization of untrusted data`)",
        "s_bynum": "If you know the weakness, give its number (e.g. `what is CWE-502?`)",
        "found": "{n} found in the collected data",
        "nvd_total": "({c} has {n:,} CVEs in NVD overall)",
        "no_facts": "(no established facts)",
        "skip": "Skipping answer generation",
        # description -> CVE
        "from_desc": "matched by description, similarity {s:.2f}",
        "desc_block": "CVEs with similar descriptions (similarity) — not confirmed",
        "desc_none": "No clear match for this description in the collected data.",
        "s_confirm": "If one of the candidates above is right, ask again with its CVE ID",
        # product -> CVE
        "product": "Read as a product name",
        "product_block": "Lookup by product name — ",
        "product_local": "{n} found in the collected data",
        "product_empty": "Not in the collected data",
        "product_nvd": "{n:,} in NVD overall (most recent first)",
        "product_nvd_none": "Not found in NVD either",
        "product_nvd_fail": "NVD lookup failed (network or rate limit)",
        "corpus": "This app has collected {n} CVEs. \"Not found\" means not found within that set.",
        "s_fetch": "You can collect and index it: `python src/0_fetch_advisories.py --cve-ids <CVE-ID>`",
        # carrying context over
        "version_inherited": "carried over from previous turn",
    },
}

SYSTEM_PROMPT = """당신은 보안 취약점을 설명하고 대응을 돕는 실무 도우미입니다.

{language_directive}

아래 정보는 성격이 다릅니다. 다르게 다루세요.

1) <확정된 사실>은 API 조회와 계산으로 이미 확정된 값입니다.
   숫자나 판정을 바꾸거나 새로 추정하지 말고 그대로 전달하세요.
2) <검색된 근거>는 문서에서 찾아온 것입니다. 설명은 이 안에서만 하세요.

답변 규칙:
- 초급 개발자도 이해할 수 있게 쉽게 설명하세요.
- 대응 조치를 물었다면 "지금 무엇을 해야 하는가"를 먼저, 구체적으로 답하세요.
- 취약점 유형을 물었다면 정의 → 왜 위험한가 → 어떻게 막는가 순으로 설명하세요.
- CISA KEV 등재는 실제 악용이 '확인된 사실', EPSS는 '확률 예측'입니다. 섞지 마세요.
- 설정 예시나 코드 조각을 임의로 지어내지 마세요. 문서에 있는 형태로만 전달하고,
  정확한 적용은 원본 문서를 확인하도록 안내하세요.
- 근거에 없는 내용은 없다고 말하세요.

<확정된 사실>
{facts}

<검색된 근거>
{context}
"""


# --------------------------------------------------------------------------
# 1단계: 구조화 신호 추출
# --------------------------------------------------------------------------

# 실시간 조회 결과를 프로세스 안에서만 재사용한다. 같은 CVE를 두 번 물었을 때
# NVD를 또 부르지 않기 위해서다. 파일로 저장하지 않는 이유는 3_query.py의
# fetch_cve_live() 주석 참고(색인 상태를 예측 가능하게 유지하기 위함).
_live_core_cache: dict[str, dict | None] = {}


def core_for(cve_id: str | None) -> dict | None:
    """CVE의 확정 사실(위험도)을 얻는다. 수집 데이터에 없으면 NVD 실시간 조회.

    3_query.py와 같은 함수를 쓴다. 두 파일의 차이는 **라우팅 하나여야** 비교가
    공정하기 때문에, 데이터 접근 능력은 동일하게 맞춘다.
    """
    if not cve_id:
        return None
    cores = q3.load_cve_core()
    if cve_id in cores:
        return cores[cve_id]
    if cve_id not in _live_core_cache:
        _live_core_cache[cve_id] = q3.fetch_cve_live(cve_id)
    return _live_core_cache[cve_id]


def extract_signals(message: str, history=None) -> dict:
    """질문에서 '정확히 처리할 수 있는 신호'를 먼저 뽑는다.

    벡터 검색에 넘기기 전에 이걸 먼저 하는 이유:
      CVE ID나 CWE 번호, 버전 문자열은 **정확히 일치시켜야 하는 값**이다.
      임베딩은 CWE-1021과 CWE-225를 구별하지 못하므로(실측), 이런 값은
      검색이 아니라 조회·계산으로 처리해야 한다.

    돌려주는 신호:
      cve_id       -- 메시지에 적힌 CVE ID (없으면 직전 대화에서 이어받음)
      inherited    -- CVE를 이어받은 것인지 여부 (답변에 밝혀야 한다)
      cwe_ids      -- 메시지에 직접 적힌 CWE 번호들
      version      -- "2.14.1" 같은 버전 문자열 (없으면 직전 대화에서 이어받음)
      version_from -- 버전을 이어받은 것인지 여부
      enumeration  -- 'CVE 목록을 달라'는 요청인지
      product      -- 제품 이름으로 보이는 말 (없으면 None)
      description  -- 설명을 붙여넣은 질문인지

    여기서는 '뽑기'만 한다:
      조회나 검색은 하지 않는다. 신호 추출은 값싸야 매 턴 부담 없이 돌릴 수
      있다. 실제 조회(NVD 호출, 임베딩)는 확정 사실을 모으는 단계에서 한다.
    """
    cve_id = common.extract_cve_id(message)
    inherited = False
    if cve_id is None and history:
        cve_id = q3.cve_from_history(history)
        inherited = cve_id is not None

    # 버전도 이어받는다. "CVE-2021-44228, 우리는 2.14.1을 씁니다" 다음 턴에
    # "그럼 몇으로 올려야 하나요?"라고 물으면 메시지에 버전이 없다.
    # 되찾지 않으면 사용자가 같은 말을 반복해야 한다.
    #
    # 다만 **대상이 바뀌었으면 이어받지 않는다.** 사용자가 이번 메시지에
    # 새 CVE 번호를 적었다면 다른 제품 이야기일 수 있는데, 앞 대화의 버전을
    # 끌고 오면 엉뚱한 제품의 버전으로 영향 판정을 내리게 된다.
    # 판정은 계산이라 확신에 차서 출력되므로, 틀리면 알아차리기 어렵다.
    # 모르면 다시 묻는 편이 낫다(아래 s_version 제안이 그 역할을 한다).
    # 버전은 stated_version으로 뽑는다. extract_version이 아니다.
    #   붙여넣은 설명 본문에 적힌 영향 범위("2.0-beta9 through 2.15.0")를
    #   사용자가 쓰는 버전으로 오해하지 않기 위한 것이다. 자세한 근거는
    #   3_query.py의 stated_version() 주석 참고. 이것도 공유 부품이다.
    description = has_description(message)
    version = q3.stated_version(message)
    version_from = False
    if version is None and history and cve_id is not None and inherited:
        version = q3.version_from_history(history)
        version_from = version is not None

    return {
        "cve_id": cve_id,
        "inherited": inherited,
        "cwe_ids": list(dict.fromkeys(
            f"CWE-{m.group(1)}" for m in q3.CWE_PATTERN.finditer(message))),
        "version": version,
        "version_from": version_from,
        "enumeration": bool(ENUMERATION_PATTERN.search(message)),
        "product": product_signal(message, has_target=cve_id is not None),
        "description": description,
    }


def has_description(message: str) -> bool:
    """설명을 붙여넣은 질문인지 판단한다. **길이만** 본다.

    3_query.py와의 차이가 여기서 가장 잘 드러난다. 3_query는 세 조건을
    모두 요구했다.
        1. CWE 번호가 없을 것
        2. 'CVE'라는 말이 들어 있을 것   <- 이것이 하드 게이트다
        3. 설명으로 볼 만큼 길 것

    2번 때문에, 영문 설명을 붙여넣고 "이게 뭔가요?"라고만 물으면 설명 검색이
    아예 시작되지 않았다. 사용자가 'CVE'라는 단어를 쓸 줄 알아야 기능이
    열리는 셈이다. 여기서는 길이만 보고, 결과를 믿을지는 유사도로 정한다.
    **판단을 입구가 아니라 출구에서 한다.**
    """
    return len(q3.description_query(message)) >= q3.DESCRIPTION_MIN_CHARS


PRODUCT_ASK_PATTERN = re.compile(r"cve|cwe|취약점|vulnerab", re.IGNORECASE)


def product_signal(message: str, has_target: bool = False) -> str | None:
    """제품 이름으로 보이는 말을 뽑는다. 없으면 None.

    "mit kerberos 관련된 CVE 있나요?" -> "mit kerberos"
    "SQL injection 관련 CVE 있나요?"  -> None (유형 이름이므로 CWE 쪽 일이다)
    "어떻게 대응하나요?"               -> None (제품을 묻는 질문이 아니다)

    유형과 제품을 가르는 방법은 3_query.py와 같다. 이미 가진 CWE 카탈로그
    1,391개의 이름과 대조한다. 사전을 따로 만들지 않는 것이 요점이다.

    조건을 거는 이유 — 이것은 거절이 아니라 비용 절약이다:
      제품 조회는 NVD를 실시간으로 부른다. API 키가 없으면 요청 제한 때문에
      한 번에 6초를 쉬어야 한다. "어떻게 대응하나요?" 같은 후속 질문에서도
      조사를 걷어내면 "대응 방법" 같은 말이 남아 제품처럼 보이는데,
      그걸로 NVD를 부르면 6초를 버리고 무관한 결과를 얻는다.

      그래서 두 가지를 본다. (1) 취약점을 묻는 질문인가, (2) 이미 대상
      CVE가 정해졌는가. 정해졌다면 제품 조회는 잡음일 뿐이다.

      신호를 못 잡아도 답변이 막히지 않는다는 점이 3_query.py와 다르다.
      여기서는 넓은 검색이 그대로 돌아간다. **막는 조건이 아니라 켜는 조건이다.**
    """
    if has_target or common.extract_cve_id(message) or q3.CWE_PATTERN.search(message):
        return None
    if not PRODUCT_ASK_PATTERN.search(message):
        return None
    # 긴 설명을 붙여넣은 질문은 설명 검색이 맡는다. product_keyword는 짧은
    # 질문에서 조사를 걷어내려고 만든 것이라, 설명에 쓰면 앞 네 단어만
    # 잘라 와서("Google Chromium V8 contains") 제품 이름이 아닌 것을 만든다.
    if has_description(message):
        return None
    keyword = q3.product_keyword(message)

    # 영문이 들어 있는 낱말만 남긴다.
    #
    # is_weakness_term은 CWE 카탈로그(전부 영문)와 대조하므로, 한글 낱말은
    # 무엇이든 '유형이 아님' = '제품'으로 판정된다. 실제로 "웹 프레임 관련
    # 취약점이 뭔가요?"에서 "프레임"을 제품으로 읽고 NVD를 불렀다.
    # 유형을 묻는 질문인데 제품 조회로 6초를 버린 것이다.
    #
    # 영문을 요구하는 것이 마침 맞는 해법이다. NVD keywordSearch는 영문만
    # 검색한다. 한글 키워드로는 어차피 아무것도 못 찾는다.
    # 한글 제품명(예: "한컴오피스")은 이 규칙에 걸려 빠지는데, NVD에서
    # 한글로는 찾을 수 없으므로 실질적인 손해는 없다.
    latin = " ".join(w for w in keyword.split() if re.search(r"[A-Za-z]", w))
    if len(latin) < 3 or q3.is_weakness_term(latin):
        return None
    return latin


# --------------------------------------------------------------------------
# 2단계: 구조화 조회 (검색으로 대체할 수 없는 것들)
# --------------------------------------------------------------------------

def lookup_cwe(cwe_id: str) -> dict | None:
    """CWE 번호로 카탈로그에서 **정확히** 찾는다. 벡터 검색이 아니다.

    실험1이 보여준 것: "describe CWE-1021"을 벡터 검색하면 CWE-1021이
    top-5에도 안 든다. 임베딩에게 'CWE-1021'과 'CWE-225'는 비슷한 토큰이다.

    번호가 주어졌다면 사전에서 찾으면 될 일을 유사도로 풀 이유가 없다.
    """
    catalog = {c["cwe_id"]: c for c in common.read_json(common.CWE_CATALOG_PATH, [])}
    return catalog.get(cwe_id)


def guess_cwes(question: str, collection, top_k: int = 3) -> list[dict]:
    """질문이 가리키는 취약점 유형을 **의미 검색**으로 추정한다.

    번호가 없을 때 쓴다. 실험4가 보여준 것: 개념으로 물으면("rendered UI
    layers frames clickjacking") CWE-1021이 1·2·3위를 독점한다.
    같은 색인인데 질의 종류에 따라 결과가 갈린다.

    이미 색인해둔 CWE 문서가 '자연어 → CWE 번호' 사전 역할을 해준다.
    별도의 키워드 표를 만들 필요가 없다.
    """
    catalog = {c["cwe_id"]: c for c in common.read_json(common.CWE_CATALOG_PATH, [])}
    hits = q3._query(collection, question, where={"scope": "type"}, top_k=top_k)

    found, seen = [], set()
    for hit in hits:
        cid = hit["cwe_id"]
        if cid in seen:
            continue
        seen.add(cid)
        found.append({"cwe_id": cid,
                      "name": catalog.get(cid, {}).get("name", ""),
                      "distance": hit["distance"]})
    return found


def enumerate_cves(cwe_ids: list[str]) -> list[dict]:
    """해당 CWE를 가리키는 수집된 CVE를 **전부** 찾는다. 벡터 검색이 아니다.

    실험2가 보여준 것: "SQL injection 관련 CVE"를 벡터 검색하면 CWE-89의
    observed_examples가 나오는데, 거기 적힌 CVE는 MITRE가 예시로 적어둔
    과거 사례일 뿐 우리가 수집한 목록이 아니다. 그걸로 답하면 사용자가
    다시 물었을 때 "수집된 데이터에 없습니다"가 나온다.

    벡터 검색은 '비슷한 문서 k개'를 주지 '조건에 맞는 전부'를 주지 못한다.
    열거는 구조화 조회의 일이다.
    """
    rows = []
    for core in common.read_json(common.CVE_CORE_PATH, []):
        if any(cid in core["cwe_ids"] for cid in cwe_ids):
            rows.append(core)
    return sorted(rows, key=lambda c: -(c.get("cvss_score") or 0))


def lookup_product(keyword: str, want_nvd: bool, lang: str = "ko") -> str:
    """제품 이름으로 CVE를 찾는다. 수집 데이터를 먼저 보고, 없으면 NVD에 묻는다.

    이 기능이 필요한 이유:
      "mit kerberos 관련된 CVE 있나요?"에 이 앱은 "없습니다"라고 답했다.
      실제로는 CVE-2024-37370 등이 존재한다. 수집한 155건 안에 없었을 뿐이다.
      **'내 데이터에 없다'와 '세상에 없다'는 완전히 다른 말인데**, 사용자에게는
      구분 없이 전달됐다. 보안 도구에서 이 혼동은 조치를 미루게 만든다.

    그래서 답을 세 층으로 나눈다.
      1. 수집된 데이터에서 찾은 것      -- 이 앱이 설명까지 할 수 있는 것
      2. NVD 전체 건수와 최근 목록       -- 존재는 하지만 이 앱은 설명 못 하는 것
      3. 수집하는 방법                  -- 사용자가 직접 넘어갈 수 있는 길

    want_nvd가 False면 NVD를 부르지 않는 이유:
      키 없이 호출하면 요청 제한 때문에 6초를 쉬어야 한다. 수집 데이터에서
      이미 찾았다면 굳이 기다릴 이유가 없다.
    """
    t = T4[lang]
    lines = []

    local = q3.local_cves_by_keyword(keyword)
    if local:
        lines.append(t["product_local"].format(n=len(local)))
        for core in sorted(local, key=lambda c: -(c.get("cvss_score") or 0))[:10]:
            kev = " · KEV" if core.get("kev", {}).get("listed") else ""
            lines.append(f"- {core['cve_id']} (CVSS {core.get('cvss_score')}{kev})")
    else:
        lines.append(t["product_empty"])

    if want_nvd:
        total, recent = q3.nvd_keyword_search(keyword, PRODUCT_NVD_MAX)
        if total is None:
            lines.append(t["product_nvd_fail"])
        elif total == 0:
            lines.append(t["product_nvd_none"])
        else:
            lines.append("")
            lines.append(t["product_nvd"].format(n=total))
            for row in recent:
                lines.append(f"- {row['cve_id']} (CVSS {row['cvss_score']}) "
                             f"{row['description'][:110]}")

    lines.append("")
    lines.append(t["corpus"].format(n=len(q3.load_cve_core())))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 3단계: 넓은 검색 (분류에 실패해도 차단하지 않는다)
# --------------------------------------------------------------------------

def retrieve_broad(question: str, collection, cve_id: str | None = None,
                   cwe_ids: list[str] | None = None) -> dict:
    """세 카테고리를 각각 쿼터만큼 검색한다. 신호가 있으면 그 범위로 좁힌다.

    3_query.py와의 차이:
      3_query는 CVE ID가 있어야만 검색을 시작한다. 여기서는 신호가 없어도
      필터 없이 검색해서 뭐라도 답한다. 분류 실패가 거절이 되지 않게 하는
      것이 이 파일의 요점이다.

    신호가 있으면 왜 좁히나 (실험3):
      "어떤 버전으로 올려야 하나요?"를 필터 없이 검색하면 1위는 Log4Shell이지만
      4·5위에 무관한 CVE의 수정 패키지가 섞인다(0.663 대 0.679로 근소).
      보안 도구가 다른 CVE의 패치 버전을 섞어 안내하면 위험하므로,
      대상이 정해졌을 때는 반드시 범위를 건다.

    반환값: {"advisory": [...], "cwe": [...]}
    """
    result = {"advisory": [], "cwe": []}

    # 어드바이저리·KEV: CVE가 정해졌으면 그 CVE로 좁히고, 아니면 전체에서 찾는다.
    adv_where = ({"$and": [{"cve_id": cve_id}, {"scope": "instance"}]}
                 if cve_id else {"scope": "instance"})
    advisory = q3._query(collection, question, where=adv_where, top_k=QUOTA_ADVISORY)

    # CWE 유형 문서: 번호가 정해졌으면 그 번호로 좁히고, 아니면 전체에서 찾는다.
    if cwe_ids:
        cwe_where = {"$and": [{"cwe_id": {"$in": cwe_ids}}, {"scope": "type"}]}
    else:
        cwe_where = {"scope": "type"}
    cwe = q3._query(collection, question, where=cwe_where, top_k=QUOTA_CWE)

    # 관련성 게이트 — 넓게 검색할 때 반드시 필요한 장치.
    #
    # 실제로 겪은 문제: "Can you describe about CWE-1021?"처럼 CVE가 없는 유형
    # 질문에서, 어드바이저리 검색이 아무 데도 묶여 있지 않아 무관한 CVE의
    # CISA 조치문("벤더 지침에 따라 완화 조치를 적용하라")이 거리 0.52로
    # 딸려 왔다. 어느 취약점에나 해당하는 상투적인 문장이라 어느 질문에든
    # 어중간하게 걸린다.
    #
    # 규칙: CVE가 지정됐으면 어드바이저리는 그 CVE의 것이므로 그대로 믿는다.
    #       지정되지 않았으면, 어드바이저리가 CWE 문서보다 '더 가까울 때만'
    #       남긴다. 즉 질문이 실제로 사건 쪽을 향할 때만 통과시킨다.
    #
    # 넓게 검색하는 설계에는 이런 장치가 짝으로 있어야 한다. 범위를 넓히면
    # 놓치는 것은 줄지만 잡음이 늘기 때문이다.
    if cve_id is None and advisory and cwe:
        if advisory[0]["distance"] > cwe[0]["distance"]:
            advisory = []

    result["advisory"] = advisory
    result["cwe"] = cwe
    return result


# --------------------------------------------------------------------------
# 4단계: 확정된 사실 모으기
# --------------------------------------------------------------------------

def collect_facts(signals: dict, cwe_ids_used: list[str], lang: str = "ko",
                  desc_hits: list[dict] | None = None) -> tuple[str, list[str]]:
    """검색이 아니라 조회·계산으로 얻은 확정 사실을 모은다.

    반환값: (LLM 프롬프트에 넣을 글, 사용자에게 보여줄 블록 목록)

    이 값들을 벡터 검색에 넣지 않는 이유는 3_query.py와 같다. 숫자와 판정을
    LLM에게 계산시키지 않는 것이 가장 확실한 안전장치다.
    """
    t = T4[lang]
    lines, blocks = [], []

    cve_id = signals["cve_id"]
    # 수집 데이터에 없으면 NVD에서 실시간으로 가져온다(core_for 참고).
    core = core_for(cve_id)
    if core:
        risk = q3.format_risk(core, lang)
        lines.append(f"[대상 CVE {cve_id}의 위험도]\n{risk}")
        blocks.append(f"**{t['risk_block']}{cve_id}**\n\n```\n{risk}\n```")

        if signals["version"]:
            verdict, _ = q3.check_version(cve_id, signals["version"],
                                          q3.load_advisories(), lang)
            lines.append(f"[버전 판정] 입력 {signals['version']}\n{verdict}")
            blocks.append(f"**{t['verdict_block']} `{signals['version']}`**"
                          f"\n\n```\n{verdict}\n```")

    # 열거 요청이면 구조화 조회 결과를 사실로 넣는다.
    if signals["enumeration"] and cwe_ids_used:
        matched = enumerate_cves(cwe_ids_used)
        listing = [t["found"].format(n=len(matched))]
        for c in matched[:10]:
            kev = " · KEV" if c.get("kev", {}).get("listed") else ""
            listing.append(f"- {c['cve_id']} (CVSS {c.get('cvss_score')}{kev})")
        for cid in cwe_ids_used[:2]:
            total = q3.nvd_cve_count(cid)
            if total is not None:
                listing.append(t["nvd_total"].format(c=cid, n=total))
        text = "\n".join(listing)
        lines.append(f"[collected CVEs of this weakness type]\n{text}")
        blocks.append(f"**{t['list_block']}{', '.join(cwe_ids_used[:2])}**"
                      f"\n\n```\n{text}\n```")

    # 설명으로 찾은 후보들. 대상으로 확정하지 못한 경우에만 보여준다.
    # 확정했다면 위의 '위험도' 블록이 이미 그 CVE를 다루고 있다.
    if desc_hits and not signals.get("from_description"):
        listing = []
        for hit in desc_hits:
            listing.append(f"- {hit['cve_id']} (유사도 {hit['similarity']:.3f}, "
                           f"CVSS {hit['cvss_score']}) {hit['description'][:110]}")
        text = "\n".join(listing)
        # LLM에게 '후보일 뿐'이라고 분명히 적어준다. 그냥 넣으면 확정된
        # 사실처럼 읽고 "이것은 CVE-xxxx입니다"라고 단정해 버린다.
        lines.append("[similar CVE descriptions — CANDIDATES ONLY, not confirmed. "
                     "Do not state any of these as the answer; present them as possibilities.]\n"
                     + text)
        blocks.append(f"**{t['desc_block']}**\n\n```\n{text}\n```")

    # 제품 이름으로 찾기. NVD는 수집 데이터에서 못 찾았을 때만 부른다.
    if signals.get("product"):
        want_nvd = not q3.local_cves_by_keyword(signals["product"])
        text = lookup_product(signals["product"], want_nvd, lang)
        # 지시문을 함께 넣는 이유 — 실측한 실패다.
        #   확정 사실에 "NVD 전체로는 127건"을 넣었는데도 LLM은
        #   "MIT Kerberos 관련 CVE는 존재하지 않는 것으로 보입니다"라고 답했다.
        #   <검색된 근거>에 그 제품 이야기가 없으니 "근거에 없는 내용은 없다고
        #   말하세요"라는 규칙을 따른 것이다. 규칙끼리 부딪힌 셈이다.
        #
        #   고치려던 오류가 바로 이것이므로, 이 블록에서만 규칙을 명시적으로
        #   뒤집어 준다. '내 데이터에 없다'와 '세상에 없다'를 반드시 구분하게 한다.
        lines.append(
            f"[lookup by product name '{signals['product']}' — STRUCTURED LOOKUP, "
            f"authoritative. Overrides the retrieved-evidence rule for this product.\n"
            f" Answer in EXACTLY two parts, in this order:\n"
            f"  1. What THIS APP HAS COLLECTED. If none, say plainly that this app "
            f"has not collected any, and give the corpus size.\n"
            f"  2. What EXISTS IN NVD but is NOT collected here. Give the total count "
            f"and list the CVE IDs below. Say explicitly that these were looked up "
            f"live from NVD, that this app cannot explain them in detail because "
            f"they are not indexed, and link https://nvd.nist.gov/vuln/search .\n"
            f" NEVER say the product has no CVEs when an NVD count is shown. "
            f"NEVER call these 'retrieved evidence' — they came from a live NVD "
            f"lookup, not from the vector search.]\n{text}")
        blocks.append(f"**{t['product_block']}`{signals['product']}`**"
                      f"\n\n```\n{text}\n```")

    return ("\n\n".join(lines) or t["no_facts"]), blocks


# --------------------------------------------------------------------------
# 5단계: 답변 조립
# --------------------------------------------------------------------------

def generate(question: str, facts: str, hits: dict, history=None) -> str:
    """확정 사실과 검색 근거를 구획으로 나눠 LLM에 넘긴다.

    대화 기록을 함께 넘기는 이유:
      "방금 말한 조치를 더 풀어줘"는 직전 답변을 봐야 답할 수 있다.
      CVE ID 이어받기(extract_signals)만으로는 부족하다. 그건 '무엇에 대한
      이야기인가'만 알려주고, '무슨 이야기를 했는가'는 알려주지 않는다.

    그래도 사실은 매 턴 다시 계산한다:
      위험도와 버전 판정은 대화 기록이 아니라 system 프롬프트의 <확정된 사실>
      에서만 온다. 대화 기록은 맥락을 위한 것이지 **사실의 출처가 아니다.**
      LLM이 자기가 세 턴 전에 한 말을 근거로 삼게 두면 오류가 누적된다.

    기록은 그대로 넣지 않고 recent_turns()로 추린다. 이 앱의 답변 뒤에는
    '검색된 근거 보기' 블록이 길게 붙어서, 통째로 넣으면 토큰만 늘고
    새 질문의 신호가 묻힌다.
    """
    lang = common.detect_language(question)
    context = q3.format_context(hits["advisory"] + hits["cwe"])
    try:
        from openai import OpenAI
        common.load_env()
        # CHAT_BASE_URL 이 있으면 그 주소(예: 로컬 Ollama)로 보낸다. 없으면 OpenAI.
        client = OpenAI(base_url=os.getenv("CHAT_BASE_URL") or None)
        resp = client.chat.completions.create(
            model=os.getenv("CHAT_MODEL", CHAT_MODEL), temperature=0,
            messages=[{"role": "system",
                       "content": SYSTEM_PROMPT.format(
                           language_directive=q3.LANGUAGE_DIRECTIVE[lang],
                           facts=facts, context=context)},
                      *q3.recent_turns(history),
                      {"role": "user", "content": question}],
        )
        return resp.choices[0].message.content
    except Exception as error:
        return f"{T4[lang]['skip']} ({type(error).__name__}: {error})."


def is_low_confidence(cwe_used: list[dict], guessed: bool) -> bool:
    """유형을 '추정'했고 그 추정이 멀면 신뢰도가 낮다고 본다.

    번호로 지정된 경우(guessed=False)에는 확신도를 따질 필요가 없다.
    사전 조회라 정확하기 때문이다.
    """
    if not guessed or not cwe_used:
        return False
    best = cwe_used[0].get("distance")
    return best is not None and best > GUESS_DISTANCE_LIMIT


def describe_interpretation(signals: dict, cwe_used: list[dict],
                            guessed: bool, lang: str = "ko") -> str:
    """질문을 어떻게 이해했는지 밝힌다.

    3_query.py는 분류에 실패하면 거절했지만, 여기서는 넓게 검색해서라도
    답한다. 그러면 '왜 이런 답이 나왔는지'를 사용자가 알아야 하고, 해석이
    틀렸을 때 바로잡을 방법도 함께 줘야 한다. 추측했다는 사실을 숨기면
    사용자는 답이 정확한 줄로 오해한다.
    """
    t = T4[lang]
    parts = []
    if signals["cve_id"]:
        # 어디서 온 대상인지 세 가지로 나눠 밝힌다. 사용자가 적은 것,
        # 직전 대화에서 이어받은 것, 설명을 보고 우리가 고른 것은 신뢰도가
        # 다르다. 특히 세 번째는 틀릴 수 있으므로 반드시 표시해야 한다.
        mark = ""
        if signals.get("from_description"):
            mark = f" *({t['from_desc'].format(s=signals['desc_similarity'])})*"
        elif signals["inherited"]:
            mark = f" *({t['inherited']})*"
        parts.append(f"**{t['target']}: {signals['cve_id']}**{mark}")
    if signals.get("product"):
        parts.append(f"**{t['product']}: `{signals['product']}`**")
    if cwe_used:
        names = ", ".join(f"{c['cwe_id']}({c['name'][:34]})" for c in cwe_used[:2])
        if not guessed:
            parts.append(f"**{t['specified']}: {names}**")
        elif is_low_confidence(cwe_used, guessed):
            # 확신이 없으면 반드시 밝힌다. 틀린 유형을 확신하며 설명하는 것이
            # 이 방식의 가장 큰 위험이므로, 사용자가 답을 걸러 읽을 수 있어야 한다.
            label = t["low_conf"].format(d=cwe_used[0]["distance"])
            parts.append(f"⚠️ **{label}: {names}** {t['low_warn']}")
        else:
            parts.append(f"**{t['guessed']}: {names}**")
    if signals["version"]:
        mark = f" *({t['version_inherited']})*" if signals.get("version_from") else ""
        parts.append(f"**{t['version_in']}: {signals['version']}**{mark}")
    if not parts:
        parts.append(f"**{t['no_signal']}**")
    return " · ".join(parts)


def answer(message: str, history=None, collection=None) -> str:
    """소프트 라우팅으로 질문 하나를 처리한다. 어떤 경우에도 거절하지 않는다.

    흐름:
      1. 구조화 신호 추출 (CVE ID / CWE 번호 / 버전 / 열거 요청)
      2. CWE 번호가 있으면 사전 조회, 없으면 의미 검색으로 추정
      3. 확정 사실 모으기 (위험도 · 버전 판정 · CVE 목록)
      4. 세 카테고리를 쿼터로 검색 (신호가 있으면 그 범위로)
      5. 해석 설명 + LLM 답변 + 확정 사실 + 근거 + 다음 행동 제안

    3_query.py라면 1번에서 CVE ID가 없을 때 바로 끝났을 것이다.
    여기서는 신호가 하나도 없어도 4번으로 내려가 뭐라도 답한다.
    """
    collection = collection or q3.get_collection()
    signals = extract_signals(message, history)

    # 설명만 주어졌으면, 그 설명과 가장 비슷한 CVE를 찾아 본다.
    #
    # 유사도가 충분히 높으면 대상으로 삼고, 애매하면 후보로만 보여준다.
    # 어느 쪽이든 **거절하지 않는다.** 못 찾아도 아래 넓은 검색으로 내려간다.
    # 3_query.py는 여기서 확신이 없으면 "CVE ID를 적어주세요"로 끝났다.
    desc_hits = []
    if signals["cve_id"] is None and signals["description"]:
        desc_hits = q3.find_cves_by_description(message, DESC_TOP_K)
        if desc_hits and desc_hits[0]["similarity"] >= DESC_ADOPT:
            signals["cve_id"] = desc_hits[0]["cve_id"]
            signals["from_description"] = True
            signals["desc_similarity"] = desc_hits[0]["similarity"]

    # 대상 CWE 정하기: 번호가 있으면 정확 조회, 없으면 추정
    guessed = False
    if signals["cwe_ids"]:
        cwe_used = []
        for cid in signals["cwe_ids"]:
            entry = lookup_cwe(cid)
            cwe_used.append({"cwe_id": cid,
                             "name": entry["name"] if entry else "(카탈로그에 없음)"})
    else:
        cwe_used = guess_cwes(message, collection)
        guessed = True

    # CVE가 정해졌으면 그 CVE가 가리키는 CWE를 우선한다 (더 정확한 근거).
    core = core_for(signals["cve_id"])
    if core:
        core_cwes = core["cwe_ids"]
        if core_cwes:
            cwe_used = [{"cwe_id": c, "name": (lookup_cwe(c) or {}).get("name", "")}
                        for c in core_cwes]
            guessed = False

    # 질문한 언어를 따라간다. 답변뿐 아니라 아래 라벨·판정·제안도 함께 바뀐다.
    lang = common.detect_language(message)
    t = T4[lang]

    cwe_ids_used = [c["cwe_id"] for c in cwe_used]
    facts_text, fact_blocks = collect_facts(signals, cwe_ids_used, lang, desc_hits)
    hits = retrieve_broad(message, collection,
                          cve_id=signals["cve_id"], cwe_ids=cwe_ids_used)

    parts = [describe_interpretation(signals, cwe_used, guessed, lang), "\n\n",
             generate(message, facts_text, hits, history)]

    if fact_blocks:
        parts.append("\n\n---\n" + "\n\n".join(fact_blocks))

    parts.append(f"\n\n<details><summary>{t['sources']}</summary>\n")
    for c in hits["advisory"]:
        parts.append(f"\n**{t['advisory']} · {c['cve_id']} · {c['vendor']} · "
                     f"{c['section']}** ({t['distance']} {c['distance']:.3f})\n\n"
                     f"> {c['text'][:350]}...\n")
    for c in hits["cwe"]:
        parts.append(f"\n**{t['weakness']} · {c['cwe_id']} · {c['section']}** "
                     f"({t['distance']} {c['distance']:.3f})\n\n> {c['text'][:350]}...\n")
    parts.append("\n</details>")

    # 다른 해석 경로 제안. 해석이 틀렸을 때 사용자가 바로 방향을 바꿀 수 있게 한다.
    suggestions = []
    if desc_hits and not signals.get("from_description"):
        # 설명으로 찾았지만 확신이 없었다. 사용자가 후보를 보고 고르면 된다.
        suggestions.append(t["s_confirm"])
    if signals.get("product"):
        suggestions.append(t["s_fetch"])
    if not signals["cve_id"] and cwe_ids_used:
        suggestions.append(t["s_list"].format(c=cwe_ids_used[0]))
    if signals["cve_id"] and not signals["version"]:
        suggestions.append(t["s_version"])
    if is_low_confidence(cwe_used, guessed):
        # 한국어 개념 질의는 영문 CWE 문서와 잘 안 맞는다(실측). 사용자가
        # 바로 시도할 수 있는 대안을 알려준다. 영어로 물은 경우에는 이미
        # 영어이므로 이 제안이 뜨는 일이 드물다.
        suggestions.append(t["s_english"])
        suggestions.append(t["s_bynum"])
    elif guessed and cwe_ids_used:
        suggestions.append(t["s_specify"].format(c=cwe_ids_used[0]))
    if suggestions:
        parts.append(f"\n\n**{t['next']}**\n" +
                     "".join(f"\n- {s}" for s in suggestions))
    return "".join(parts)


# --------------------------------------------------------------------------
# 챗봇 / 명령줄
# --------------------------------------------------------------------------

_collection_cache = None


def chat_fn(message: str, history) -> str:
    global _collection_cache
    # 3_query.py의 live_collection()이 재색인으로 죽은 핸들을 알아서 다시 연다.
    _collection_cache = q3.live_collection(_collection_cache)
    return answer(message, history, _collection_cache)


def launch_ui(share: bool = False) -> None:
    """gradio 챗봇을 띄운다.

    3_query.py와 동시에 비교하려면 포트를 다르게 준다:
        GRADIO_SERVER_PORT=7861 python src/4_query.py --ui
    """
    global _collection_cache
    import gradio as gr

    _collection_cache = q3.get_collection()
    print(f"벡터 DB 준비 완료: {_collection_cache.count()}개 청크")
    print(f"답변 생성 모델: {CHAT_MODEL}  /  라우팅: 소프트(4_query)")

    gr.ChatInterface(
        fn=chat_fn,
        title="CVE 대응 도우미 — 소프트 라우팅 (4_query)",
        description=(
            "CVE ID, CWE 번호, 취약점 이름 중 무엇으로 물어도 답합니다. "
            "신호가 없으면 전체 문서에서 넓게 검색하고, 어떻게 이해했는지 함께 표시합니다."
        ),
        examples=[
            "Can you describe about CWE-1021?",
            "SQL injection 관련 CVE가 뭐야?",
            "CVE-2021-44228 우리는 2.14.1을 씁니다",
            "웹 페이지가 다른 사이트 프레임에 갇히는 문제가 뭔가요?",
        ],
    # show_error=True가 없으면 예외가 나도 화면에는 'Error' 한 단어만 뜬다.
    ).launch(share=share, show_error=True)


def main() -> None:
    args = sys.argv[1:]
    if "--ui" in args or "--share" in args:
        launch_ui(share="--share" in args)
        return

    positional = [a for a in args if not a.startswith("--")]
    if not positional:
        raise SystemExit(
            '질문을 인자로 주세요.\n'
            '  python src/4_query.py "Can you describe about CWE-1021?"\n'
            '  python src/4_query.py --ui')
    print(answer(positional[0]))


if __name__ == "__main__":
    main()
