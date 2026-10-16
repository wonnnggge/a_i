"""
3단계: 검색 + 답변 생성

1단계 프로젝트가 "이 CVE는 어떤 유형의 취약점인가"까지 답했다면,
여기서는 "그래서 지금 무엇을 해야 하는가"까지 답한다.

답을 만드는 재료가 두 종류다. 이 구분이 이 파일의 핵심이다.

  [계산으로 얻은 사실]  ← 벡터 검색을 쓰지 않는다
    위험도  : CVSS, EPSS, KEV 등재 여부와 기한  (cve_core.json에서 그대로 읽음)
    버전판정: 내 버전이 영향받는지              (check_version()이 정확히 비교)

  [검색으로 얻은 근거]  ← 벡터 검색을 쓴다
    어드바이저리 3개 (scope=instance) : 무엇을 해야 하는가
    CWE 유형 문서 2개 (scope=type)    : 왜 그런가, 근본 예방책은

숫자와 버전을 LLM에게 계산시키지 않는 것이 이 설계의 요점이다.
2.14.1과 2.15.0은 임베딩 공간에서 거의 같은 위치라, 검색 결과만 보고 답하게
하면 안전한 버전을 취약하다고 말할 수 있다.

사용 예:
    python src/3_query.py
    python src/3_query.py CVE-2021-44228
    python src/3_query.py CVE-2021-44228 "우리는 2.14.1을 쓰는데 어떻게 하나요?"
    python src/3_query.py --ui
"""
import os
import math
import time
import re
import sys
from importlib import import_module
from pathlib import Path

import chromadb

import common

# 수집하지 않은 CVE를 실시간 조회할 때 0_fetch_advisories.py의 함수를 재사용한다.
# 파일 이름이 숫자로 시작해 일반 import가 안 되므로 import_module을 쓴다.
sys.path.insert(0, str(Path(__file__).parent))

CHAT_MODEL = os.getenv("CHAT_MODEL", "gpt-4.1-nano")

# 검색 쿼터: 어드바이저리에서 3개, CWE 유형 문서에서 2개.
TOP_K_ADVISORY = 3
TOP_K_CWE = 2

# "2.14.1을 씁니다", "version 2.14.1" 처럼 문장에 섞인 버전을 찾기 위한 정규식.
#
# 끝에 \b(단어 경계)를 쓰면 안 된다. 한글은 파이썬 정규식에서 단어 문자로
# 취급되기 때문에, "2.14.1을"에서는 '1'과 '을' 사이에 경계가 없다고 판정된다.
# 그러면 정규식이 되돌아가 '2.14'까지만 잡아 버전이 잘린다(실제로 겪은 버그).
# 그래서 끝에는 경계를 걸지 않고, 앞에만 '숫자나 점이 아닐 것'을 요구한다.
#   (?<![\d.])      앞이 숫자·점이 아님 (긴 숫자의 일부를 잘라 잡는 것 방지)
#   \d+(?:\.\d+)+   1.2, 2.14.1 처럼 점이 최소 하나는 있어야 버전으로 본다
#                   (점이 없으면 그냥 숫자라 버전으로 오인하지 않는다)
#   (?:-[A-Za-z0-9.]+)?   '2.0-beta9' 같은 접미사
VERSION_PATTERN = re.compile(r"(?<![\d.])\d+(?:\.\d+)+(?:-[A-Za-z0-9.]+)?")

# 질문에 직접 적힌 CWE 번호를 찾기 위한 정규식. ("CWE-89 관련 CVE 알려줘")
CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)

# '유형 → CVE' 역방향 조회를 원하는 질문인지 판단하는 정규식.
#   "SQL injection 관련 CVE가 뭐야?", "what cve is related to sql injection?"
# CVE라는 단어 앞뒤에 '어떤/무슨/관련/목록/which/what' 류가 붙으면 역방향으로 본다.
REVERSE_INTENT_PATTERN = re.compile(
    r"(어떤|무슨|어떠한|관련|해당|목록|리스트|which|what|list|find|search)"
    r"[\s\S]{0,25}cve|cve[\s\S]{0,25}(목록|리스트|list)",
    re.IGNORECASE,
)

# 질문에 '설명문'이 들어 있는지 판단할 때 쓴다. 한글이 없는 문장을 설명으로 본다.
#   "Google Chromium V8 contains a type confusion ... 이 내용과 관련된 CVE ID는?"
#   -> 앞 문장은 설명, 뒤 문장은 지시문. 검색에는 설명만 쓰는 편이 정확하다.
#      (실측: 질문 전체로 검색하면 유사도 0.786, 설명만 쓰면 0.865)
HANGUL_PATTERN = re.compile(r"[가-힣]")

# 설명이 이 정도 길이는 돼야 '설명으로 CVE 찾기'로 본다.
# 짧으면 "SQL injection 관련 CVE가 뭐야?" 같은 유형 질문일 가능성이 크다.
DESCRIPTION_MIN_CHARS = 60
DESCRIPTION_TOP_K = 3

# 유사도 임계값. 수집된 CVE 155건으로 실측한 값을 기준으로 정했다.
#   설명이 데이터에 있는 경우          0.869
#   비슷하지만 데이터에 없는 취약점    0.598
#   보안과 무관한 문장                 0.120
DESCRIPTION_STRONG = 0.70   # 이 이상이면 '일치'로 본다
DESCRIPTION_WEAK = 0.55     # 이 미만이면 '못 찾았다'고 답한다

# 챗봇이 답변 첫 줄에 남기는 표식. 다음 턴에서 "그거"가 어느 CVE였는지
# 되찾는 데 쓴다. 사람에게도 대상이 보이므로 잘못 짚었을 때 바로 알 수 있다.
#
# 한국어/영어 두 표기를 모두 인식해야 한다. 사용자가 영어로 물으면 답변도
# 영어로 나가므로 표식이 'Target CVE:'가 되는데, 그 다음 턴에 한국어로
# 물으면 앞 턴의 영어 표식을 읽어야 맥락이 이어진다.
TARGET_MARKER_PATTERN = re.compile(
    r"(?:대상 CVE|Target CVE):\s*(CVE-\d{4}-\d{4,})", re.IGNORECASE)

# 제품 이름으로 CVE를 찾을 때, 질문에서 걷어낼 말들.
# "mit kerberos 관련된 CVE 있나요?" -> "mit kerberos"
STOP_WORDS_PATTERN = re.compile(
    # CVE / CWE / ID 는 조사나 복수형이 붙어도 걷어낸다. ("CVE가", "CVEs")
    r"cves?[가-힣]*|cwes?[가-힣]*|\bids?[가-힣]*|"
    r"관련(된|한)?|취약점|유형|목록|리스트|해당|또는|그리고|무엇|무슨|어떤|뭐|뭔가요|"
    r"있나요|있어|있니|있습니까|인가요|입니까|하나요|알려\s*줘|알려\s*주세요|주세요|해줘|"
    r"찾아|검색|대한|대해|"
    r"\b(what|which|list|find|search|related|about|any|are|is|there|for|to|the|a|an|"
    r"vulnerabilit\w*)\b",
    re.IGNORECASE)

NVD_KEYWORD_MAX = 5     # 실시간 조회 결과를 몇 건까지 보여줄지

# NVD 요청 사이 대기. 키가 없으면 길게 쉰다(요청 제한이 빡빡하다).
NVD_SLEEP_WITH_KEY = 0.7
NVD_SLEEP_NO_KEY = 6.0

# 대화 기억: LLM에게 함께 넘길 직전 대화의 턴 수(user+assistant 한 쌍이 1턴).
# 길게 넘길수록 맥락은 좋아지지만 토큰이 늘고, 옛 이야기가 새 질문을 흐린다.
HISTORY_TURNS = 3
HISTORY_CHARS = 500     # assistant 답변은 앞부분만 넘긴다 (근거 블록 제외)

# 역방향 조회에서 참고할 CWE 개수, CVE 목록 표시 개수
REVERSE_TOP_CWE = 3
REVERSE_MAX_CVES = 10

# 답변 언어 지시. 질문한 언어로 답하는 것이 원칙이다. 영어로 물었는데
# 한국어로 답하면 사용자가 답을 다시 번역해 읽어야 한다.
LANGUAGE_DIRECTIVE = {
    "ko": "한국어로 답하세요.",
    "en": "Answer in English. Do not translate your answer into Korean.",
}

# 사용자에게 그대로 보이는 문구들. LLM이 만드는 답변뿐 아니라 이 문구들도
# 질문 언어를 따라가야 한다. 영어 답변 안에 한국어 판정 문장이 끼어 있으면
# 읽기 어렵고, 무엇보다 버전 판정은 가장 중요한 출력이다.
T = {
    "ko": {
        "target": "대상 CVE",
        "inherited": "직전 대화에서 이어받음 — 다른 CVE라면 ID를 직접 적어주세요",
        "inherited_version": "직전 대화에서 이어받은 버전",
        "risk_block": "위험도(조회된 사실)",
        "verdict_block": "버전 판정(계산된 사실) — 입력",
        "sources": "검색된 근거 보기",
        "advisory": "어드바이저리",
        "weakness": "취약점 유형",
        "distance": "거리",
        "refs": "원본 확인",
        "bad_version": "'{v}'은 표준 버전 형식이 아니어서 자동 판정할 수 없습니다.",
        "no_fix": "{p}: 수정 버전 정보 없음",
        "vuln_row": "{p}: {v}은 취약 → {f} 이상으로 올리세요",
        "safe_row": "{p}: {v}은 이 범위에 해당하지 않음 (수정 버전 {f})",
        "vuln_head": "{v}은(는) 영향받습니다.",
        "safe_head": "{v}은(는) 확인된 영향 범위에 들지 않습니다. 다만 아래 범위만 검사한 결과입니다.",
        "unknown_head": "수정 버전 정보가 없어 판정할 수 없습니다.",
        "no_range": "이 CVE에는 비교할 수 있는 버전 범위 정보가 없습니다.",
        "cvss": "CVSS {s} ({sev})",
        "epss": "EPSS {e:.5f} — 향후 30일 악용 '확률 예측' (전체 CVE 중 백분위 {p:.1f}%)",
        "kev_yes": "CISA KEV 등재됨 — 실제 악용이 '확인된 사실' (등재 {added}, 조치 기한 {due})",
        "kev_no": "CISA KEV 미등재 — 실제 악용이 확인되지는 않음",
        "kev_unknown": "CISA KEV 확인하지 못함 — 등재 여부를 직접 확인하세요 "
                       "(https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
        "ransom": "랜섬웨어 캠페인에 사용된 것이 확인됨",
        "published": "공개일 {pub} / 수집 시각 {at}",
        # --- 설명으로 CVE 찾기 ---
        "desc_intro": "질문을 '설명으로 CVE 찾기'로 이해했습니다.",
        "desc_strong": "이 설명과 가장 가까운 CVE입니다.",
        "desc_weak": "확실하지 않습니다. 비슷해 보이는 후보만 보여드립니다.",
        "desc_none": "수집된 데이터에서 이 설명과 비슷한 CVE를 찾지 못했습니다.",
        "desc_similarity": "유사도",
        "desc_tail": "다른 CVE라면 ID를 직접 적어주세요.",
        # --- 유형으로 CVE 찾기 ---
        "reverse_intro": "질문을 '취약점 유형으로 CVE 찾기'로 이해했습니다.",
        "reverse_no_type": "질문에서 취약점 유형을 파악하지 못했습니다. "
                           "`CWE-89`처럼 번호로 물어보셔도 됩니다.",
        "reverse_found": "수집된 데이터에서 **{n}건** 찾았습니다.",
        "reverse_empty": "수집된 데이터에는 이 유형의 CVE가 **없습니다.**",
        "reverse_more": "... 외 {n}건",
        "reverse_nvd": "참고: NVD 전체에는 이 유형의 CVE가 **{n:,}건** 있습니다. "
                       "이 앱은 수집해둔 일부만 답할 수 있습니다.",
        "reverse_scope": "이 목록은 **수집된 CVE 안에서만** 찾은 결과입니다. "
                         "전체를 보려면 [NVD 검색](https://nvd.nist.gov/vuln/search)을 쓰세요.",
        "reverse_one": "이어서 바로 물어보실 수 있습니다 — **{marker}: {cve}**\n\n예: `그거 어떻게 막아?`",
        "reverse_many": "이어서 물어보려면 위 목록에서 **CVE ID를 골라 적어주세요.** "
                        "여러 건이라 어느 것인지 자동으로 정하지 않습니다.",
        "reverse_fetch": "이 유형의 CVE를 다루려면 먼저 수집해야 합니다:",
        # --- 무엇을 묻는지 모를 때 안내 ---
        "guide_head": "어떤 CVE에 대한 질문인지 알 수 없습니다. 이렇게 물어보실 수 있습니다.",
        "guide_1": "1. CVE ID로 묻기 — `{demo}은 어떤 위험인가요?`",
        "guide_2": "2. 버전까지 함께 — `{demo} 우리는 2.14.1을 씁니다`",
        "guide_3": "3. 취약점 유형으로 찾기 — `SQL injection 관련 CVE가 뭐야?`",
        "guide_4": "4. 설명으로 찾기 — 취약점 설명을 붙여넣고 `이 설명에 해당하는 CVE는?`",
        # --- 제품 이름으로 CVE 찾기 / 수집 범위 ---
        "corpus": "이 앱이 담고 있는 것: **CVE {n}건**(CISA KEV 기준으로 수집). "
                  "NVD 전체가 아닙니다.",
        "product_intro": "질문을 '제품 이름으로 CVE 찾기'로 이해했습니다. (키워드: **{kw}**)",
        "product_local": "수집된 데이터에서 **{n}건** 찾았습니다.",
        "product_local_none": "수집된 데이터에는 **없습니다.**",
        "product_nvd": "NVD 전체에는 **{total:,}건** 있습니다. 최근 {n}건입니다.",
        "product_nvd_none": "NVD에서도 찾지 못했습니다. 키워드를 바꿔 보세요.",
        "product_nvd_fail": "NVD 실시간 조회에 실패했습니다(네트워크 또는 요청 제한). "
                            "아래 링크에서 직접 확인하세요.",
        "product_fetch": "자세히 보려면 먼저 수집하세요:",
        "guide_no_history": "> 이 대화에는 **이전 기록이 없습니다.** 브라우저를 새로 고치거나 "
                            "서버를 다시 띄우면 기록이 지워집니다. 앞 질문부터 다시 해주세요.",
        "guide_history_no_cve": "> 직전 대화에서 대상 CVE를 찾지 못했습니다. CVE ID를 직접 적어주세요.",
        # --- 설명으로 취약점 유형(CWE) 찾기 ---
        "cwe_intro": "질문을 '설명으로 취약점 유형(CWE) 찾기'로 이해했습니다.",
        "cwe_via_cve": "이 설명은 **{cve}** 와 일치합니다 (유사도 {sim:.2f}). "
                       "아래는 NVD가 그 CVE에 붙여 둔 유형입니다.",
        "cwe_authoritative": "이 유형은 NVD 분석가가 CVE에 직접 붙인 값입니다. "
                             "문서 검색으로 추측한 것보다 정확합니다.",
        "cwe_guess": "설명과 비슷한 CWE 문서를 찾은 결과입니다. **확실하지 않습니다.**",
        "cwe_none": "설명에 해당하는 취약점 유형을 찾지 못했습니다.",
    },
    "en": {
        "target": "Target CVE",
        "inherited": "carried over from the previous turn — state a CVE ID if you meant another",
        "inherited_version": "version carried over from the previous turn",
        "risk_block": "Risk (looked up)",
        "verdict_block": "Version verdict (computed) — input",
        "sources": "Show retrieved evidence",
        "advisory": "Advisory",
        "weakness": "Weakness type",
        "distance": "distance",
        "refs": "Original sources",
        "bad_version": "'{v}' is not a standard version string, so it cannot be judged automatically.",
        "no_fix": "{p}: no fixed version published",
        "vuln_row": "{p}: {v} is affected → upgrade to {f} or later",
        "safe_row": "{p}: {v} is not in this affected range (fixed in {f})",
        "vuln_head": "{v} IS affected.",
        "safe_head": "{v} is not in any confirmed affected range. Note this only covers the ranges listed below.",
        "unknown_head": "Cannot judge: no fixed-version information is available.",
        "no_range": "This CVE has no comparable version-range information.",
        "cvss": "CVSS {s} ({sev})",
        "epss": "EPSS {e:.5f} — 'predicted probability' of exploitation in the next 30 days (percentile {p:.1f}%)",
        "kev_yes": "Listed in CISA KEV — exploitation is a CONFIRMED FACT (added {added}, due {due})",
        "kev_no": "Not in CISA KEV — exploitation has not been confirmed",
        "kev_unknown": "CISA KEV NOT CHECKED — verify listing yourself "
                       "(https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
        "ransom": "Known to have been used in ransomware campaigns",
        "published": "Published {pub} / fetched {at}",
        # --- find a CVE from a description ---
        "desc_intro": "Reading this as 'find a CVE from a description'.",
        "desc_strong": "This is the closest match to your description.",
        "desc_weak": "Not confident. Showing the closest candidates only.",
        "desc_none": "No CVE in the collected data looks like this description.",
        "desc_similarity": "similarity",
        "desc_tail": "If you meant a different CVE, state its ID.",
        # --- find CVEs from a weakness type ---
        "reverse_intro": "Reading this as 'find CVEs by weakness type'.",
        "reverse_no_type": "Could not tell which weakness type you mean. "
                           "You can also ask by number, e.g. `CWE-89`.",
        "reverse_found": "Found **{n}** in the collected data.",
        "reverse_empty": "The collected data has **no** CVE of this type.",
        "reverse_more": "... and {n} more",
        "reverse_nvd": "Note: NVD lists **{n:,}** CVEs of this type in total. "
                       "This app can only answer from what it collected.",
        "reverse_scope": "This list covers **only the collected CVEs**. "
                         "For everything, use [NVD search](https://nvd.nist.gov/vuln/search).",
        "reverse_one": "You can follow up right away — **{marker}: {cve}**\n\ne.g. `how do I fix it?`",
        "reverse_many": "To follow up, **pick one CVE ID from the list above.** "
                        "There is more than one, so nothing is chosen automatically.",
        "reverse_fetch": "To work with this type, collect it first:",
        # --- when the target is unclear ---
        "guide_head": "I cannot tell which CVE you are asking about. You can ask in these ways.",
        "guide_1": "1. By CVE ID — `What is the risk of {demo}?`",
        "guide_2": "2. With your version — `{demo} we run 2.14.1`",
        "guide_3": "3. By weakness type — `what CVEs relate to SQL injection?`",
        "guide_4": "4. By description — paste the description and ask `which CVE is this?`",
        # --- find CVEs by product name / corpus scope ---
        "corpus": "What this app holds: **{n} CVEs** (collected from the CISA KEV list). "
                  "This is not all of NVD.",
        "product_intro": "Reading this as 'find CVEs by product name'. (keyword: **{kw}**)",
        "product_local": "Found **{n}** in the collected data.",
        "product_local_none": "**Not found** in the collected data.",
        "product_nvd": "NVD has **{total:,}** in total. Here are the {n} most recent.",
        "product_nvd_none": "Nothing found in NVD either. Try a different keyword.",
        "product_nvd_fail": "Live NVD lookup failed (network or rate limit). "
                            "Check the link below yourself.",
        "product_fetch": "To look at one in detail, collect it first:",
        "guide_no_history": "> This conversation has **no earlier history.** Reloading the page or "
                            "restarting the server clears it. Please ask the first question again.",
        "guide_history_no_cve": "> No target CVE was found in the earlier turns. Please state a CVE ID.",
        # --- find the weakness type (CWE) from a description ---
        "cwe_intro": "Reading this as 'find the weakness type (CWE) from a description'.",
        "cwe_via_cve": "This description matches **{cve}** (similarity {sim:.2f}). "
                       "Below is the type NVD assigned to that CVE.",
        "cwe_authoritative": "This type was assigned to the CVE by an NVD analyst, "
                             "so it is more reliable than a document-search guess.",
        "cwe_guess": "These are the closest CWE documents to your description. **Not confident.**",
        "cwe_none": "Could not determine a weakness type for this description.",
    },
}

SYSTEM_PROMPT_TEMPLATE = """당신은 보안 취약점 대응을 돕는 실무 도우미입니다.

{language_directive}

아래 정보는 두 종류입니다. 성격이 다르므로 다르게 다루세요.

1) <위험도>와 <버전 판정>은 API 조회와 버전 비교로 **이미 확정된 사실**입니다.
   숫자나 판정 결과를 바꾸거나 새로 추정하지 말고 그대로 전달하세요.
2) <어드바이저리>와 <취약점 유형>은 검색해 온 문서입니다.
   설명은 이 문서 안에 있는 내용으로만 하세요.

답변 규칙:
- 초급 개발자도 이해할 수 있게 쉽게 설명하세요.
- "지금 무엇을 해야 하는가"를 가장 먼저, 구체적으로 알려주세요.
  (올려야 할 버전, 당장 못 올릴 때의 우회책 순서로)
- 그 다음에 "왜 위험한가"를 취약점 유형 문서로 설명하세요.
- CISA KEV 등재는 실제 악용이 **확인된 사실**이고, EPSS는 **확률 예측**입니다.
  이 둘을 섞어 말하지 마세요.
- 문서에 없는 내용은 지어내지 말고, 없다고 말한 뒤 원본 링크를 확인하라고 안내하세요.
- **설정 예시나 코드 조각을 임의로 지어내지 마세요.** 문서가 "시스템 속성을
  설정하라"고 했으면 그대로 전달하고, 문서에 없는 XML/YAML 예시를 만들어내면
  안 됩니다. 잘못된 설정 예시는 조치를 했다고 착각하게 만들어 오히려 위험합니다.
  정확한 적용 방법은 원본 어드바이저리를 확인하도록 안내하세요.

<위험도>
{risk}

<버전 판정>
{version_verdict}

<어드바이저리>
{advisory_context}

<취약점 유형>
{cwe_context}
"""


# --------------------------------------------------------------------------
# 데이터 로딩
# --------------------------------------------------------------------------

def load_cve_core() -> dict:
    """cve_core.json을 CVE ID로 찾을 수 있는 딕셔너리로 바꾼다."""
    return {c["cve_id"]: c for c in common.read_json(common.CVE_CORE_PATH, [])}


def load_advisories() -> dict:
    """어드바이저리를 CVE ID별 목록으로 묶는다.

    한 CVE에 OSV·GHSA·Red Hat 등 여러 어드바이저리가 붙으므로,
    ID 하나에 목록 하나를 매단다.
    """
    grouped: dict[str, list] = {}
    for adv in common.read_json(common.ADVISORIES_PATH, []):
        grouped.setdefault(adv["cve_id"], []).append(adv)
    return grouped


def get_collection():
    """벡터 DB를 열어 검색 가능한 컬렉션을 돌려준다.

    색인할 때 쓴 것과 같은 임베딩 함수를 붙여야 질의 벡터가 문서 벡터와
    같은 공간에 놓인다. check_backend_match()가 그 일치 여부를 미리 확인해,
    어긋났을 때 원인을 알기 쉬운 메시지로 알려준다.
    """
    # 백엔드 검사를 먼저 한다. 임베딩 함수를 만든 뒤에 검사하면, tfidf로
    # 검색하려 할 때 vectorizer 파일이 없다는 에러가 먼저 나서 진짜 원인이 가려진다.
    common.check_backend_match()
    embedding_fn = common.build_embedding_function()
    client = chromadb.PersistentClient(path=str(common.CHROMA_DIR))
    return client.get_collection(common.COLLECTION_NAME, embedding_function=embedding_fn)


def live_collection(cached):
    """캐시해둔 컬렉션 핸들이 아직 살아 있는지 확인하고, 죽었으면 다시 연다.

    왜 필요한가:
      챗봇을 띄워둔 채 2_embed_and_store.py --full 을 실행하면, 그 스크립트가
      컬렉션을 지우고 새로 만들면서 **컬렉션 UUID가 바뀐다.** 챗봇이 들고 있던
      옛 핸들은 그 순간부터 이렇게 실패한다.

          NotFoundError: Collection [f3966471-...] does not exist.

      그런데 gradio는 예외가 나면 화면에 'Error' 한 단어만 띄우므로,
      사용자는 무엇이 잘못됐는지 알 길이 없다. 수업 중에 재색인을 해보는 일이
      흔하므로, 여기서 조용히 다시 열어 회복시킨다.

    count()로 확인하는 이유:
      가장 가벼운 호출이면서, 컬렉션이 사라졌으면 확실히 예외를 낸다.
    """
    if cached is None:
        return get_collection()
    try:
        cached.count()
        return cached
    except Exception:
        return get_collection()


# --------------------------------------------------------------------------
# 계산으로 얻는 사실 (1) 버전 판정
# --------------------------------------------------------------------------

def parse_version(text: str):
    """버전 문자열을 비교 가능한 객체로 바꾼다.

    packaging 라이브러리는 '2.14.1' < '2.15.0' 같은 비교를 규칙에 맞게 해준다.
    문자열끼리 그냥 비교하면 '2.9.0' > '2.15.0'이 되어버린다(사전순으로는 9가
    1보다 크기 때문). 버전 비교를 직접 구현하면 이런 함정에 빠지기 쉽다.

    Maven의 '2.0-beta9'처럼 packaging이 해석하지 못하는 형식도 있어서,
    실패하면 None을 돌려주고 호출부가 '판정 불가'로 처리하게 한다.
    억지로 추측해서 틀린 답을 주는 것보다 모른다고 하는 편이 안전하다.
    """
    try:
        from packaging.version import Version
        return Version(text)
    except Exception:
        return None


def check_version(cve_id: str, user_version: str,
                  advisories: dict, lang: str = "ko") -> tuple[str, list[str]]:
    """사용자가 쓰는 버전이 영향받는지 **정확히 계산**한다. 검색을 쓰지 않는다.

    왜 검색으로 하면 안 되는가:
      "2.14.1이 영향받나요?"라는 질문을 벡터 검색에 넘기면, 2.14.1과 2.15.0이
      임베딩 공간에서 거의 같은 위치라 관련 문서가 뒤섞여 나온다. LLM이 그걸
      읽고 "2.14.1은 안전합니다"라고 답할 수도 있는데, 보안 판단에서 이런
      오답은 치명적이다.

      그래서 OSV가 준 구조화된 버전 범위를 실제 부등호로 비교한다.

          introduced <= 내 버전 < fixed   이면 취약

    반환값:
      (판정 문장, 근거 목록) 튜플. 판정 문장은 프롬프트의 <버전 판정>에 그대로
      들어간다. LLM은 이 문장을 전달만 하고 다시 계산하지 않는다.
    """
    t = T[lang]
    target = parse_version(user_version)
    if target is None:
        return t["bad_version"].format(v=user_version), []

    vulnerable, safe, unknown = [], [], []
    for adv in advisories.get(cve_id, []):
        for item in adv.get("affected", []):
            introduced = parse_version(item["introduced"]) if item.get("introduced") else None
            fixed = parse_version(item["fixed"]) if item.get("fixed") else None
            package = f"{item['package']} ({item['ecosystem']})"

            if fixed is None:
                unknown.append(t["no_fix"].format(p=package))
                continue
            # introduced가 없거나 해석 실패면 '아주 오래된 버전부터'로 본다.
            if (introduced is None or target >= introduced) and target < fixed:
                vulnerable.append(t["vuln_row"].format(p=package, v=user_version, f=fixed))
            else:
                safe.append(t["safe_row"].format(p=package, v=user_version, f=fixed))

    if vulnerable:
        return (t["vuln_head"].format(v=user_version) + "\n" + "\n".join(vulnerable),
                vulnerable)
    if safe:
        return (t["safe_head"].format(v=user_version) + "\n" + "\n".join(safe), safe)
    if unknown:
        return (t["unknown_head"] + "\n" + "\n".join(unknown), unknown)
    return (t["no_range"], [])


def extract_version(message: str) -> str | None:
    """문장에서 사용자가 쓰는 버전으로 보이는 숫자를 찾는다.

    "우리는 2.14.1을 쓰는데요" 같은 문장에서 2.14.1을 뽑는다.
    CVE ID(CVE-2021-44228)의 숫자와 헷갈리지 않도록, 먼저 CVE ID를 지운 뒤
    남은 부분에서 찾는다. 이 순서를 지키지 않으면 '2021'이나 '44228'을
    버전으로 오인한다.
    """
    without_cve = common.CVE_PATTERN.sub(" ", message)
    found = VERSION_PATTERN.search(without_cve)
    return found.group() if found else None


def stated_version(message: str) -> str | None:
    """사용자가 '우리가 쓰는 버전'으로 말한 값만 뽑는다.

    (이름 주의: 바로 위 check_version의 매개변수가 user_version이라
     같은 이름을 피했다. 교육용 코드에서 이름이 겹치면 읽기 어렵다.)

    extract_version과 무엇이 다른가:
      extract_version은 문장 어디에 있든 버전처럼 생긴 숫자를 가져온다.
      그런데 사용자는 CVE 설명을 **통째로 붙여넣기도 한다.** 그 설명 안에는
      영향 범위가 적혀 있다.

          "CVE-2021-44228 Apache Log4j2 2.0-beta9 through 2.15.0 JNDI
           features ... 이거 설명해줘"

      여기서 2.0-beta9은 사용자가 쓰는 버전이 아니라 **설명에 적힌 취약 범위의
      시작점**이다. 그대로 판정에 넣으면 이런 답이 나온다(실측).

          입력 `2.0-beta9` -> "2.0-beta9은(는) 영향받습니다. 2.3.1 이상으로 올리세요"

      사용자는 자기 버전을 말한 적이 없는데 확신에 찬 판정을 받는다.
      버전 판정은 검색이 아니라 계산이라 근거 블록에도 안 남아서,
      틀려도 어디서 온 값인지 추적하기 어렵다.

    어떻게 가르나 — 붙여넣은 설명 문장만 빼고 본다:
      긴 영문 문장은 붙여넣은 설명으로 보고 제외한다. 남은 문장에서만 찾는다.

          한글이 섞인 문장        -> 사용자가 쓴 말         -> 본다
          짧은 영문 문장          -> 사용자가 영어로 쓴 말   -> 본다
          긴 영문 문장(60자 이상) -> 붙여넣은 설명          -> 뺀다

      "We use log4j 2.14.1, are we affected?"는 영문이지만 짧아서 남는다.
      길이로 가르는 것이 거칠어 보이지만, 사람이 직접 치는 질문과 복사해
      붙이는 설명은 길이가 확실히 갈린다(description_query와 같은 기준).
    """
    sentences = re.split(r"(?<=[.!?])\s+", message.replace("\n", " "))
    kept = [s for s in sentences
            if HANGUL_PATTERN.search(s) or len(s.strip()) < DESCRIPTION_MIN_CHARS]
    return extract_version(" ".join(kept))


# --------------------------------------------------------------------------
# 계산으로 얻는 사실 (2) 위험도
# --------------------------------------------------------------------------

def format_risk(core: dict, lang: str = "ko") -> str:
    """CVSS·EPSS·KEV를 사람이 읽을 위험도 요약으로 만든다. 검색을 쓰지 않는다.

    KEV와 EPSS를 구분해 표현하는 것이 중요하다.
      KEV 등재  -- 실제 공격에 쓰인 것이 **확인된 사실**
      EPSS 점수 -- 앞으로 30일 안에 악용될 **확률 예측**
    둘을 섞어 말하면 "악용 확률이 높다"를 "이미 공격받았다"로 오해하게 된다.
    프롬프트에서도 이 둘을 섞지 말라고 지시한다.
    """
    t = T[lang]
    lines = []
    if core.get("cvss_score") is not None:
        lines.append(t["cvss"].format(s=core["cvss_score"], sev=core.get("severity", "")))
    if core.get("epss") is not None:
        pct = core.get("epss_percentile") or 0
        lines.append(t["epss"].format(e=core["epss"], p=pct * 100))

    kev = core.get("kev", {})
    if kev is None:
        # 조회를 못 한 것과 조회해보니 없는 것은 전혀 다르다. 확인하지 않았는데
        # "미등재"라고 하면, 실제로 악용 중인 취약점을 안심하고 미루게 된다.
        lines.append(t["kev_unknown"])
    elif kev.get("listed"):
        lines.append(t["kev_yes"].format(added=kev.get("date_added", ""),
                                         due=kev.get("due_date", "")))
        if kev.get("ransomware") == "Known":
            lines.append(t["ransom"])
    else:
        lines.append(t["kev_no"])

    lines.append(t["published"].format(pub=core.get("published", ""),
                                       at=core.get("fetched_at", "")))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 검색으로 얻는 근거
# --------------------------------------------------------------------------

def _query(collection, question: str, where: dict, top_k: int) -> list[dict]:
    """Chroma에 질의하되, **같은 섹션이 결과를 독점하지 않도록** 골라 돌려준다.

    왜 섹션 다양성이 필요한가 (실제로 겪은 문제):
      "당장 업그레이드가 어렵습니다. 임시 우회책이 있나요?"라고 물었는데
      제품 목록(affected_releases)과 버전 범위(affected) 청크가 상위 3개를
      모두 차지하고, 정작 답인 우회책(mitigation) 청크가 밀려났다.

      의미가 옅은 목록성 청크라도 개수가 많으면 하나뿐인 핵심 청크를
      수적으로 눌러버린다. 거리 차이는 0.759 대 0.782로 근소했다.

    어떻게 고치나:
      필요한 개수의 3배를 후보로 받아온 뒤, 가까운 순서대로 훑으면서
      **섹션마다 하나씩만** 먼저 담는다. 그래도 자리가 남으면 남은 후보로 채운다.
      이렇게 하면 요약·상세·우회책·영향범위가 골고루 들어와, 질문이 무엇이든
      답에 필요한 종류가 빠지지 않는다.

      검색 결과의 다양성을 확보하는 이 방식은 실무 RAG에서 자주 쓰인다
      (같은 문서의 인접 청크만 잔뜩 나오는 현상을 막는 데도 같은 원리를 쓴다).
    """
    results = collection.query(
        query_texts=[common.clean_query(question)],
        n_results=top_k * 3,   # 골라낼 여지를 두려고 넉넉히 받는다
        where=where,
    )

    candidates = []
    for doc, meta, distance in zip(results["documents"][0],
                                   results["metadatas"][0],
                                   results["distances"][0]):
        header, _, body = doc.partition("\n")
        candidates.append({**meta, "header": header, "text": body.strip(),
                           "distance": distance})

    picked, used_sections = [], set()
    for chunk in candidates:                      # 1순위: 섹션마다 하나씩
        if chunk["section"] in used_sections:
            continue
        used_sections.add(chunk["section"])
        picked.append(chunk)
        if len(picked) >= top_k:
            return picked

    for chunk in candidates:                      # 2순위: 남은 자리를 가까운 순으로
        if chunk in picked:
            continue
        picked.append(chunk)
        if len(picked) >= top_k:
            break
    return picked


def retrieve(cve_id: str, question: str, cwe_ids: list[str],
             collection=None) -> tuple[list[dict], list[dict]]:
    """어드바이저리와 CWE 문서에서 **각각 정해진 개수만큼** 검색한다.

    쿼터를 나눠 두 번 질의하는 이유 (2단계의 핵심 검색 설계):
      한 번에 섞어서 상위 5개를 뽑으면 한쪽이 결과를 독점한다.
        - 어드바이저리 본문에는 제품명·버전·CVE 번호가 반복되어, 질문에 그런
          단어가 있으면 어드바이저리가 상위를 쓸어간다.
        - 반대로 일반적인 질문에서는 문서 수가 많은 CWE 쪽이 독점하기도 한다.

      그런데 좋은 답에는 두 종류가 모두 필요하다.
        어드바이저리 = "무엇을 해야 하는가" (올릴 버전, 우회책)
        CWE 유형     = "왜 그런가"          (원리, 근본 예방책)

      쿼터를 고정하면 질문이 어떻든 두 관점이 항상 답에 들어온다.
      이렇게 검색 대상을 성격별로 나눠 각각 뽑는 방식은 실무 RAG에서
      답변의 구성 자체를 보장하고 싶을 때 흔히 쓴다.

    where 필터:
      어드바이저리는 cve_id로, CWE는 cwe_id 목록으로 범위를 좁힌다.
      scope 조건을 함께 걸어 두 집합이 겹치지 않게 한다.
    """
    collection = collection or get_collection()

    advisory_hits = _query(collection, question, top_k=TOP_K_ADVISORY, where={
        "$and": [{"cve_id": cve_id}, {"scope": "instance"}],
    })

    cwe_hits = []
    if cwe_ids:
        cwe_hits = _query(collection, question, top_k=TOP_K_CWE, where={
            "$and": [{"cwe_id": {"$in": cwe_ids}}, {"scope": "type"}],
        })

    return advisory_hits, cwe_hits


def format_context(chunks: list[dict]) -> str:
    """검색된 청크를 LLM 프롬프트에 넣을 글로 합친다.

    헤더를 살려 넣어야 LLM이 각 근거가 어느 출처의 어느 부분인지 알고
    답변에 반영할 수 있다.
    """
    if not chunks:
        return "(관련 문서를 찾지 못했습니다)"
    return "\n\n".join(f"{c['header']}\n{c['text']}" for c in chunks)


# --------------------------------------------------------------------------
# 답변 생성
# --------------------------------------------------------------------------

def generate_answer(core: dict, question: str, version_verdict: str,
                    advisory_hits: list[dict], cwe_hits: list[dict],
                    history=None) -> str:
    """계산된 사실과 검색된 근거를 구획으로 나눠 LLM에 넘기고 답변을 받는다.

    프롬프트를 구획으로 나누는 이유:
      전부 뭉쳐서 "이 내용으로 답하라"고 하면, LLM이 확정된 숫자까지
      '문서에서 읽은 내용'으로 취급해 다시 추론하거나 바꿔 말할 수 있다.
      위험도와 버전 판정을 따로 떼어 "이미 확정된 사실이니 그대로 전달하라"고
      지시하면 그런 변형이 줄어든다.

    temperature=0:
      가장 확률이 높은 답만 고르게 해서 같은 질문에 거의 같은 답이 나오게 한다.
      보안 정보를 다루므로 창의성보다 일관성이 중요하다.

    history를 함께 넘기는 이유:
      "방금 말한 조치를 더 설명해줘" 같은 질문은 직전 답변을 봐야 답할 수 있다.
      다만 위험도와 버전 판정은 매 턴 다시 계산해 system 프롬프트에 넣는다.
      대화 기록은 '무슨 이야기를 했는지'를 위한 것이고, 사실의 출처가 아니다.

    API 키가 없어도 죽지 않는다:
      예외를 잡아 안내 문구를 돌려주면, 답변 생성만 빠지고 검색된 근거는
      그대로 확인할 수 있다. 기능 하나가 없다고 전체가 멈추지 않게 하는 것을
      우아한 성능 저하(graceful degradation)라고 한다.
    """
    # 질문한 언어로 답하게 한다. 영어로 물었는데 한국어로 답하면 사용자가
    # 답을 다시 번역해 읽어야 한다.
    lang = common.detect_language(question)
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        language_directive=LANGUAGE_DIRECTIVE[lang],
        risk=format_risk(core),
        version_verdict=version_verdict or "(사용자가 버전을 알려주지 않았습니다)",
        advisory_context=format_context(advisory_hits),
        cwe_context=format_context(cwe_hits),
    )
    try:
        from openai import OpenAI
        common.load_env()
        # CHAT_BASE_URL 이 있으면 그 주소(예: 로컬 Ollama)로 보낸다. 없으면 OpenAI.
        client = OpenAI(base_url=os.getenv("CHAT_BASE_URL") or None)
        response = client.chat.completions.create(
            model=os.getenv("CHAT_MODEL", CHAT_MODEL),
            temperature=0,
            messages=[
                {"role": "system", "content": system_prompt},
                *recent_turns(history),
                {"role": "user", "content": question},
            ],
        )
        return response.choices[0].message.content
    except Exception as error:
        return (f"답변 생성을 건너뜁니다 ({type(error).__name__}: {error}).\n"
                f"아래 위험도와 근거는 정상적으로 조회했으니 그대로 확인하세요.\n"
                f"OPENAI_API_KEY를 .env에 설정하면 답변까지 생성됩니다.")


# --------------------------------------------------------------------------
# 명령줄 출력
# --------------------------------------------------------------------------

def answer_for_cve(cve_id: str, question: str, collection=None,
                   generate: bool = False) -> None:
    """CVE 하나를 조회해 위험도·버전 판정·검색 근거를 터미널에 출력한다."""
    cores = load_cve_core()
    if cve_id not in cores:
        print(f"\n'{cve_id}'는 수집된 데이터에 없습니다.")
        print(f"  python src/0_fetch_advisories.py --cve-ids {cve_id}")
        print("  python src/1_chunk.py && python src/2_embed_and_store.py")
        return

    core = cores[cve_id]
    advisories = load_advisories()

    print(f"\n{'=' * 70}")
    print(f"[CVE] {cve_id}")
    print(f"{'=' * 70}")
    print("[위험도 — 조회된 사실]")
    for line in format_risk(core).split("\n"):
        print(f"  {line}")
    print(f"  연결된 CWE: {', '.join(core['cwe_ids']) or '(없음)'}")

    version = extract_version(question)
    verdict = ""
    if version:
        verdict, _ = check_version(cve_id, version, advisories)
        print(f"\n[버전 판정 — 계산된 사실] 입력 버전: {version}")
        for line in verdict.split("\n"):
            print(f"  {line}")

    advisory_hits, cwe_hits = retrieve(cve_id, question, core["cwe_ids"], collection)

    print(f"\n[질문] {question}")
    print(f"\n[검색 근거 — 벤더 어드바이저리 {len(advisory_hits)}개]")
    for c in advisory_hits:
        print(f"  - {c['vendor']} / {c['section']}  (거리 {c['distance']:.3f})")
        print(f"    {c['text'][:220].strip()}...")
    print(f"\n[검색 근거 — 취약점 유형 {len(cwe_hits)}개]")
    for c in cwe_hits:
        print(f"  - {c['cwe_id']} / {c['section']}  (거리 {c['distance']:.3f})")
        print(f"    {c['text'][:220].strip()}...")

    if generate:
        print("\n[LLM 답변]")
        print(generate_answer(core, question, verdict, advisory_hits, cwe_hits))


def fetch_cve_live(cve_id: str) -> dict | None:
    """수집하지 않은 CVE를 NVD에서 **그 자리에서** 조회한다. 실패하면 None.

    수집(0_fetch_advisories.py)과 무엇이 다른가:
      수집은 여섯 소스를 모두 순회하고 파일로 저장한다. CVE 하나에 10~20초가
      걸리므로 채팅 도중에 할 일이 아니다. 이 함수는 **NVD 한 곳만** 부르고
      아무것도 저장하지 않는다. 0.5~1초면 끝난다.

    왜 이것만으로 답이 되나 (이 설계의 핵심):
      이 프로젝트가 색인해둔 문서는 두 종류다.
        scope=type     CWE 유형 문서 — **1391개 전부** 들어 있다
        scope=instance 벤더 어드바이저리 — 수집한 CVE 것만 있다
      모르는 CVE라도 'CWE 번호'만 알면, 이미 색인된 유형 문서로
      "왜 위험한가 / 근본 예방책은"까지 답할 수 있다. 부족한 것은
      "어느 버전으로 올려야 하나"뿐이고, 그건 답변에 명시해 알린다.

    저장하지 않는 이유:
      채팅 한 번 때문에 data/ 파일과 벡터 DB를 건드리면, 색인 상태를 예측할 수
      없게 된다. 필요하면 사용자가 수집 명령으로 명시적으로 추가하게 한다.
      (안내 문구에 그 명령을 함께 보여준다.)

    실패를 조용히 삼키는 이유:
      NVD가 느리거나 rate limit에 걸려도 챗봇 전체가 죽으면 안 된다.
      None을 돌려주면 호출부가 기존 안내로 넘어간다.
    """
    try:
        fetch_module = import_module("0_fetch_advisories")
        common.load_env()
        api_key = os.getenv("NVD_API_KEY") or os.getenv("NVD_KEY")
        nvd_cve = fetch_module.fetch_nvd_cve(cve_id, api_key)
        if nvd_cve is None:
            return None
    except Exception:
        return None

    # KEV와 EPSS도 함께 본다. 둘 다 싸다 — KEV는 받아둔 파일을 다시 쓰고,
    # EPSS는 요청 한 번이다. 반면 이 둘이 없으면 위험도 판단이 반쪽이 된다.
    #
    # 특히 KEV는 빠뜨리면 위험하다. build_cve_core(kev=None)은 kev를
    # {"listed": False}로 채우는데, 이는 '확인해보니 없다'는 단언이다.
    # 조회를 안 해놓고 "미등재"라고 말하면, 실제로 악용 중인 취약점을
    # 안심하고 미루게 된다. 그래서 실패하면 None으로 두어
    # format_risk가 '확인하지 못함'으로 표시하게 한다.
    kev_entry, kev_failed = None, False
    try:
        kev_entry = fetch_module.fetch_kev_catalog().get(cve_id)
    except Exception:
        kev_failed = True

    epss_entry = None
    try:
        epss_entry = fetch_module.fetch_epss([cve_id]).get(cve_id)
    except Exception:
        pass

    core = fetch_module.build_cve_core(cve_id, nvd_cve, kev_entry, epss_entry)
    if kev_failed:
        core["kev"] = None
    return core


def answer_uncollected_cve(cve_id: str, question: str, collection,
                           lang: str = "ko") -> str:
    """수집하지 않은 CVE를 NVD 실시간 조회 + 색인된 CWE 문서로 답한다.

    답변에 '무엇이 빠졌는지'를 반드시 밝힌다:
      벤더 어드바이저리가 없으므로 "어느 버전으로 올려야 하는가"는 답할 수 없다.
      그 사실을 숨기고 유형 설명만 하면, 사용자는 대응까지 안내받았다고
      착각한다. 보안에서 그런 착각은 조치를 안 하게 만들어 위험하다.
    """
    core = fetch_cve_live(cve_id)

    if core is None or not core.get("cwe_ids"):
        available = ", ".join(sorted(load_cve_core())[:5]) or "(없음)"
        reason = ("NVD에서 찾지 못했습니다 (존재하지 않는 ID이거나 조회에 실패했습니다)."
                  if core is None else
                  "NVD에 이 CVE의 취약점 유형(CWE)이 아직 분류되지 않았습니다.")
        return (f"`{cve_id}`는 수집된 데이터에 없고, {reason}\n\n"
                f"직접 수집하려면:\n"
                f"```bash\npython src/0_fetch_advisories.py --cve-ids {cve_id}\n"
                f"python src/1_chunk.py\npython src/2_embed_and_store.py --full\n```\n\n"
                f"지금 바로 물어볼 수 있는 CVE: {available}")

    # 어드바이저리는 없으므로 CWE 유형 문서만 검색된다.
    advisory_hits, cwe_hits = retrieve(cve_id, question, core["cwe_ids"], collection)
    answer = generate_answer(core, question, "", advisory_hits, cwe_hits)

    t = T[lang]
    notice = (
        "> **수집되지 않은 CVE입니다.** NVD에서 방금 조회한 정보와 이미 색인된 "
        "CWE 유형 문서로 답했습니다.\n"
        "> 벤더 어드바이저리가 없어 **패치 버전·우회책·조치 기한은 답할 수 없습니다.**"
        if lang == "ko" else
        "> **This CVE is not in the collected data.** Answered from a live NVD lookup "
        "plus the already-indexed CWE documents.\n"
        "> Vendor advisories are missing, so **fixed versions, workarounds and "
        "deadlines cannot be answered.**"
    )

    parts = [
        notice, "\n\n",
        f"**{t['target']}: {cve_id}**\n\n", answer,
        "\n\n---\n",
        f"**{t['risk_block']}**\n\n```\n{format_risk(core, lang)}\n```",
        f"\n\n전체 대응 정보까지 보려면 이 CVE를 수집하세요:\n"
        f"```bash\npython src/0_fetch_advisories.py --cve-ids {cve_id}\n"
        f"python src/1_chunk.py\npython src/2_embed_and_store.py --full\n```",
    ]

    if cwe_hits:
        parts.append(f"\n<details><summary>{t['sources']}</summary>\n")
        for c in cwe_hits:
            parts.append(f"\n**{t['weakness']} · {c['cwe_id']} · {c['section']}** "
                         f"({t['distance']} {c['distance']:.3f})\n\n> {c['text'][:400]}...\n")
        parts.append("\n</details>")

    return "".join(parts)


def pick_demo_cve() -> str | None:
    """데모용 CVE를 데이터에서 고른다.

    CVE ID를 코드에 박아두면 수집 조건을 바꿨을 때 그 CVE가 없어서 아무것도
    보여주지 못한다. 어드바이저리가 가장 많이 붙은 CVE를 골라야 2단계의
    특징이 잘 드러난다.
    """
    cores = load_cve_core()
    if not cores:
        return None
    advisories = load_advisories()
    return max(cores, key=lambda cid: len(advisories.get(cid, [])))


# --------------------------------------------------------------------------
# gradio 챗봇 UI
# --------------------------------------------------------------------------

_collection_cache = None

# CWE별 NVD 전체 건수 캐시. 같은 유형을 여러 번 물어도 API를 한 번만 부른다.
_nvd_count_cache: dict[str, int | None] = {}


# --------------------------------------------------------------------------
# 역방향 조회: 취약점 유형 -> CVE
# --------------------------------------------------------------------------

def has_reverse_intent(message: str) -> bool:
    """'유형 → CVE'를 묻는 질문인지 판단한다.

    이 앱의 기본 방향은 CVE ID를 받아 정보를 찾는 정방향이다. 그런데
    "SQL injection 관련 CVE가 뭐야?" 같은 질문은 방향이 반대다.

    두 가지 중 하나면 역방향으로 본다.
      1. 질문에 CWE 번호가 직접 적혀 있다 ("CWE-89 관련 CVE")
      2. CVE라는 단어 근처에 '어떤/무슨/관련/목록/which/what' 류가 있다

    왜 의도를 따로 판단하나:
      앞선 대화에서 이미 어떤 CVE를 다루고 있어도, 사용자가 새로 "SQL
      injection CVE 알려줘"라고 물으면 앞의 CVE를 이어받으면 안 된다.
      그래서 '이어받기'보다 이 판단을 먼저 한다.
    """
    return bool(CWE_PATTERN.search(message) or REVERSE_INTENT_PATTERN.search(message))


# --------------------------------------------------------------------------
# 설명으로 CVE 찾기
# --------------------------------------------------------------------------

def description_part(message: str) -> str:
    """질문에서 한글이 없는 문장만 모은다 (= 영문 설명 부분).

    영문 취약점 설명을 붙여넣고 한국어로 "이건 무슨 CVE야?"라고 묻는 일이 흔하다.
    검색에는 설명만 쓰는 편이 정확하다. 한국어 지시문까지 함께 임베딩하면
    설명의 신호가 옅어진다(실측: 설명만 0.865, 질문 전체 0.786).
    """
    sentences = re.split(r"(?<=[.!?])\s+", message.replace("\n", " "))
    plain = [s.strip() for s in sentences if s.strip() and not HANGUL_PATTERN.search(s)]
    return " ".join(plain)


def description_query(message: str) -> str:
    """검색에 쓸 문장. 영문 설명이 있으면 그것만, 없으면 질문 전체."""
    return description_part(message) or message.strip()


def has_description_intent(message: str) -> bool:
    """'이 설명에 해당하는 CVE는?' 형태의 질문인지 판단한다.

    세 가지를 모두 만족해야 한다.
      1. CWE 번호가 없다 — 번호를 콕 집었으면 유형 조회가 맞다
      2. CVE를 묻고 있다
      3. 설명으로 볼 만큼 긴 문장이 있다

    3번이 필요한 이유:
      "SQL injection 관련 CVE가 뭐야?"는 설명이 아니라 유형 질문이다.
      둘 다 '관련 CVE'를 묻지만 원하는 답의 모양이 다르다. 길이로 가른다.
    """
    if CWE_PATTERN.search(message):
        return False
    if not re.search(r"cve", message, re.IGNORECASE):
        return False
    return len(description_query(message)) >= DESCRIPTION_MIN_CHARS


_description_index_cache = None


def _unit(vector):
    """길이를 1로 맞춘다. 이러면 유사도 계산이 내적 한 번으로 끝난다."""
    norm = math.sqrt(sum(x * x for x in vector))
    return [x / norm for x in vector] if norm else vector


def description_index():
    """CVE 설명을 임베딩해 메모리에 담아둔다 (프로세스당 한 번만).

    왜 벡터 DB를 안 쓰나:
      벡터 DB에는 CWE 유형 문서와 벤더 어드바이저리만 들어 있다. NVD가 준
      CVE 한 줄 설명은 cve_core.json에만 있다. 건수가 수백 개 수준이라
      따로 색인을 만들기보다 한 번 임베딩해 들고 있는 편이 간단하다.
    """
    global _description_index_cache
    if _description_index_cache is None:
        cores = load_cve_core()
        items = [(cid, core["description"]) for cid, core in cores.items()
                 if core.get("description")]
        embed_fn = common.build_embedding_function()
        vectors = [_unit(v) for v in embed_fn([text for _, text in items])]
        _description_index_cache = ([cid for cid, _ in items], vectors)
    return _description_index_cache


def find_cves_by_description(message: str, top_k: int = DESCRIPTION_TOP_K) -> list[dict]:
    """설명과 가장 비슷한 CVE를 유사도 높은 순으로 돌려준다."""
    ids, vectors = description_index()
    embed_fn = common.build_embedding_function()
    query = _unit(embed_fn([description_query(message)])[0])

    scored = []
    for cve_id, vector in zip(ids, vectors):
        similarity = sum(a * b for a, b in zip(query, vector))
        scored.append((similarity, cve_id))
    scored.sort(reverse=True)

    cores = load_cve_core()
    results = []
    for similarity, cve_id in scored[:top_k]:
        core = cores[cve_id]
        results.append({
            "cve_id": cve_id,
            "similarity": similarity,
            "description": core.get("description", ""),
            "cvss_score": core.get("cvss_score"),
            "kev": core.get("kev", {}),
        })
    return results




def mentions_cwe(message: str) -> bool:
    """'유형(CWE)이 무엇인지' 묻고 있는가.

    CWE 번호가 이미 적혀 있으면 제외한다. 번호를 콕 집었다면 그 유형의
    CVE를 보려는 것이지, 유형이 무엇인지 묻는 것이 아니다.

    길이는 보지 않는다. "위의 내용과 관련된 CWE ID는?"처럼 짧아도
    유형을 묻는 질문이기 때문이다. 길이 판단은 asks_for_cwe가 따로 한다.
    """
    if CWE_PATTERN.search(message):
        return False
    return bool(re.search(r"cwe|취약점\s*유형|weakness type", message, re.IGNORECASE))


def asks_for_cwe(message: str) -> bool:
    """'이 설명은 무슨 CWE야?' 형태인지 판단한다 (설명이 함께 있는 경우)."""
    return mentions_cwe(message) and len(description_query(message)) >= DESCRIPTION_MIN_CHARS


def answer_cwe_of_cve(cve_id: str, lang: str, inherited: bool) -> str | None:
    """이미 대상이 정해진 CVE에 대해 '유형이 뭐냐'고 물을 때 답한다.

    왜 따로 두나:
      2턴 질문은 대개 짧다("그거 CWE가 뭐야?"). 설명이 없으니 검색할 것도 없다.
      이럴 때는 이미 알고 있는 CVE의 CWE를 그냥 읽어주면 된다.
      NVD 분석가가 붙여 둔 값이라 검색보다 정확하다.

    수집하지 않은 CVE면 None을 돌려준다. 그 경우는 실시간 조회 경로가 처리한다.
    """
    cores = load_cve_core()
    if cve_id not in cores:
        return None

    t = T[lang]
    catalog = {c["cwe_id"]: c for c in common.read_json(common.CWE_CATALOG_PATH, [])}
    cwe_ids = cores[cve_id].get("cwe_ids", [])

    header = f"**{t['target']}: {cve_id}**"
    if inherited:
        header += f" *({t['inherited']})*"

    if not cwe_ids:
        return f"{header}\n\n{t['cwe_none']}\n\n> {corpus_note(lang)}"

    parts = [header, "\n\n", t["cwe_intro"], "\n\n"]
    for cwe_id in cwe_ids:
        name = catalog.get(cwe_id, {}).get("name", "")
        parts.append(f"- **{cwe_id}** — {name}\n")
    parts.append("\n> " + t["cwe_authoritative"])
    return "".join(parts)


def answer_description_to_cwe(message: str, collection, lang: str) -> str:
    """설명을 주고 '무슨 유형이냐'고 물을 때 답한다.

    두 갈래로 답한다.
      1. 설명과 일치하는 CVE를 찾았으면 -> 그 CVE의 CWE를 답한다.
         NVD 분석가가 붙여 둔 값이라 신뢰도가 높다.
      2. 못 찾았으면 -> CWE 문서를 임베딩으로 검색해 후보만 제시한다.
         이 경로는 자주 빗나가므로 '확실하지 않다'고 분명히 밝힌다.
         (실측: 긴 설명으로 검색하면 1·2위 거리 차이가 0.003까지 좁혀진다)
    """
    t = T[lang]
    catalog = {c["cwe_id"]: c for c in common.read_json(common.CWE_CATALOG_PATH, [])}
    hits = find_cves_by_description(message, top_k=1)
    best = hits[0] if hits and hits[0]["similarity"] >= DESCRIPTION_STRONG else None

    parts = [t["cwe_intro"] + "\n\n"]

    if best:
        cwe_ids = load_cve_core()[best["cve_id"]].get("cwe_ids", [])
        parts.append(t["cwe_via_cve"].format(cve=best["cve_id"], sim=best["similarity"]) + "\n\n")
        for cwe_id in cwe_ids:
            name = catalog.get(cwe_id, {}).get("name", "")
            parts.append(f"- **{cwe_id}** — {name}\n")
        parts.append("\n> " + t["cwe_authoritative"] + "\n\n")
        parts.append(f"**{t['target']}: {best['cve_id']}**\n")
        return "".join(parts)

    cwes = find_cwes_for_question(message, collection)
    if not cwes:
        return parts[0] + t["cwe_none"]

    parts.append(t["cwe_guess"] + "\n\n")
    for cwe in cwes:
        parts.append(f"- **{cwe['cwe_id']}** — {cwe['cwe_name']} "
                     f"({t['distance']} {cwe['distance']:.3f})\n")
    return "".join(parts)




# --------------------------------------------------------------------------
# 제품 이름으로 CVE 찾기 (수집 데이터 + NVD 실시간 조회)
# --------------------------------------------------------------------------

def corpus_note(lang: str) -> str:
    """이 앱이 무엇을 담고 있는지 한 줄로 알려준다.

    왜 필요한가:
      "없습니다"라는 답을 사용자는 "세상에 없다"로 읽는다. 실제로는
      "내가 모은 155건 안에 없다"는 뜻이다. 범위를 함께 적으면 오해가 사라진다.
    """
    return T[lang]["corpus"].format(n=len(load_cve_core()))


def product_keyword(message: str) -> str:
    """질문에서 제품 이름으로 보이는 부분만 남긴다.

    "mit kerberos 관련된 CWE 또는 CVE 가 있나요?" -> "mit kerberos"

    형태소 분석기를 쓰지 않는 이유:
      교육용이라 의존성을 늘리지 않으려 했다. 흔한 조사·의문사만 걷어내도
      제품 이름은 대체로 남는다. 정확도가 필요하면 이 부분을 LLM에게
      맡기는 방법도 있다(질의 재작성).
    """
    text = CWE_PATTERN.sub(" ", message)
    text = STOP_WORDS_PATTERN.sub(" ", text)
    text = re.sub(r"[^\w가-힣.\- ]+", " ", text)
    words = [w for w in text.split() if len(w) >= 2]
    return " ".join(words[:4])


def is_weakness_term(keyword: str) -> bool:
    """이 말이 취약점 '유형' 이름인가, 제품 이름인가.

    CWE 카탈로그의 이름과 겹치면 유형으로 본다.
      "sql injection"  -> CWE-89 이름에 들어 있다      -> 유형
      "mit kerberos"   -> 어떤 CWE 이름에도 없다        -> 제품

    사전을 따로 만들지 않고 이미 가진 카탈로그(1391개)를 쓰는 것이 핵심이다.
    """
    if not keyword:
        return False
    target = keyword.lower()
    for entry in common.read_json(common.CWE_CATALOG_PATH, []):
        if target in entry.get("name", "").lower():
            return True
    return False


def asks_by_product(message: str) -> bool:
    """'이 제품에 관련된 CVE 있나요?' 형태인지 판단한다."""
    if common.extract_cve_id(message) or CWE_PATTERN.search(message):
        return False
    if not re.search(r"cve|cwe|취약점", message, re.IGNORECASE):
        return False
    keyword = product_keyword(message)
    return len(keyword) >= 3 and not is_weakness_term(keyword)


def local_cves_by_keyword(keyword: str) -> list[dict]:
    """수집된 CVE 중 설명에 키워드가 들어 있는 것을 찾는다 (단순 문자열 대조)."""
    target = keyword.lower()
    return [core for core in load_cve_core().values()
            if target in (core.get("description") or "").lower()]


def nvd_keyword_search(keyword: str, limit: int = NVD_KEYWORD_MAX):
    """NVD에서 키워드로 CVE를 실시간 조회한다. (전체 건수, 최근 목록)을 돌려준다.

    두 번 호출하는 이유:
      NVD는 공개일 오름차순으로 돌려준다. 그냥 앞에서 가져오면 2001년 것부터
      나온다. 그래서 먼저 전체 건수를 보고, 마지막 페이지를 가져와 뒤집는다.

    실패해도 앱은 멈추지 않는다:
      네트워크가 없거나 요청 제한에 걸리면 (None, [])을 돌려주고,
      답변에서는 NVD 검색 링크만 안내한다.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    api_key = os.getenv("NVD_API_KEY") or os.getenv("NVD_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        import requests
        first = requests.get(url, headers=headers, timeout=20,
                             params={"keywordSearch": keyword, "resultsPerPage": 1})
        if not first.ok:
            return None, []
        total = first.json().get("totalResults", 0)
        if total == 0:
            return 0, []

        time.sleep(NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_NO_KEY)
        start = max(0, total - limit)
        page = requests.get(url, headers=headers, timeout=30,
                            params={"keywordSearch": keyword,
                                    "resultsPerPage": min(limit, total),
                                    "startIndex": start})
        if not page.ok:
            return total, []

        found = []
        for item in reversed(page.json().get("vulnerabilities", [])):
            cve = item["cve"]
            description = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
            metrics = cve.get("metrics", {})
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    score = metrics[key][0]["cvssData"].get("baseScore")
                    break
            found.append({"cve_id": cve["id"], "description": description, "cvss_score": score})
        return total, found
    except Exception:
        return None, []


def answer_product_lookup(message: str, lang: str) -> str:
    """제품 이름으로 CVE를 찾는다. 수집 데이터와 NVD를 모두 보고, 출처를 구분해 말한다."""
    t = T[lang]
    keyword = product_keyword(message)
    parts = [t["product_intro"].format(kw=keyword), "\n\n"]

    local = local_cves_by_keyword(keyword)
    if local:
        parts.append(t["product_local"].format(n=len(local)) + "\n\n")
        for core in local[:REVERSE_MAX_CVES]:
            parts.append(f"- **{core['cve_id']}** (CVSS {core.get('cvss_score')})\n")
    else:
        parts.append(t["product_local_none"] + "\n")
    parts.append("\n> " + corpus_note(lang) + "\n")

    total, recent = nvd_keyword_search(keyword)
    parts.append("\n---\n\n")
    if total is None:
        parts.append(t["product_nvd_fail"] + "\n")
    elif total == 0:
        parts.append(t["product_nvd_none"] + "\n")
    else:
        parts.append(t["product_nvd"].format(total=total, n=len(recent)) + "\n\n")
        for item in recent:
            score = item["cvss_score"] if item["cvss_score"] is not None else "-"
            parts.append(f"- **{item['cve_id']}** (CVSS {score}) — {item['description'][:110]}\n")
        if recent:
            parts.append("\n" + t["product_fetch"] + "\n\n```bash\n"
                         f"python src/0_fetch_advisories.py --cve-ids {recent[0]['cve_id']}\n"
                         "python src/1_chunk.py && python src/2_embed_and_store.py\n```\n")

    parts.append(f"\n[NVD 검색](https://nvd.nist.gov/vuln/search/results?query={keyword.replace(' ', '+')})")
    return "".join(parts)


def answer_description_lookup(message: str, lang: str) -> str:
    """'이 설명에 해당하는 CVE는?' 질문에 답한다.

    유사도에 따라 말을 다르게 한다. 애매한 것을 단정적으로 답하면
    사용자가 엉뚱한 CVE의 조치를 그대로 따를 수 있다.
      0.70 이상 -> 일치한다고 본다
      0.55 이상 -> 후보만 보여준다
      그 미만  -> 못 찾았다고 답한다
    """
    t = T[lang]
    hits = find_cves_by_description(message)
    best = hits[0]["similarity"] if hits else 0.0

    if best < DESCRIPTION_WEAK:
        # '못 찾았다'고만 하면 "그런 CVE가 없다"로 읽힌다. 범위를 함께 밝힌다.
        return (f"{t['desc_intro']}\n\n{t['desc_none']}\n\n"
                f"> {corpus_note(lang)}\n\n{t['reverse_scope']}")

    headline = t["desc_strong"] if best >= DESCRIPTION_STRONG else t["desc_weak"]
    parts = [f"{t['desc_intro']}\n\n{headline}\n\n"]
    for hit in hits:
        kev = " · KEV" if hit["kev"].get("listed") else ""
        parts.append(f"- **{hit['cve_id']}** "
                     f"({t['desc_similarity']} {hit['similarity']:.2f} · "
                     f"CVSS {hit['cvss_score']}{kev})\n")
        parts.append(f"  - {hit['description'][:160]}\n")

    if best >= DESCRIPTION_STRONG:
        # 확실할 때만 이어받기 표식을 남긴다. 애매한데 표식을 남기면
        # 다음 턴의 "그거"가 엉뚱한 CVE를 가리킬 수 있다.
        parts.append(f"\n**{t['target']}: {hits[0]['cve_id']}**\n\n{t['desc_tail']}")
    else:
        parts.append(f"\n{t['desc_tail']}")
    return "".join(parts)



def nvd_cve_count(cwe_id: str) -> int | None:
    """NVD 전체에서 이 CWE에 해당하는 CVE가 몇 건인지 조회한다.

    왜 이 숫자가 필요한가 (정직한 답을 위해):
      이 앱이 수집한 CVE는 수십 건뿐이라 대표성이 없다. "SQL injection CVE가
      뭐야?"에 "1건입니다"라고 답하면 그게 더 잘못된 답이다. NVD 전체 건수를
      함께 보여줘야 사용자가 "아, 이건 수집된 일부구나"를 안다.

      NVD API는 cweId 파라미터로 이 역방향 조회를 지원한다(CWE-89는 11,585건).

    실패해도 그냥 넘어간다:
      네트워크가 없거나 rate limit에 걸려도 역방향 조회 자체는 로컬 데이터로
      동작해야 하므로, 건수를 못 가져오면 None을 돌려주고 표시만 생략한다.
    """
    if cwe_id in _nvd_count_cache:
        return _nvd_count_cache[cwe_id]

    count = None
    try:
        import requests
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cweId": cwe_id, "resultsPerPage": 1},
            timeout=15,
        )
        if resp.ok:
            count = resp.json().get("totalResults")
    except Exception:
        count = None

    _nvd_count_cache[cwe_id] = count
    return count


def find_cwes_for_question(question: str, collection) -> list[dict]:
    """질문이 가리키는 취약점 유형(CWE)을 찾는다.

    두 경로가 있다.
      1. 질문에 CWE 번호가 직접 적혀 있으면 그대로 쓴다 (정확).
      2. 아니면 CWE 문서 청크를 **의미 검색**해서 가까운 유형을 찾는다.
         "SQL injection" -> CWE-89 처럼 자연어를 유형으로 옮기는 일인데,
         이미 색인해둔 scope="type" 청크가 그 사전 역할을 한다.
         키워드 표를 따로 만들 필요 없이 기존 RAG를 그대로 재사용하는 셈이다.

    where에 scope="type"만 걸고 cwe_id 필터는 걸지 않는다. 정방향 검색과 달리
    "어느 CWE인지"를 지금 찾는 중이라 범위를 좁힐 근거가 아직 없기 때문이다.

    반환값: [{"cwe_id", "cwe_name", "distance"}] 를 가까운 순으로.
    """
    catalog = {c["cwe_id"]: c for c in common.read_json(common.CWE_CATALOG_PATH, [])}

    explicit = [f"CWE-{m.group(1)}" for m in CWE_PATTERN.finditer(question)]
    if explicit:
        return [{"cwe_id": cid,
                 "cwe_name": catalog.get(cid, {}).get("name", ""),
                 "distance": None}
                for cid in dict.fromkeys(explicit)]

    # 청크 메타데이터에는 cwe_id만 있고 이름은 없다(임베딩 저장 시 제외했다).
    # 이름은 카탈로그에서 가져온다.
    hits = _query(collection, question, where={"scope": "type"}, top_k=REVERSE_TOP_CWE)
    found, seen = [], set()
    for hit in hits:
        cid = hit["cwe_id"]
        if cid in seen:
            continue
        seen.add(cid)
        found.append({
            "cwe_id": cid,
            "cwe_name": catalog.get(cid, {}).get("name", ""),
            "distance": hit["distance"],
        })
    return found


def cves_for_cwe(cwe_id: str) -> list[dict]:
    """수집된 CVE 중 이 CWE를 가리키는 것을 찾는다. 벡터 검색이 아니다.

    cve_core.json의 cwe_ids를 그대로 대조하는 구조화 조회다. NVD 분석가가
    확정해둔 매핑이라 정확하고, 의미 검색처럼 애매하게 걸릴 여지가 없다.
    """
    return [c for c in common.read_json(common.CVE_CORE_PATH, [])
            if cwe_id in c["cwe_ids"]]


def answer_reverse_lookup(question: str, collection, lang: str = "ko",
                          only_if_found: bool = False):
    """'유형 → CVE' 질문에 답한다.

    구성:
      1. 질문을 어떤 유형으로 이해했는지 밝힌다 (틀렸으면 사용자가 바로 안다)
      2. 수집된 데이터에서 찾은 CVE 목록
      3. NVD 전체 건수 — 이 앱의 답이 전체가 아님을 분명히 한다
      4. 이어서 물어보는 방법 안내

    lang:
      답변 문구도 질문한 언어를 따라간다. 영어로 물었는데 한국어 안내가
      섞여 나오면 읽기 어렵다.

    only_if_found:
      의도가 분명하지 않은 질문에서 '마지막으로 한 번 시도'할 때 쓴다.
      한 건도 못 찾으면 None을 돌려주어, 호출한 쪽이 사용법 안내로 넘어가게 한다.
    """
    t = T[lang]
    cwes = find_cwes_for_question(question, collection)
    if not cwes:
        return None if only_if_found else t["reverse_no_type"]

    parts = [t["reverse_intro"] + "\n"]
    all_matched: list[str] = []   # 이어받기 표식을 남길지 판단하는 데 쓴다

    for cwe in cwes:
        matched = cves_for_cwe(cwe["cwe_id"])
        all_matched.extend(c["cve_id"] for c in matched)
        nvd_total = nvd_cve_count(cwe["cwe_id"])

        parts.append(f"\n### {cwe['cwe_id']} — {cwe['cwe_name']}\n")
        if matched:
            parts.append("\n" + t["reverse_found"].format(n=len(matched)) + "\n\n")
            for c in matched[:REVERSE_MAX_CVES]:
                kev = " · KEV" if c.get("kev", {}).get("listed") else ""
                parts.append(f"- **{c['cve_id']}** (CVSS {c.get('cvss_score')}{kev})\n")
            if len(matched) > REVERSE_MAX_CVES:
                parts.append("- " + t["reverse_more"].format(n=len(matched) - REVERSE_MAX_CVES) + "\n")
        else:
            parts.append("\n" + t["reverse_empty"] + "\n")

        if nvd_total is not None:
            parts.append("\n> " + t["reverse_nvd"].format(n=nvd_total) + "\n")

    unique = list(dict.fromkeys(all_matched))
    if only_if_found and not unique:
        return None

    parts.append("\n---\n\n" + t["reverse_scope"] + "\n\n")
    if len(unique) == 1:
        # 찾은 CVE가 하나뿐이면 다음 턴에서 "그거"가 무엇인지 명확하다.
        parts.append(t["reverse_one"].format(marker=t["target"], cve=unique[0]))
    elif len(unique) > 1:
        # 여러 건이면 "그거"가 모호하다. 표식을 남기지 않고 지정을 요청한다.
        parts.append(t["reverse_many"])
    else:
        parts.append(t["reverse_fetch"] + "\n\n"
                     "```bash\npython src/0_fetch_advisories.py --cve-ids <CVE-ID>\n"
                     "python src/1_chunk.py && python src/2_embed_and_store.py\n```")
    return "".join(parts)

def cve_from_history(history) -> str | None:
    """직전 대화에서 다루던 CVE ID를 되찾는다.

    왜 필요한가:
      역방향 조회를 붙이면 자연스럽게 2턴 대화가 된다.

          1턴  "SQL injection 관련 CVE가 뭐야?"  -> CVE-2026-9586 입니다
          2턴  "그거 어떻게 막아?"                -> ???

      2턴의 메시지에는 CVE ID가 없다. 기록을 보지 않으면 "CVE ID를 적어주세요"가
      다시 나와서, 문제가 해결되는 게 아니라 한 턴 뒤로 밀릴 뿐이다.

    왜 전역 변수가 아니라 history를 쓰나:
      gradio가 매 호출마다 대화 기록을 인자로 넘겨주므로 추가 비용이 없다.
      게다가 기록이 곧 진실이라, 사용자가 재시도나 되돌리기로 대화를 바꾸면
      동작도 자동으로 따라간다. 전역 변수에 '현재 CVE'를 보관하면 그때 어긋나고,
      무엇보다 --share로 여러 사람이 접속하면 서로의 값을 덮어쓴다.

    assistant 메시지는 표식만 읽는다 (중요):
      답변 본문에는 CWE 문서의 '실제 사례' 섹션이 딸려오는데, 거기에는 관련
      없는 CVE 번호가 잔뜩 들어 있다("CVE-2020-9054: ...", "CVE-2010-1208: ...").
      그대로 훑으면 엉뚱한 CVE를 집는다. 그래서 답변 첫 줄에 남겨둔
      '대상 CVE:' 표식만 읽는다. user 메시지는 사람이 직접 쓴 것이라 그대로 훑는다.

    가장 최근 것을 고른다: 기록을 뒤에서부터 훑어 처음 찾은 것을 돌려준다.
    """
    for msg in reversed(history or []):
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if not isinstance(content, str):
            # 이미지·파일 첨부는 문자열이 아니다. 건너뛴다.
            continue

        if msg.get("role") == "assistant":
            found = TARGET_MARKER_PATTERN.search(content)
            if found:
                return found.group(1).upper()
        elif msg.get("role") == "user":
            found = common.extract_cve_id(content)
            if found:
                return found
    return None


def recent_turns(history, turns: int = HISTORY_TURNS) -> list[dict]:
    """LLM에게 함께 넘길 직전 대화를 추린다.

    답변을 통째로 넘기지 않는 이유:
      이 앱의 답변 뒤에는 '검색된 근거 보기' 블록이 붙는다. 문서 발췌가 길고
      관련 없는 CVE 번호도 많이 들어 있다. 그대로 다시 넣으면 토큰만 늘고
      새 질문의 신호가 묻힌다. 그래서 구분선(---) 앞부분만, 그것도 일부만 넘긴다.

    몇 턴만 넘기는 이유:
      대화가 길어지면 토큰이 계속 쌓인다. 보안 상담은 보통 직전 두세 턴이면
      맥락이 충분하다.
    """
    trimmed = []
    for msg in (history or [])[-turns * 2:]:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        role = msg.get("role")
        if not isinstance(content, str) or role not in ("user", "assistant"):
            continue
        if role == "assistant":
            content = content.split("\n---\n")[0][:HISTORY_CHARS]
        trimmed.append({"role": role, "content": content})
    return trimmed


def version_from_history(history) -> str | None:
    """직전 대화에서 사용자가 말한 버전을 되찾는다.

    왜 필요한가:
      1턴  "CVE-2021-44228 우리는 2.14.1을 씁니다"
      2턴  "그럼 몇 버전으로 올려야 하나요?"

      2턴 메시지에는 버전이 없다. 되찾지 않으면 "버전을 알려주세요"를 다시
      묻게 되어, 사용자는 같은 말을 반복해야 한다.

    사용자 메시지만 훑는 이유:
      답변 본문에는 '2.15.0 이상으로 올리세요'처럼 우리가 제안한 버전이
      들어 있다. 그것을 사용자가 쓰는 버전으로 오해하면 판정이 통째로 틀린다.

    stated_version을 쓰는 이유:
      같은 이유가 과거 턴에도 적용된다. 사용자가 몇 턴 전에 CVE 설명을
      붙여넣었다면 그 안의 버전이 계속 따라온다. 지금 말한 것이든 전에 말한
      것이든, '사용자가 자기 버전으로 말한 값'만 되찾아야 한다.
    """
    for msg in reversed(history or []):
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            found = stated_version(content)
            if found:
                return found
    return None


def _log_turn(message: str, history) -> None:
    """이번 턴에 무엇이 들어왔는지 터미널에 한 줄로 남긴다."""
    size = len(history) if history else 0
    last_marker = "-"
    for msg in reversed(history or []):
        if isinstance(msg, dict) and msg.get("role") == "assistant":
            found = TARGET_MARKER_PATTERN.search(msg.get("content") or "")
            last_marker = found.group(1) if found else "표식없음"
            break
    kinds = {type(m).__name__ for m in (history or [])}
    print(f"[턴] 질문={message[:28]!r} 기록={size}개 {kinds or ''} "
          f"직전표식={last_marker}")


def chat_fn(message: str, history) -> str:
    """챗봇이 메시지를 받을 때마다 부르는 함수.

    대상 CVE를 정하는 순서 (이 순서가 중요하다):

      1. 메시지에 CVE ID가 적혀 있으면 그것을 쓴다.
      2. 아니고 '유형 → CVE'를 묻는 질문이면 역방향 조회로 답한다.
      3. 아니면 직전 대화에서 다루던 CVE를 이어받는다.
      4. 그래도 없으면 역방향 조회를 시도하고, 그마저 안 되면 안내를 준다.

      2번을 3번보다 먼저 두는 이유:
        Log4Shell 얘기를 하다가 "SQL injection CVE 알려줘"라고 물으면,
        이어받기가 먼저 동작할 경우 엉뚱하게 Log4Shell을 계속 붙들고 있게 된다.
        새 주제를 묻는 것인지 앞의 것을 이어가는 것인지를 먼저 가른다.

    이어받은 CVE는 반드시 밝힌다:
      답변 첫 줄에 '대상 CVE: ...'를 남긴다. 보안 도구가 엉뚱한 CVE의 조치를
      조용히 안내하면 위험하므로, 무엇에 대해 답하는지 사용자가 항상 볼 수 있어야
      한다. 이 표식은 다음 턴에서 cve_from_history()가 되읽는 용도도 겸한다.

    그 다음 흐름:
      5. 문장에 버전이 있으면 정확히 판정한다(검색이 아니라 계산).
      6. 어드바이저리·CWE에서 쿼터만큼 검색한다.
      7. 확정된 사실과 검색 근거를 구획으로 나눠 LLM에 넘긴다.
      8. 답변 + 접어둔 근거를 돌려준다.
    """
    global _collection_cache

    cores = load_cve_core()
    _collection_cache = live_collection(_collection_cache)

    # 진단 출력: 매 턴 터미널에 한 줄씩 남긴다.
    # 대화 기록이 실제로 전달되는지, 대상 CVE를 어디서 얻었는지 눈으로 확인할 수 있다.
    # gradio는 화면에 답변만 보여주므로, 이런 문제는 터미널을 봐야 원인을 잡는다.
    _log_turn(message, history)

    cve_id = common.extract_cve_id(message)
    inherited = False
    lang = common.detect_language(message)

    # 의도 판단 순서: CVE ID > 설명문 > 유형.
    # 설명을 유형보다 먼저 보는 이유: "...crafted HTML page. 이 내용과 관련된 CVE는?"
    # 처럼 둘 다 걸리는 질문에서, 사용자가 원하는 것은 '그 설명의 CVE 한 건'이다.
    if cve_id is None and asks_for_cwe(message):
        return answer_description_to_cwe(message, _collection_cache, lang)

    if cve_id is None and has_description_intent(message):
        return answer_description_lookup(message, lang)

    # 제품 이름을 유형보다 먼저 본다. "mit kerberos 관련 CVE"는 유형 질문이
    # 아니라 제품 질문인데, '관련 CVE'라는 표현 때문에 유형 조회로 빨려 들어간다.
    if cve_id is None and asks_by_product(message):
        return answer_product_lookup(message, lang)

    if cve_id is None and has_reverse_intent(message):
        return answer_reverse_lookup(message, _collection_cache, lang)

    if cve_id is None:
        cve_id = cve_from_history(history)
        inherited = cve_id is not None

    # 대상 CVE가 정해진 상태에서 "그럼 CWE는?"이라고 물으면, 그 CVE의 유형을
    # 바로 답한다. 이 분기가 없으면 CVE 설명을 처음부터 다시 늘어놓게 된다.
    if cve_id and mentions_cwe(message):
        cwe_answer = answer_cwe_of_cve(cve_id, lang, inherited)
        if cwe_answer is not None:
            return cwe_answer

    if cve_id is None:
        # CVE/CWE라는 말 없이 설명만 길게 붙여넣는 경우가 있다. 이때도
        # 유형 목록보다는 '이 설명이 무슨 CVE인지'를 알려주는 편이 맞다.
        if len(description_query(message)) >= DESCRIPTION_MIN_CHARS:
            return answer_description_lookup(message, lang)

        # 마지막 시도: 유형 조회로 읽어본다. 그래도 안 되면 사용법을 안내한다.
        reverse = answer_reverse_lookup(message, _collection_cache, lang,
                                        only_if_found=True)
        if reverse is not None:
            return reverse
        demo = pick_demo_cve()
        t = T[lang]
        # 기록이 비어서 이어받지 못한 것인지, 기록은 있는데 CVE가 없었던 것인지
        # 구분해 알려준다. 원인이 전혀 다르기 때문이다.
        # (실제로 겪은 일: 페이지를 새로 고치면 gradio의 대화 기록이 사라진다)
        hint = t["guide_no_history"] if not history else t["guide_history_no_cve"]
        return "\n\n".join([
            t["guide_head"],
            t["guide_1"].format(demo=demo),
            t["guide_2"].format(demo=demo),
            t["guide_3"],
            t["guide_4"],
            hint,
            "> " + corpus_note(lang),
        ])

    if cve_id not in cores:
        # 수집 데이터에 없다고 바로 포기하지 않는다. CWE 유형 문서 1391개는
        # 이미 전부 색인돼 있으므로, NVD에서 'CWE 번호'만 실시간으로 얻으면
        # "왜 위험한가 / 어떻게 막나"는 그 자리에서 답할 수 있다.
        # 자세한 설계 근거는 answer_uncollected_cve() 참고.
        return answer_uncollected_cve(cve_id, message, _collection_cache,
                                      common.detect_language(message))

    # 질문한 언어를 따라간다. 답변뿐 아니라 아래 라벨과 판정 문장도 함께 바뀐다.
    t = T[lang]

    core = cores[cve_id]

    # 버전도 CVE와 같은 방식으로 이어받는다. 이번 메시지에 없으면 직전 대화에서 찾는다.
    #
    # 단, **대상이 바뀌었으면 이어받지 않는다** (inherited가 True일 때만).
    #   1턴  "CVE-2021-44228 우리는 2.14.1을 씁니다"
    #   2턴  "CVE-2014-0160은 어떤가요?"          <- 사용자가 새 CVE를 지정
    #
    #   2턴에서 2.14.1을 끌고 오면 Heartbleed(OpenSSL)를 Log4j 버전으로
    #   판정하게 된다. 버전 판정은 검색이 아니라 계산이라 확신에 찬 문장으로
    #   나오고("영향받습니다"), 근거 블록에도 안 남아서 틀려도 알아차리기 어렵다.
    #
    #   CVE를 이어받았다는 것은 '같은 이야기를 계속하고 있다'는 뜻이므로
    #   그때는 버전도 같은 대상의 것이다. 사용자가 새 번호를 적었다면
    #   이야기가 바뀐 것이니 다시 묻는 편이 낫다.
    version = stated_version(message)
    inherited_version = False
    if version is None and inherited:
        version = version_from_history(history)
        inherited_version = version is not None

    verdict = ""
    if version:
        verdict, _ = check_version(cve_id, version, load_advisories(), lang)

    advisory_hits, cwe_hits = retrieve(cve_id, message, core["cwe_ids"],
                                       _collection_cache)
    answer = generate_answer(core, message, verdict, advisory_hits, cwe_hits, history)

    # 어느 CVE에 답하는지 항상 첫 줄에 밝힌다. 이어받은 경우에는 그 사실과
    # 바로잡는 방법까지 함께 알려준다. 이 줄은 다음 턴에서 맥락을 되찾는
    # 표식으로도 쓰인다(cve_from_history 참고).
    header = f"**{t['target']}: {cve_id}**"
    if inherited:
        header += f" *({t['inherited']})*"

    # 확정된 사실은 접지 않고 항상 보여준다. 대응 판단에 바로 필요한 정보다.
    parts = [header, "\n\n", answer,
             "\n\n---\n",
             f"**{t['risk_block']}**\n\n```\n{format_risk(core, lang)}\n```"]
    if verdict:
        # 이어받은 버전이면 그렇다고 밝힌다. 사용자가 다른 버전을 말하려던
        # 것이었다면 바로 알아차릴 수 있어야 한다.
        note = f" *({t['inherited_version']})*" if inherited_version else ""
        parts.append(f"\n**{t['verdict_block']} `{version}`**{note}\n\n```\n{verdict}\n```")

    parts.append(f"\n<details><summary>{t['sources']}</summary>\n")
    for c in advisory_hits:
        parts.append(f"\n**{t['advisory']} · {c['vendor']} · {c['section']}** "
                     f"({t['distance']} {c['distance']:.3f})\n\n> {c['text'][:400]}...\n")
    for c in cwe_hits:
        parts.append(f"\n**{t['weakness']} · {c['cwe_id']} · {c['section']}** "
                     f"({t['distance']} {c['distance']:.3f})\n\n> {c['text'][:400]}...\n")
    parts.append("\n</details>")

    refs = core.get("references", [])[:3]
    if refs:
        parts.append(f"\n\n**{t['refs']}**: " +
                     " · ".join(f"[{r['tags'][0]}]({r['url']})" for r in refs))
    return "".join(parts)


def launch_ui(share: bool = False) -> None:
    """gradio 챗봇을 브라우저에 띄운다.

    gradio는 무거워서 함수 안에서 import한다. 파일 맨 위에 두면 명령줄로
    간단히 조회할 때도 매번 로딩을 기다려야 하고, gradio를 설치하지 않은
    사람은 CLI조차 쓸 수 없게 된다.

    화면을 띄우기 전에 벡터 DB를 미리 열어본다. 문제가 있으면 첫 질문에서야
    에러가 나서 원인을 알기 어렵기 때문이다.
    """
    global _collection_cache
    import gradio as gr

    _collection_cache = get_collection()
    cores = load_cve_core()
    print(f"벡터 DB 준비 완료: {_collection_cache.count()}개 청크 / CVE {len(cores)}건")
    print(f"답변 생성 모델: {CHAT_MODEL}")

    demo = pick_demo_cve() or "CVE-2021-44228"
    gr.ChatInterface(
        fn=chat_fn,
        title="CVE 대응 도우미 (CWE + 벤더 어드바이저리)",
        description=(
            "CVE ID로 질문하면 위험도(CVSS·EPSS·KEV)를 조회하고, "
            "벤더 어드바이저리와 CWE 문서를 함께 검색해 답합니다. "
            "쓰는 버전을 함께 적으면 영향 여부를 정확히 판정합니다."
        ),
        examples=[
            f"{demo} 우리는 2.14.1을 쓰는데 어떻게 해야 하나요?",
            f"{demo} 당장 업그레이드가 어려운데 우회책이 있나요?",
            f"{demo}이 왜 그렇게 위험한가요?",
        ],
    # show_error=True가 없으면 예외가 나도 화면에는 'Error' 한 단어만 뜬다.
    ).launch(share=share, show_error=True)


def main() -> None:
    args = sys.argv[1:]

    if "--ui" in args or "--share" in args:
        launch_ui(share="--share" in args)
        return

    positional = [a for a in args if not a.startswith("--")]
    generate = "--answer" in args

    # 역방향 조회를 명령줄에서도 시험할 수 있게 한다.
    #   python src/3_query.py --weakness "SQL injection"
    if "--weakness" in args:
        question = positional[0] if positional else "SQL injection"
        print(answer_reverse_lookup(question, get_collection()))
        return

    if positional:
        cve_id = positional[0].upper()
        question = positional[1] if len(positional) > 1 else common.DEFAULT_QUESTION
        answer_for_cve(cve_id, question, generate=generate)
        return

    demo = pick_demo_cve()
    if demo is None:
        raise SystemExit("수집된 데이터가 없습니다. 먼저 0_fetch_advisories.py를 실행하세요.")

    collection = get_collection()
    for question in [
        "우리는 2.14.1 버전을 쓰는데 영향을 받나요? 어떻게 해야 하나요?",
        "당장 업그레이드가 어렵습니다. 임시 우회책이 있나요?",
    ]:
        answer_for_cve(demo, question, collection=collection, generate=generate)


if __name__ == "__main__":
    main()
