"""
0단계: 실제 데이터 수집 (MITRE CWE + NVD CVE)

이 스크립트는 실제로 실행되는 코드다. 두 개의 공개 데이터 소스를 사용한다.

  1) MITRE CWE 카탈로그 (XML zip, 무료·인증 불필요)
     https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
     -> data/cwe_catalog.json  (1_chunk.py가 읽는 스키마)

  2) NVD CVE API 2.0 (무료, API 키 없으면 rate limit이 빡빡함)
     https://services.nvd.nist.gov/rest/json/cves/2.0
     -> data/cve_cwe_mapping.json

NVD API 키가 있으면 프로젝트 루트 .env 또는 환경변수에 넣어두면 자동으로 쓴다:

    NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

키 없이도 동작하지만, NVD 권고에 따라 요청 사이에 6초를 쉬므로 느리다.
(키가 있으면 0.7초. 무료 키는 https://nvd.nist.gov/developers/request-an-api-key)

사용 예:

    # 기본: KEV(실제로 악용이 확인된 취약점) 200건 + 거기서 참조된 CWE만 저장
    python src/0_fetch_real_data.py

    # 최근 30일 CRITICAL 등급 CVE 400건으로 수집
    python src/0_fetch_real_data.py --source recent --days 30 --severity CRITICAL --max-cves 400

    # CWE 카탈로그를 통째로 저장 (약 900+개, 청크 3600+개)
    python src/0_fetch_real_data.py --cwe-scope all

수집이 끝나면 1_chunk.py -> 2_embed_and_store.py -> 3_query.py를
코드 수정 없이 그대로 실행하면 된다.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

DATA_DIR = Path(__file__).parent.parent / "data"
RAW_DIR = DATA_DIR / "raw"

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD 무료 사용 시 권장 간격(초). API 키가 있으면 훨씬 짧게 잡아도 된다.
NVD_SLEEP_NO_KEY = 6.0
NVD_SLEEP_WITH_KEY = 0.7
NVD_PAGE_SIZE = 200  # API 최대값 2000이지만, 실패 시 재시도 비용을 낮추려고 작게 잡음


# --------------------------------------------------------------------------
# 1) MITRE CWE 카탈로그
# --------------------------------------------------------------------------

def download_cwe_xml(cache: bool = True) -> bytes:
    """MITRE 서버에서 CWE 카탈로그 zip 파일을 내려받아, 압축 안에 든 XML을 반환한다.

    무슨 일을 하나:
      MITRE는 전 세계 취약점 '유형' 사전인 CWE를 하나의 거대한 XML 파일로
      공개하고, 용량을 줄이려고 zip으로 압축해 배포한다. 이 함수는 그 zip을
      내려받아(약 6MB) 압축을 풀고, 안에 들어 있는 XML의 내용(약 18MB)을
      그대로 돌려준다.

    파라미터:
      cache -- True(기본)면 이전에 받아둔 파일이 data/raw/에 있을 때 그걸 쓴다.
               18MB를 매번 다시 받을 이유가 없기 때문이다. 최신 버전으로
               갱신하고 싶으면 False를 넘긴다(명령줄에서는 --no-cache).

    반환값:
      XML 파일의 내용. 문자열(str)이 아니라 바이트(bytes)다.
      XML은 파일 첫 줄에 자기 인코딩을 적어두기 때문에, 우리가 임의로
      디코딩하지 않고 바이트 그대로 파서에게 넘기는 편이 안전하다.

    알아둘 문법:
      - requests.get(url)은 웹 브라우저가 주소창에 URL을 치는 것과 같다.
        응답 객체를 돌려주고, .content에 받은 데이터가 바이트로 들어 있다.
      - resp.raise_for_status()는 응답 코드가 404나 500 같은 실패면 그 자리에서
        예외를 던진다. 이게 없으면 에러 페이지 HTML을 zip으로 착각해 열려다가
        훨씬 뒤에서 이상한 에러가 난다. 즉 '문제를 일찍 드러내는' 안전장치다.
      - io.BytesIO(...)는 메모리에 있는 바이트를 '파일인 척' 감싸주는 도구다.
        zipfile은 파일을 열도록 만들어져 있어서, 디스크에 저장하지 않고
        메모리에서 바로 압축을 풀려면 이렇게 감싸야 한다.
      - with 문은 블록이 끝날 때 자원(여기서는 zip 파일)을 자동으로 닫아준다.
    """
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = RAW_DIR / "cwec_latest.xml"

    if cache and cache_path.exists():
        print(f"[CWE] 캐시 사용: {cache_path}")
        return cache_path.read_bytes()

    print(f"[CWE] 다운로드: {CWE_ZIP_URL}")
    resp = requests.get(CWE_ZIP_URL, timeout=120)
    resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        xml_name = next(n for n in z.namelist() if n.lower().endswith(".xml"))
        xml_bytes = z.read(xml_name)

    cache_path.write_bytes(xml_bytes)
    print(f"[CWE] 저장: {cache_path} ({len(xml_bytes) / 1_000_000:.1f} MB)")
    return xml_bytes


def _text_of(element: ET.Element | None) -> str:
    """XML 태그 하나에 들어 있는 글자를 전부 모아 한 줄 문자열로 만든다.

    왜 필요한가:
      XML 태그의 내용이 항상 순수한 글자만은 아니다. MITRE의 CWE 설명은
      HTML 서식을 섞어 쓴다. 예를 들면 이런 모양이다.

          <Extended_Description>
            <xhtml:p>첫 문단입니다.</xhtml:p>
            <xhtml:p>둘째 문단입니다.</xhtml:p>
          </Extended_Description>

      이때 element.text를 읽으면 '<Extended_Description> 바로 뒤, 첫 자식 태그
      앞'에 있는 글자만 나온다. 위 예시에서는 줄바꿈과 공백뿐이라 사실상
      빈 문자열이 나오고, 정작 본문은 통째로 사라진다. 초보자가 XML을 다룰 때
      가장 자주 겪는 함정이다.

    어떻게 해결하나:
      itertext()는 그 태그 아래 있는 모든 자손의 글자를 순서대로 하나씩
      돌려주는 반복자다. "".join(...)으로 그것들을 전부 이어붙이면 본문이
      빠짐없이 모인다.

      그 다음 " ".join(문자열.split())은 공백을 정리하는 관용적인 표현이다.
      split()은 인자 없이 부르면 연속된 공백·탭·줄바꿈을 한꺼번에 구분자로
      보고 단어 목록을 만들어 준다. 그것을 공백 하나로 다시 이어붙이면
      들쭉날쭉하던 여백이 깔끔한 한 줄이 된다.

    None을 받으면:
      찾으려던 태그가 없을 때 호출부가 None을 넘길 수 있다. 그럴 때마다
      호출부에서 if로 검사하게 하면 코드가 지저분해지므로, 여기서 빈 문자열을
      돌려주어 "없으면 빈 값"으로 자연스럽게 흘러가게 한다.
    """
    if element is None:
        return ""
    return " ".join("".join(element.itertext()).split())


def _local(tag: str) -> str:
    """네임스페이스가 붙은 XML 태그 이름에서 순수한 이름만 잘라낸다.

    왜 필요한가:
      XML에는 '네임스페이스(namespace)'라는 개념이 있다. 서로 다른 조직이 만든
      XML에서 같은 태그 이름이 충돌하지 않도록, 태그마다 소속을 나타내는 URL을
      붙이는 장치다. 파이썬의 XML 파서는 이 소속을 태그 이름 앞에 중괄호로
      붙여서 보여준다.

          실제 파싱 결과: '{http://cwe.mitre.org/cwe-7}Weakness'
          우리가 원하는 것:                          'Weakness'

      게다가 이 URL은 CWE 규격 버전이 오르면 cwe-7에서 cwe-8로 바뀔 수 있다.
      URL을 코드에 그대로 적어두면 나중에 MITRE가 버전을 올리는 순간 아무것도
      못 찾게 된다. 그래서 URL 부분은 아예 무시하고 뒤쪽 이름만 쓴다.

    어떻게 동작하나:
      rsplit("}", 1)은 오른쪽에서부터 '}' 를 기준으로 딱 한 번만 자른다.
      결과는 ['{http://...', 'Weakness'] 같은 리스트이고, [-1]은 그 마지막
      요소, 즉 순수한 태그 이름이다. 네임스페이스가 없어서 '}'가 아예 없으면
      자를 곳이 없으므로 원래 문자열이 그대로 나온다. 어느 쪽이든 안전하다.
    """
    return tag.rsplit("}", 1)[-1]


def _find_child(parent: ET.Element, name: str) -> ET.Element | None:
    """어떤 XML 태그의 바로 아래 자식 중, 지정한 이름의 '첫 번째' 하나를 찾는다.

    파라미터:
      parent -- 뒤질 대상이 되는 부모 태그
      name   -- 찾고 싶은 자식 태그 이름. 네임스페이스는 빼고 'Description'처럼
                순수한 이름만 적는다.

    반환값:
      찾으면 그 태그 객체, 없으면 None. 'Extended_Description'처럼 CWE 항목에
      따라 있을 수도 없을 수도 있는 태그가 많아서, 없는 경우를 예외가 아니라
      None으로 돌려주는 편이 쓰기 편하다.

    참고:
      파이썬 XML 파서에는 원래 parent.find("Description") 같은 편리한 메서드가
      있다. 하지만 그 메서드는 네임스페이스까지 정확히 일치해야 찾아주기 때문에
      URL을 매번 적어야 한다. 위 _local()에서 설명한 이유로 URL에 의존하고 싶지
      않아서, 자식을 직접 순회하며 이름만 비교하는 방식을 택했다.

      for child in parent: 처럼 태그 객체를 for에 바로 넣으면 '바로 아래 자식'만
      차례로 나온다(손자 이하는 나오지 않는다). 이 점이 모든 자손을 훑는
      itertext()와 다르다.
    """
    for child in parent:
        if _local(child.tag) == name:
            return child
    return None


def _iter_children(parent: ET.Element, name: str):
    """어떤 XML 태그의 바로 아래 자식 중, 지정한 이름을 가진 것을 '전부' 돌려준다.

    _find_child가 첫 번째 하나만 찾는 함수라면, 이쪽은 같은 이름의 자식이
    여러 개일 때 쓴다. 예를 들어 <Weaknesses> 아래에는 <Weakness>가 969개,
    <Potential_Mitigations> 아래에는 <Mitigation>이 여러 개 들어 있다.

    return이 아니라 yield를 쓰는 이유:
      yield를 쓴 함수를 '제너레이터(generator)'라고 부른다. 보통 함수는 return을
      만나면 값을 하나 주고 끝나지만, 제너레이터는 yield에서 값을 하나 건네주고
      그 자리에 멈춰 있다가, 호출부가 다음 값을 요구하면 거기서부터 이어서
      실행한다.

      덕분에 969개짜리 리스트를 메모리에 통째로 만들지 않고 한 개씩 흘려보낼 수
      있어 메모리를 아낀다. 쓰는 쪽에서는 차이를 느낄 필요 없이 평소처럼
      for 문에 넣으면 된다.

          for weakness in _iter_children(node, "Weakness"):
              ...

      다만 제너레이터는 한 번 끝까지 돌면 소진된다. 같은 결과를 두 번 이상
      순회해야 한다면 list(...)로 감싸 리스트로 만들어 두어야 한다.
    """
    for child in parent:
        if _local(child.tag) == name:
            yield child


def parse_cwe_catalog(xml_bytes: bytes) -> list[dict]:
    """MITRE의 거대한 CWE XML을, 이 프로젝트가 쓰기 좋은 딕셔너리 목록으로 바꾼다.

    무슨 일을 하나:
      download_cwe_xml()이 가져온 18MB짜리 XML은 태그가 수십 종류로 얽혀 있어
      그대로 쓰기 어렵다. 이 함수는 그중 우리에게 필요한 여섯 가지 정보만 뽑아,
      납작하고 단순한 형태로 정리한다. 이런 작업을 데이터 처리에서 '파싱해서
      스키마에 맞춘다'고 말한다.

    반환값의 생김새 (리스트 안에 딕셔너리가 여러 개):
      [
        {
          "cwe_id": "CWE-89",
          "name": "Improper Neutralization of Special Elements used in an SQL Command",
          "abstraction": "Base",              # 이 항목이 얼마나 추상적인지
          "status": "Stable",                 # MITRE가 매긴 문서 상태
          "description": "짧은 정의 한 문단",
          "extended_description": "더 긴 상세 설명",
          "potential_mitigations": "완화 방법들을 줄바꿈으로 이어붙인 글",
          "observed_examples": "실제 CVE 사례들을 줄바꿈으로 이어붙인 글",
        },
        ...
      ]

      마지막 네 필드는 모두 '문자열' 하나다. 원래 XML에서는 완화 방법이
      <Mitigation> 태그 여러 개로 쪼개져 있지만, 다음 단계인 1_chunk.py가
      섹션 하나를 문자열 하나로 다루도록 되어 있어 여기서 미리 합쳐 둔다.
      이렇게 앞 단계가 뒤 단계의 입력 형식을 맞춰주는 것이 파이프라인의 핵심이다.

    XML의 구조 (실제 파일을 아주 단순화한 모습):
      <Weakness_Catalog>
        <Weaknesses>
          <Weakness ID="89" Name="..." Abstraction="Base" Status="Stable">
            <Description>...</Description>
            <Extended_Description>...</Extended_Description>
            <Potential_Mitigations>
              <Mitigation><Phase>Implementation</Phase><Description>...</Description></Mitigation>
              <Mitigation>...</Mitigation>
            </Potential_Mitigations>
            <Observed_Examples>
              <Observed_Example><Reference>CVE-2021-1234</Reference><Description>...</Description></Observed_Example>
            </Observed_Examples>
          </Weakness>
          ... (969개)
        </Weaknesses>
        <Categories> ... </Categories>
      </Weakness_Catalog>

      ID나 Name처럼 여는 태그 안에 적힌 값은 '속성(attribute)'이라 부르고
      weakness.get("Name")으로 읽는다. Description처럼 태그로 감싸인 값은
      '자식 요소(child element)'라서 _find_child()로 찾은 뒤 _text_of()로 읽는다.
      이 둘을 읽는 방법이 다르다는 점이 초보자가 자주 헷갈리는 부분이다.

    예외:
      <Weaknesses> 태그를 못 찾으면 RuntimeError를 던진다. MITRE가 파일 구조를
      바꿨거나 엉뚱한 파일을 받았다는 뜻인데, 이때 빈 리스트를 조용히 돌려주면
      한참 뒤 '검색 결과가 없다'는 엉뚱한 증상으로 나타나 원인을 찾기 어렵다.
      문제가 생긴 자리에서 바로 멈추는 편이 디버깅에 훨씬 유리하다.
    """
    root = ET.fromstring(xml_bytes)
    weaknesses_node = _find_child(root, "Weaknesses")
    if weaknesses_node is None:
        raise RuntimeError("CWE XML에서 <Weaknesses> 노드를 찾지 못했습니다.")

    catalog = []
    for weakness in _iter_children(weaknesses_node, "Weakness"):
        cwe_id = f"CWE-{weakness.get('ID')}"

        # 완화 방법: <Mitigation> 여러 개를 'Phase: 본문' 형태로 이어붙인다.
        mitigations = []
        mit_node = _find_child(weakness, "Potential_Mitigations")
        if mit_node is not None:
            for mitigation in _iter_children(mit_node, "Mitigation"):
                phase = _text_of(_find_child(mitigation, "Phase"))
                body = _text_of(_find_child(mitigation, "Description"))
                if not body:
                    continue
                mitigations.append(f"[{phase}] {body}" if phase else body)

        # 실제 사례: <Observed_Example>은 실제 CVE ID와 한 줄 설명을 갖는다.
        examples = []
        ex_node = _find_child(weakness, "Observed_Examples")
        if ex_node is not None:
            for example in _iter_children(ex_node, "Observed_Example"):
                ref = _text_of(_find_child(example, "Reference"))
                body = _text_of(_find_child(example, "Description"))
                if not body:
                    continue
                examples.append(f"{ref}: {body}" if ref else body)

        catalog.append({
            "cwe_id": cwe_id,
            "name": weakness.get("Name", ""),
            "abstraction": weakness.get("Abstraction", ""),
            "status": weakness.get("Status", ""),
            "description": _text_of(_find_child(weakness, "Description")),
            "extended_description": _text_of(_find_child(weakness, "Extended_Description")),
            "potential_mitigations": "\n".join(mitigations),
            "observed_examples": "\n".join(examples),
        })

    # NVD는 개별 Weakness가 아니라 상위 Category(CWE-264 '권한/접근 제어' 등)로
    # 매핑해둔 CVE도 많다. Category는 <Weaknesses>가 아니라 <Categories>에 들어
    # 있고 본문 필드도 <Summary> 하나뿐이라, 스키마를 맞춰 함께 담는다.
    categories_node = _find_child(root, "Categories")
    if categories_node is not None:
        for category in _iter_children(categories_node, "Category"):
            catalog.append({
                "cwe_id": f"CWE-{category.get('ID')}",
                "name": category.get("Name", ""),
                "abstraction": "Category",
                "status": category.get("Status", ""),
                "description": _text_of(_find_child(category, "Summary")),
                "extended_description": "",
                "potential_mitigations": "",
                "observed_examples": "",
            })

    return catalog


# --------------------------------------------------------------------------
# 2) NVD CVE -> CWE 매핑
# --------------------------------------------------------------------------

def _extract_cwe_ids(cve: dict) -> list[str]:
    """NVD가 준 CVE 정보 덩어리에서, 이 CVE가 어떤 CWE 유형인지를 뽑아낸다.

    무슨 일을 하나:
      NVD API는 CVE 하나를 아주 깊게 중첩된 JSON으로 돌려준다. 그중 CWE 정보는
      아래처럼 리스트 안의 리스트 속에 들어 있다.

          {
            "id": "CVE-2021-44228",
            "weaknesses": [
              { "source": "...", "type": "Primary",
                "description": [ { "lang": "en", "value": "CWE-502" } ] },
              { "source": "...", "type": "Secondary",
                "description": [ { "lang": "en", "value": "CWE-917" } ] }
            ]
          }

      그래서 for 문을 두 번 겹쳐 바깥 weaknesses를 돌고, 그 안의 description을
      다시 돌면서 value 값을 모은다.

    왜 그냥 다 담지 않고 걸러내나:
      NVD는 분석가가 아직 CWE를 지정하지 못한 CVE에도 자리를 비워두지 않고
      'NVD-CWE-noinfo'(정보 없음)나 'NVD-CWE-Other'(기타) 같은 값을 채워 넣는다.
      이건 진짜 CWE 번호가 아니라서 MITRE 카탈로그에는 존재하지 않는다.
      그대로 두면 나중에 검색할 때 아무 문서도 못 찾는 유령 ID가 된다.

      그래서 두 가지 조건을 모두 만족하는 것만 남긴다.
        value.startswith("CWE-")  -- 'CWE-'로 시작하고
        value[4:].isdigit()       -- 그 뒤가 전부 숫자여야 한다
      value[4:]는 앞 네 글자('CWE-')를 잘라낸 나머지를 뜻하는 슬라이싱이다.
      'CWE-502'면 '502'가 되어 isdigit()이 True, 'NVD-CWE-noinfo'는 애초에
      'CWE-'로 시작하지 않아 첫 조건에서 걸러진다.

    중복 제거:
      서로 다른 기관(source)이 같은 CWE를 지정하는 일이 흔해서 같은 번호가
      두 번 나올 수 있다. if value not in ids로 이미 담은 것은 건너뛴다.
      set()을 쓰면 더 빠르지만, set은 순서를 보장하지 않는다. 여기서는 NVD가
      매긴 순서(Primary가 먼저)가 곧 중요도 순이라 그 순서를 지키려고
      일부러 리스트를 썼다.

    반환값:
      ['CWE-20', 'CWE-400', 'CWE-502', 'CWE-917'] 같은 문자열 리스트.
      쓸 만한 CWE가 하나도 없으면 빈 리스트 []를 돌려준다.
    """
    ids = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value[4:].isdigit():
                if value not in ids:
                    ids.append(value)
    return ids


def _extract_cvss(cve: dict) -> tuple[float | None, str]:
    """CVE의 위험도 점수(CVSS)와 심각도 등급을 뽑아낸다.

    CVSS가 뭔가:
      Common Vulnerability Scoring System의 약자로, 취약점이 얼마나 위험한지를
      0.0부터 10.0 사이 숫자로 매긴 국제 표준 점수다. 점수 구간마다 등급 이름이
      붙는다: LOW(0.1~3.9), MEDIUM(4.0~6.9), HIGH(7.0~8.9), CRITICAL(9.0~10.0).
      Log4Shell(CVE-2021-44228)은 만점인 10.0 CRITICAL이다.

    왜 이렇게 복잡한가:
      CVSS는 버전이 여러 번 바뀌었고(v2 -> v3.0 -> v3.1), NVD는 옛날 CVE에는
      옛 버전 점수만, 최근 CVE에는 새 버전 점수를 붙여 놓았다. 게다가 한 CVE에
      여러 버전 점수가 동시에 달려 있기도 하다. JSON에서는 버전마다 열쇠 이름이
      아예 다르다.

          "metrics": {
            "cvssMetricV31": [ { "cvssData": { "baseScore": 10.0,
                                               "baseSeverity": "CRITICAL" } } ],
            "cvssMetricV2":  [ { "cvssData": { "baseScore": 7.5 } } ]
          }

      그래서 for 문으로 v3.1 -> v3.0 -> v2 순서로 훑다가 처음 발견되는 것을
      쓰고 곧바로 return한다. 이렇게 '가장 좋은 것부터 찾아보고 없으면 차선책'
      으로 내려가는 방식을 폴백(fallback)이라고 부른다.

    baseSeverity를 두 군데서 찾는 이유:
      severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
      v3에서는 등급이 cvssData 안에 있지만 v2에서는 그 바깥에 있다. 파이썬의
      or는 앞의 값이 비어 있으면(None이나 빈 문자열) 뒤의 값을 택하므로,
      이 한 줄로 두 위치를 차례로 시도하고 둘 다 없으면 빈 문자열이 된다.

    반환값:
      (점수, 등급) 두 개짜리 튜플. 예: (10.0, "CRITICAL")
      점수가 아예 없는 CVE도 있어서 그때는 (None, "")을 돌려준다. 호출부에서
      0.0이 아니라 None으로 두는 이유는, '점수가 0점'인 것과 '점수를 아직 안
      매긴 것'은 전혀 다른 의미이기 때문이다.

      함수가 값을 두 개 돌려주는 것처럼 보이지만 실제로는 튜플 하나다.
      받는 쪽에서 score, severity = _extract_cvss(cve) 처럼 한 번에 풀어 쓸 수
      있는데, 이를 언패킹(unpacking)이라고 한다.
    """
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
        return score, severity
    return None, ""


def _extract_product(cve: dict) -> str:
    """이 CVE가 어떤 제품에 영향을 주는지, 사람이 읽을 수 있는 이름 하나를 만든다.

    CPE가 뭔가:
      Common Platform Enumeration. 제품 이름을 사람마다 다르게 적으면(MS Windows,
      Microsoft Windows, 윈도우...) 기계가 대조할 수 없으니, 콜론으로 칸을 나눈
      표준 문자열로 적기로 한 규격이다.

          cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
           │    │  │   │      │      └ 5번 칸: 버전
           │    │  │   │      └ 4번 칸: 제품명
           │    │  │   └ 3번 칸: 제조사
           │    │  └ 2번 칸: 종류 (a=응용프로그램, o=운영체제, h=하드웨어)
           │    └ CPE 규격 버전
           └ 고정 접두사

      split(":")으로 잘라 리스트로 만들면 parts[3]이 제조사, parts[4]가 제품명,
      parts[5]가 버전이 된다. 칸 번호가 0부터 시작한다는 점에 주의한다.
      len(parts) < 6 검사는 형식이 깨진 값이 들어와도 IndexError로 죽지 않게
      하는 방어 코드다.

    for 문이 세 겹인 이유:
      NVD는 '어떤 조건에서 취약한가'를 configurations -> nodes -> cpeMatch 라는
      3단 구조로 표현한다. "윈도우이면서 동시에 특정 버전일 때만 취약" 같은
      복합 조건을 담기 위해서다. 우리는 대표 이름 하나만 있으면 되므로,
      가장 먼저 만나는 유효한 항목에서 return으로 곧장 빠져나온다.
      return은 for 문이 몇 겹이든 함수 전체를 즉시 끝낸다.

      match.get("vulnerable")를 확인하는 이유는, 이 목록에 '취약한 제품'뿐 아니라
      '조건을 한정하기 위해 함께 적어둔, 그 자체로는 안 취약한 제품'도 섞여
      있기 때문이다.

    이름 다듬기:
      CPE는 공백을 쓸 수 없어서 밑줄로 대신한다(internet_explorer). 그래서
      replace("_", " ")로 되돌려 'microsoft internet explorer'로 만든다.
      버전 칸의 '*'는 '모든 버전', '-'는 '해당 없음'을 뜻하는 특수 기호라
      그대로 붙이면 이상해지므로 그럴 때는 버전을 생략한다.

    CPE가 없으면 (폴백):
      아직 분석이 끝나지 않아 CPE 목록이 비어 있는 CVE도 많다. 그때는 영문
      설명의 앞 80글자를 잘라 대신 쓴다. text[:80]은 앞에서 80글자만 취하는
      슬라이싱이고, 원문이 그보다 길었으면 잘렸다는 표시로 '...'을 붙인다.
      설명조차 없으면 최후의 수단으로 "(unknown)"을 돌려준다. 이렇게 어떤
      경우에도 문자열 하나는 반드시 돌려주므로, 호출부는 None 걱정을 안 해도 된다.

    주의 (이 값의 한계):
      한 CVE가 수십 개 제품에 영향을 줘도 그중 맨 처음 것 하나만 보여준다.
      실제로 Log4Shell은 이 함수를 거치면 'siemens ... firmware'로 표시되는데,
      틀린 건 아니지만 대표성이 없다. 화면에 맥락을 보여주는 용도로만 쓰고,
      영향 범위를 판단하는 근거로는 절대 쓰면 안 된다.
    """
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                label = f"{vendor} {product}".replace("_", " ")
                if version not in ("*", "-"):
                    label += f" {version}"
                return label.strip()

    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            text = " ".join(desc.get("value", "").split())
            return text[:80] + ("..." if len(text) > 80 else "")
    return "(unknown)"


def _to_mapping(cve: dict) -> dict | None:
    """NVD가 준 CVE 하나를, 우리가 저장할 간단한 딕셔너리 한 줄로 변환한다.

    무슨 일을 하나:
      바로 앞의 세 함수(_extract_cwe_ids, _extract_cvss, _extract_product)를
      차례로 불러서 결과를 하나의 딕셔너리로 조립한다. 복잡한 NVD 원본에서
      우리에게 필요한 여섯 가지만 남기는 마지막 단계다.

      이렇게 '조립 담당' 함수를 따로 두는 이유는, 이 프로젝트에서 CVE를 받아오는
      경로가 두 개(fetch_specific_cves와 fetch_cve_mappings)이기 때문이다.
      두 곳이 각자 조립하면 나중에 필드를 하나 추가할 때 두 군데를 고쳐야 하고,
      한쪽만 고치면 데이터 형식이 미묘하게 어긋난다. 공통 부분을 한 함수로
      모아두면 고칠 곳이 한 군데뿐이다.

    반환값:
      성공하면 아래 모양의 딕셔너리.
        {
          "cve_id": "CVE-2021-44228",
          "cwe_ids": ["CWE-20", "CWE-400", "CWE-502", "CWE-917"],
          "product": "siemens 6bk1602-0aa12-0tp0 firmware",
          "cvss_score": 10.0,
          "severity": "CRITICAL",
          "published": "2021-12-10T10:15:09.143",
        }

      연결된 CWE가 하나도 없으면 None을 돌려준다. 이 파이프라인은 'CVE로 CWE
      문서를 찾는' 구조라서, CWE가 없는 CVE는 검색할 대상이 아예 없어 쓸모가
      없기 때문이다. 호출부는 결과가 None인지 보고 그 CVE를 건너뛴다.

      참고로 cve["id"]는 대괄호로, cve.get("published", "")는 .get()으로 읽는다.
      대괄호는 열쇠가 없으면 KeyError로 죽고, .get()은 없으면 기본값을 준다.
      id는 반드시 있어야 하는 값이라 없으면 차라리 죽는 게 맞고, published는
      없어도 괜찮은 값이라 빈 문자열로 넘어가게 한 것이다. 의도적인 구분이다.
    """
    cwe_ids = _extract_cwe_ids(cve)
    if not cwe_ids:
        # CWE가 안 붙은 CVE는 이 파이프라인에서 쓸 수 없다.
        return None
    score, severity_label = _extract_cvss(cve)
    return {
        "cve_id": cve["id"],
        "cwe_ids": cwe_ids,
        "product": _extract_product(cve),
        "cvss_score": score,
        "severity": severity_label,
        "published": cve.get("published", ""),
    }


def fetch_specific_cves(cve_ids: list[str], api_key: str | None) -> list[dict]:
    """내가 지정한 CVE ID들을 NVD에서 하나씩 직접 조회한다.

    언제 쓰나:
      명령줄에서 --cve-ids로 특정 CVE를 콕 집었을 때 쓰인다. 교육용으로는
      Log4Shell(CVE-2021-44228)이나 Heartbleed(CVE-2014-0160)처럼 유명한 사례가
      데이터에 꼭 들어 있어야 설명하기 좋은데, 아래의 fetch_cve_mappings()는
      조건에 맞는 것을 앞에서부터 가져오기 때문에 원하는 CVE가 안 걸릴 수 있다.
      그래서 '반드시 포함시킬 목록'을 따로 받는 통로를 만들었다.

    왜 for 문으로 한 건씩 부르나:
      NVD API의 cveId 파라미터는 CVE ID를 딱 하나만 받는다. 여러 개를 쉼표로
      묶어 보내는 문법이 없어서, 어쩔 수 없이 개수만큼 요청을 반복한다.

    time.sleep()이 있는 이유:
      NVD는 짧은 시간에 요청이 몰리면 접속을 차단한다(rate limit). 이를 피하려고
      요청 사이에 일부러 멈춘다. API 키가 없으면 6초, 있으면 0.7초다. 초보자가
      API를 다룰 때 가장 흔히 저지르는 실수가 반복문으로 쉬지 않고 요청을 퍼붓는
      것이고, 그러면 대개 몇 분에서 몇 시간 동안 차단당한다.

      if i < len(cve_ids) - 1 조건은 '마지막 요청 뒤에는 쉬지 않기' 위한 것이다.
      어차피 더 보낼 요청이 없는데 6초를 기다리는 건 낭비다. enumerate()는
      반복할 때마다 순번 i와 값을 함께 주는 내장 함수로, 지금이 몇 번째인지
      알아야 이런 판단을 할 수 있다.

    404를 예외로 다루지 않는 이유:
      오타가 났거나 아직 공개되지 않은 CVE ID면 NVD가 404를 준다. 이때
      raise_for_status()로 예외를 던지면 뒤에 남은 CVE들까지 조회가 통째로
      중단된다. ID 하나 틀렸다고 전체 작업을 버릴 이유는 없으므로, 안내만
      출력하고 다음으로 넘어간다. 반대로 500번대 서버 오류처럼 진짜 문제라면
      raise_for_status()가 예외를 던져 즉시 멈춘다.

    반환값:
      성공적으로 조회되고 CWE까지 붙어 있는 CVE들의 딕셔너리 리스트.
      404였거나 CWE가 없던 ID는 그냥 빠진다. 즉 넘긴 개수와 돌려받는 개수가
      다를 수 있다.
    """
    headers = {"apiKey": api_key} if api_key else {}
    sleep_s = NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_NO_KEY

    mappings = []
    for i, cve_id in enumerate(cve_ids):
        resp = requests.get(NVD_API_URL, headers=headers,
                            params={"cveId": cve_id}, timeout=120)
        if resp.status_code == 404:
            print(f"[NVD] {cve_id}: 존재하지 않는 CVE ID")
        else:
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
            record = _to_mapping(items[0]["cve"]) if items else None
            if record:
                mappings.append(record)
                print(f"[NVD] {cve_id} -> {', '.join(record['cwe_ids'])}")
            else:
                print(f"[NVD] {cve_id}: CWE 매핑이 없어 건너뜀")
        if i < len(cve_ids) - 1:
            time.sleep(sleep_s)
    return mappings


def fetch_cve_mappings(
    max_cves: int,
    source: str,
    days: int,
    severity: str | None,
    api_key: str | None,
) -> list[dict]:
    """조건에 맞는 CVE를 NVD에서 여러 페이지에 걸쳐 긁어모은다.

    무슨 일을 하나:
      "악용이 확인된 취약점" 또는 "최근 N일 안에 공개된 취약점" 같은 조건을 주면,
      거기 해당하는 CVE를 목표 개수만큼 모아 온다. 이 프로젝트에서 데이터의
      대부분을 채우는 함수다.

    페이지네이션(pagination)이란:
      조건에 맞는 CVE가 1695건이어도 서버가 한 번에 다 주지는 않는다. 트럭 한
      대에 짐을 다 못 실으면 여러 번 나눠 나르듯, API도 정해진 개수씩 나눠 준다.
      그래서 두 값을 주고받는다.

        startIndex     -- 몇 번째부터 달라는 시작 위치
        resultsPerPage -- 한 번에 몇 개씩 달라는 개수

      while 문을 돌 때마다 startIndex를 받은 개수만큼 늘려 다음 묶음을 요청한다.
      이 '나눠 받기' 패턴은 거의 모든 웹 API에 나오므로 익혀둘 가치가 있다.

    파라미터:
      max_cves -- 목표 개수. 이만큼 모으면 중간에라도 그만둔다.
      source   -- "kev"면 CISA가 '실제 공격에 쓰인 것이 확인됐다'고 등록한
                  취약점만 가져온다. 교육용으로 특히 좋은데, 교과서적 예시가
                  아니라 현실에서 실제로 피해를 낸 사건들이기 때문이다.
                  "recent"면 최근 days일 안에 공개된 CVE를 가져온다.
      days     -- source가 "recent"일 때만 의미가 있다. NVD가 한 번의 질의에서
                  최대 120일 범위만 허용해서 그 이상은 넘길 수 없다.
      severity -- "CRITICAL"처럼 심각도로 한 번 더 거르고 싶을 때. None이면 전부.
      api_key  -- 있으면 요청 간 대기 시간이 6초에서 0.7초로 짧아진다.

    반복이 끝나는 세 가지 경우:
      1. 목표 개수를 채웠을 때        -> while 조건이 거짓이 되어 종료
      2. 서버가 빈 목록을 줬을 때      -> 더 가져올 게 없으므로 break
      3. 전체 결과 개수를 다 훑었을 때 -> start_index가 total_results 이상이면 break

      셋 다 없으면 무한 루프에 빠질 수 있어서, 끝나는 조건을 빠짐없이 두는 것이
      반복문으로 API를 호출할 때 가장 중요한 부분이다.

    403 오류를 따로 처리하는 이유:
      403은 대개 '요청을 너무 자주 보내서 차단됐다'는 뜻이다. 기본 예외 메시지는
      그냥 'Forbidden'이라 원인을 짐작하기 어려우므로, 무엇을 해야 하는지
      (기다렸다 재시도하거나 API 키를 설정하라고) 한국어로 알려주는 메시지로
      바꿔서 던진다. 좋은 에러 메시지는 사용자가 다음에 할 일을 알려준다.

    total_results가 None에서 시작하는 이유:
      전체가 몇 건인지는 첫 응답을 받아봐야 안다. 그래서 '아직 모른다'는 뜻으로
      None을 넣어두고, 첫 응답에서 값을 채우면서 안내 문구를 딱 한 번만 출력한다.
      0으로 초기화하면 '아직 모름'과 '진짜 0건'을 구별할 수 없다.
    """
    headers = {"apiKey": api_key} if api_key else {}
    sleep_s = NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_NO_KEY

    base_params: dict[str, object] = {}
    if source == "kev":
        # KEV = CISA Known Exploited Vulnerabilities.
        # 실제로 악용이 확인된 취약점이라 교육용 예제로 특히 적합하다.
        base_params["hasKev"] = ""
    elif source == "recent":
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        # NVD는 한 번의 질의에서 최대 120일 범위만 허용한다.
        base_params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        base_params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    else:
        raise ValueError(f"알 수 없는 source: {source}")

    if severity:
        base_params["cvssV3Severity"] = severity

    mappings: list[dict] = []
    start_index = 0
    total_results = None

    while len(mappings) < max_cves:
        params = dict(base_params)
        params["startIndex"] = start_index
        params["resultsPerPage"] = NVD_PAGE_SIZE

        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=120)
        if resp.status_code == 403:
            raise RuntimeError(
                "NVD가 403을 반환했습니다. rate limit일 가능성이 큽니다. "
                "잠시 후 다시 시도하거나 NVD_API_KEY를 설정하세요."
            )
        resp.raise_for_status()
        payload = resp.json()

        if total_results is None:
            total_results = payload.get("totalResults", 0)
            print(f"[NVD] 조건에 맞는 CVE 총 {total_results}건 (최대 {max_cves}건 수집)")

        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            record = _to_mapping(item["cve"])
            if record is None:
                continue
            mappings.append(record)
            if len(mappings) >= max_cves:
                break

        start_index += len(vulnerabilities)
        print(f"[NVD] {start_index}/{total_results} 조회, 매핑 확보 {len(mappings)}건")

        if start_index >= (total_results or 0):
            break
        time.sleep(sleep_s)

    return mappings


# --------------------------------------------------------------------------

def filter_catalog_to_mapped(catalog: list[dict], mappings: list[dict]) -> list[dict]:
    """CWE 카탈로그에서, 실제로 수집한 CVE가 가리키는 CWE만 골라 남긴다.

    왜 걸러내나:
      MITRE 카탈로그에는 CWE가 1391개 들어 있지만, 우리가 모은 CVE 202건이
      실제로 가리키는 것은 57개뿐이다. 나머지 1334개는 이 데이터셋에서는 절대
      검색될 일이 없다. 그런데도 전부 넣으면 이런 손해를 본다.

        - 임베딩할 문서가 20배 이상 늘어 시간이 오래 걸린다.
        - OpenAI 같은 유료 임베딩을 쓰면 그만큼 돈이 더 나간다.
        - 벡터 DB 용량이 커지고 검색도 느려진다.

      필요한 것만 담는 이 판단이 RAG 시스템을 만들 때 실무에서 꽤 중요하다.

    집합(set)을 쓰는 이유:
      used = {cwe_id for m in mappings for cwe_id in m["cwe_ids"]}
      중괄호로 감싼 이 문법을 '집합 컴프리헨션'이라 한다. mappings를 돌면서
      각 CVE의 cwe_ids를 다시 돌아 모든 CWE 번호를 한 곳에 모으는데, 집합이라
      중복은 자동으로 사라진다.

      집합을 쓰는 진짜 이유는 속도다. 다음 줄에서 카탈로그 1391개마다
      "이 CWE가 used 안에 있나?"를 확인하는데, 리스트에서 in 검사는 처음부터
      끝까지 훑어야 하지만 집합은 거의 즉시 답한다. 데이터가 커질수록 이 차이가
      크게 벌어진다.

    빠진 CWE를 경고하는 이유:
      missing은 'CVE는 이 CWE를 가리키는데 카탈로그에는 그 항목이 없는' 경우다.
      MITRE가 폐기(Deprecated)했거나 카탈로그 구조가 바뀌면 생길 수 있다.
      이런 CWE를 가리키는 CVE는 나중에 검색해도 아무 문서가 안 나오므로,
      조용히 넘어가지 말고 미리 알려준다. 집합끼리의 뺄셈(used - {...})은
      '앞에는 있고 뒤에는 없는 것'만 남기는 연산이다.

      sorted(missing)[:10]으로 최대 10개만 출력하는 것은, 혹시 수백 개가
      빠졌을 때 화면이 경고로 뒤덮이는 것을 막기 위해서다.

    반환값:
      걸러낸 카탈로그 리스트. 원본 catalog는 건드리지 않고 새 리스트를 만들어
      돌려준다. 이렇게 입력을 바꾸지 않는 함수는 동작을 예측하기 쉽고,
      같은 입력으로 몇 번을 불러도 결과가 같아 디버깅이 편하다.
    """
    used = {cwe_id for m in mappings for cwe_id in m["cwe_ids"]}
    kept = [c for c in catalog if c["cwe_id"] in used]

    missing = used - {c["cwe_id"] for c in kept}
    if missing:
        # 폐기(Deprecated)된 CWE는 카탈로그의 Weaknesses에 없을 수 있다.
        print(f"[경고] 카탈로그에서 찾지 못한 CWE {len(missing)}개: {sorted(missing)[:10]}")
    return kept


def main() -> None:
    """이 스크립트의 시작점. 위에서 만든 함수들을 순서대로 불러 전체 작업을 지휘한다.

    전체 흐름:
      1. 명령줄 옵션을 읽는다 (--source, --max-cves, --cve-ids ...).
      2. .env에서 NVD API 키를 찾아본다. 없어도 그냥 진행한다.
      3. MITRE CWE XML을 받아 파싱한다        -> download_cwe_xml, parse_cwe_catalog
      4. NVD에서 CVE 목록을 모은다            -> fetch_specific_cves, fetch_cve_mappings
      5. 중복 CVE를 제거한다.
      6. 필요 없는 CWE를 걸러낸다             -> filter_catalog_to_mapped
      7. 두 개의 JSON 파일로 저장한다.

      이렇게 main()은 판단과 순서만 담당하고 실제 일은 작은 함수들에 맡기는
      구조가 읽기도 쉽고 각 함수를 따로 시험하기도 좋다.

    argparse란:
      명령줄에서 준 옵션을 대신 읽어주는 파이썬 표준 도구다. add_argument로
      옵션을 하나씩 등록해두면 parse_args()가 알아서 해석해준다. 덤으로
      `python src/0_fetch_real_data.py --help`를 치면 등록한 help 문구를 모아
      사용법을 출력해주고, 잘못된 값(--severity WRONG 등)은 알아서 막아준다.

      옵션 이름의 하이픈은 밑줄로 바뀌어 담긴다. --max-cves는 args.max_cves다.
      action="store_true"는 값을 받지 않고 있으면 True, 없으면 False가 되는
      스위치형 옵션을 뜻한다.

    load_dotenv()를 try로 감싼 이유:
      프로젝트 루트의 .env 파일을 읽어 환경변수로 올려주는 기능인데, 이건
      python-dotenv 패키지가 설치돼 있어야 한다. 없어도 이 스크립트는 API 키
      없이 (조금 느리게) 잘 돌아가므로, ImportError가 나면 그냥 넘어간다.
      '있으면 좋지만 없어도 되는' 기능을 다룰 때 쓰는 흔한 방식이다.

    중복 제거 부분:
      --cve-ids로 지정한 CVE가 뒤이은 조건 검색 결과에도 들어 있을 수 있다.
      그대로 두면 같은 CVE가 두 번 저장된다. seen이라는 집합에 이미 본 ID를
      기록하면서, 처음 보는 것만 deduped에 담는 방식으로 걸러낸다. 순서를
      유지하면서 중복만 없애야 할 때 쓰는 표준적인 방법이다.

    저장 부분:
      json.dumps(..., ensure_ascii=False, indent=2)에서
        ensure_ascii=False -- 한글이나 특수문자를 \\uXXXX로 바꾸지 말고 그대로
                              쓰라는 뜻. 사람이 파일을 열어봤을 때 읽을 수 있다.
        indent=2           -- 들여쓰기를 넣어 보기 좋게 저장한다.
      encoding="utf-8"을 명시하는 것도 중요하다. 윈도우는 기본 인코딩이 UTF-8이
      아닐 수 있어서, 생략하면 한글이 깨지거나 저장할 때 에러가 날 수 있다.
    """
    parser = argparse.ArgumentParser(description="MITRE CWE / NVD CVE 실데이터 수집")
    parser.add_argument("--source", choices=["kev", "recent"], default="kev",
                        help="kev=악용 확인된 취약점, recent=최근 N일 공개 CVE (기본: kev)")
    parser.add_argument("--days", type=int, default=30,
                        help="--source recent 일 때 조회 기간, 최대 120 (기본: 30)")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        default=None, help="CVSS v3 심각도 필터 (기본: 없음)")
    parser.add_argument("--max-cves", type=int, default=200,
                        help="수집할 CVE 최대 개수 (기본: 200)")
    parser.add_argument("--cve-ids", nargs="+", default=[], metavar="CVE-ID",
                        help="특정 CVE를 반드시 포함시킨다 (예: --cve-ids CVE-2021-44228)")
    parser.add_argument("--cwe-scope", choices=["mapped", "all"], default="mapped",
                        help="mapped=수집한 CVE가 참조하는 CWE만, all=전체 (기본: mapped)")
    parser.add_argument("--no-cache", action="store_true",
                        help="CWE XML 캐시를 무시하고 다시 받는다")
    args = parser.parse_args()

    if args.days > 120:
        parser.error("NVD는 한 번의 질의에서 최대 120일 범위만 허용합니다.")

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    # .env에 적어둔 이름이 사람마다 다를 수 있어 두 가지를 모두 받는다.
    api_key = os.getenv("NVD_API_KEY") or os.getenv("NVD_KEY")
    print(f"[NVD] API 키 {'사용' if api_key else '없음 (요청 간 6초 대기)'}")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    catalog = parse_cwe_catalog(download_cwe_xml(cache=not args.no_cache))
    print(f"[CWE] 파싱 완료: {len(catalog)}개 항목")

    mappings = []
    if args.cve_ids:
        mappings += fetch_specific_cves(args.cve_ids, api_key)
    if args.max_cves > 0:
        mappings += fetch_cve_mappings(
            max_cves=args.max_cves,
            source=args.source,
            days=args.days,
            severity=args.severity,
            api_key=api_key,
        )

    # --cve-ids로 지정한 CVE가 조회 결과에도 들어 있을 수 있어 중복을 제거한다.
    seen, deduped = set(), []
    for record in mappings:
        if record["cve_id"] in seen:
            continue
        seen.add(record["cve_id"])
        deduped.append(record)
    mappings = deduped
    print(f"[NVD] CWE가 연결된 CVE {len(mappings)}건 확보")

    if args.cwe_scope == "mapped":
        catalog = filter_catalog_to_mapped(catalog, mappings)
        print(f"[CWE] 매핑에 등장하는 CWE만 유지: {len(catalog)}개")

    catalog_path = DATA_DIR / "cwe_catalog.json"
    mapping_path = DATA_DIR / "cve_cwe_mapping.json"
    catalog_path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2), encoding="utf-8")
    mapping_path.write_text(json.dumps(mappings, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n저장 완료:\n  {catalog_path}\n  {mapping_path}")
    print("다음 단계: python src/1_chunk.py")


# 이 파일을 `python src/0_fetch_real_data.py`로 직접 실행할 때만 main()을 부른다.
# 다른 파일이 import 할 때는 __name__이 모듈 이름("0_fetch_real_data")이 되어
# 이 블록이 실행되지 않는다. 덕분에 위 함수들만 가져다 쓰는 것도 가능해진다.
if __name__ == "__main__":
    main()
