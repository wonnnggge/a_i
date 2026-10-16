"""
0단계: 실제 데이터 수집 (CWE + 벤더 어드바이저리 + 위험도 신호)

CVE ID 하나를 받아 여섯 개의 공개 소스를 순회하고, 세 개의 JSON으로 나눠 저장한다.

  CVE ID
    ├─ NVD          → CWE 매핑, CVSS, CPE, 참조 URL     ┐
    ├─ CISA KEV     → 필수 조치, 기한, 랜섬웨어 악용     ├→ cve_core.json
    ├─ EPSS         → 악용 확률 예측                    ┘
    ├─ OSV.dev      → 영향/수정 버전, 서술형 details    ┐
    ├─ Red Hat      → statement, 우회책, RHSA          ├→ advisories.json
    └─ MITRE CWE    → 취약점 유형 문서 (CVE와 무관)     → cwe_catalog.json

왜 파일을 셋으로 나누는가 (이 프로젝트의 핵심 설계):
  세 데이터의 '수명 주기'가 다르기 때문이다.
    cwe_catalog  -- 분기~연 단위로만 바뀌고, 여러 CVE가 공유한다.
    advisories   -- 패치가 나올 때마다 바뀐다. CVE 전용이다.
    cve_core     -- EPSS는 매일 갱신된다. CVE 전용이다.
  한 파일에 섞으면 어드바이저리가 하나 바뀔 때마다 CWE 1391개까지 다시
  임베딩하게 되어 시간과 비용이 낭비된다.

인증이 필요한 소스는 없다. NVD만 API 키가 있으면 빨라진다(.env의 NVD_API_KEY).
키가 없으면 요청 사이에 6초를 쉬므로 CVE가 많을수록 오래 걸린다.

사용 예 — 아래는 순서대로 실행하는 단계가 아니라 **하나만 고르는 선택지**다:

    python src/0_fetch_advisories.py                       # 기본 예제 5건
    python src/0_fetch_advisories.py --cve-ids CVE-2021-44228 CVE-2022-22965
    python src/0_fetch_advisories.py --from-kev 30         # KEV 최근 30건

중요: 실행할 때마다 세 JSON 파일을 **덮어쓴다**. 이어붙이지 않는다.
따라서 위 명령을 차례로 실행하면 마지막 것만 남는다. 여러 조건을 합치고
싶으면 한 번의 명령에 옵션을 함께 주면 된다(--cve-ids와 --from-kev는 더해진다):

    python src/0_fetch_advisories.py --cve-ids CVE-2021-44228 --from-kev 30 --cwe-scope all

--cwe-scope는 'CVE를 고르는' 옵션이 아니라 'CWE 문서를 얼마나 담을지'를
정하는 별개의 축이라, 위 어느 것과도 함께 쓸 수 있다:

    python src/0_fetch_advisories.py --from-kev 30 --cwe-scope all
"""
from __future__ import annotations

import argparse
import io
import json
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

import common

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

NVD_SLEEP_NO_KEY = 6.0
NVD_SLEEP_WITH_KEY = 0.7

# 기본 예제 CVE. 전부 OSV와 Red Hat 양쪽에 데이터가 있는 것으로 확인한 것들이다
# (오픈소스 취약점이라 벤더 어드바이저리 커버리지가 좋다).
# 상용 소프트웨어나 IoT 펌웨어 CVE는 구조화된 어드바이저리가 없는 경우가 많다.
DEFAULT_CVE_IDS = [
    "CVE-2021-44228",   # Log4Shell
    "CVE-2021-45046",   # Log4Shell 후속
    "CVE-2022-22965",   # Spring4Shell
    "CVE-2017-5638",    # Struts2 (Equifax 유출)
    "CVE-2014-6271",    # Shellshock
]


# --------------------------------------------------------------------------
# MITRE CWE 카탈로그
# --------------------------------------------------------------------------

def download_cwe_xml(cache: bool = True) -> bytes:
    """CWE 카탈로그 zip을 받아 안에 든 XML 바이트를 돌려준다.

    18MB짜리 파일이라 매번 받을 이유가 없어, data/raw/에 캐시해두고 재사용한다.
    최신본으로 갱신하려면 --no-cache로 실행한다.
    """
    common.RAW_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = common.RAW_DIR / "cwec_latest.xml"

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
    """XML 태그 안의 글자를 전부 모아 한 줄로 만든다.

    MITRE 설명문은 <xhtml:p> 같은 자식 태그를 섞어 쓰기 때문에, element.text만
    읽으면 본문이 통째로 사라진다. itertext()로 모든 자손의 글자를 이어붙인다.
    """
    if element is None:
        return ""
    return " ".join("".join(element.itertext()).split())


def _local(tag: str) -> str:
    """'{네임스페이스}Weakness' 에서 'Weakness'만 남긴다.

    네임스페이스 URL은 CWE 규격 버전이 오르면 바뀌므로(cwe-7 → cwe-8),
    URL에 의존하지 않도록 뒤쪽 이름만 쓴다.
    """
    return tag.rsplit("}", 1)[-1]


def _find_child(parent: ET.Element, name: str) -> ET.Element | None:
    for child in parent:
        if _local(child.tag) == name:
            return child
    return None


def _iter_children(parent: ET.Element, name: str):
    for child in parent:
        if _local(child.tag) == name:
            yield child


def parse_cwe_catalog(xml_bytes: bytes) -> list[dict]:
    """CWE XML을 이 프로젝트가 쓰는 딕셔너리 목록으로 바꾼다.

    <Weaknesses> 아래의 개별 취약점뿐 아니라 <Categories> 아래의 상위 분류도
    함께 담는다. NVD가 CWE-264(권한/접근 제어) 같은 Category로 매핑해둔 CVE가
    많은데, Category는 <Weaknesses>에 없어서 빠뜨리면 그런 CVE는 검색할 문서가
    없어진다.
    """
    root = ET.fromstring(xml_bytes)
    weaknesses_node = _find_child(root, "Weaknesses")
    if weaknesses_node is None:
        raise RuntimeError("CWE XML에서 <Weaknesses> 노드를 찾지 못했습니다.")

    catalog = []
    for weakness in _iter_children(weaknesses_node, "Weakness"):
        mitigations = []
        mit_node = _find_child(weakness, "Potential_Mitigations")
        if mit_node is not None:
            for mitigation in _iter_children(mit_node, "Mitigation"):
                phase = _text_of(_find_child(mitigation, "Phase"))
                body = _text_of(_find_child(mitigation, "Description"))
                if body:
                    mitigations.append(f"[{phase}] {body}" if phase else body)

        examples = []
        ex_node = _find_child(weakness, "Observed_Examples")
        if ex_node is not None:
            for example in _iter_children(ex_node, "Observed_Example"):
                ref = _text_of(_find_child(example, "Reference"))
                body = _text_of(_find_child(example, "Description"))
                if body:
                    examples.append(f"{ref}: {body}" if ref else body)

        catalog.append({
            "cwe_id": f"CWE-{weakness.get('ID')}",
            "name": weakness.get("Name", ""),
            "abstraction": weakness.get("Abstraction", ""),
            "description": _text_of(_find_child(weakness, "Description")),
            "extended_description": _text_of(_find_child(weakness, "Extended_Description")),
            "potential_mitigations": "\n".join(mitigations),
            "observed_examples": "\n".join(examples),
        })

    categories_node = _find_child(root, "Categories")
    if categories_node is not None:
        for category in _iter_children(categories_node, "Category"):
            catalog.append({
                "cwe_id": f"CWE-{category.get('ID')}",
                "name": category.get("Name", ""),
                "abstraction": "Category",
                "description": _text_of(_find_child(category, "Summary")),
                "extended_description": "",
                "potential_mitigations": "",
                "observed_examples": "",
            })

    return catalog


# --------------------------------------------------------------------------
# NVD: CVE 기본 정보
# --------------------------------------------------------------------------

def _extract_cwe_ids(cve: dict) -> list[str]:
    """NVD 응답에서 'CWE-숫자' 형태만 골라낸다.

    NVD는 분석이 끝나지 않은 CVE에 'NVD-CWE-noinfo' 같은 값을 넣는데, 이건
    실제 CWE 번호가 아니라 카탈로그에 없다. 그대로 두면 검색해도 아무 문서가
    안 나오는 유령 ID가 되므로 걸러낸다.
    """
    ids = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value[4:].isdigit() and value not in ids:
                ids.append(value)
    return ids


def _extract_cvss(cve: dict) -> tuple[float | None, str]:
    """CVSS 점수와 심각도를 뽑는다. v3.1 → v3.0 → v2 순으로 먼저 찾은 것을 쓴다.

    CVSS는 버전이 여러 번 바뀌어서 JSON의 열쇠 이름도 버전마다 다르다.
    옛 CVE에는 v2만, 최근 CVE에는 v3.1이 붙어 있다.
    """
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity") or ""
        return data.get("baseScore"), severity
    return None, ""


def _extract_references(cve: dict) -> list[dict]:
    """참조 URL 중 벤더 어드바이저리·패치·완화 관련만 골라 남긴다.

    NVD는 참조마다 'Vendor Advisory', 'Patch', 'Mitigation', 'Exploit' 같은
    태그를 붙여준다. Log4Shell은 참조가 103개나 되는데 대부분 뉴스나 3rd party
    글이라 전부 저장할 필요가 없다.

    이 URL들의 본문을 긁어오지는 않는다. 벤더마다 HTML 구조가 다르고 JS 렌더링이
    필요한 곳도 있어 크롤링은 깨지기 쉽다. 본문은 구조화된 JSON을 주는
    OSV/Red Hat에서 받고, 이 URL은 사람이 확인할 '출처 링크'로만 쓴다.
    """
    wanted = {"Vendor Advisory", "Patch", "Mitigation", "Release Notes"}
    refs = []
    for ref in cve.get("references", []):
        tags = ref.get("tags", [])
        if wanted & set(tags):
            refs.append({"url": ref["url"], "tags": tags})
    return refs


def fetch_nvd_cve(cve_id: str, api_key: str | None) -> dict | None:
    """NVD에서 CVE 하나를 조회한다. 없으면 None."""
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API_URL, headers=headers,
                        params={"cveId": cve_id}, timeout=120)
    if resp.status_code == 404:
        return None
    if resp.status_code == 403:
        raise RuntimeError(
            "NVD가 403을 반환했습니다. rate limit일 가능성이 큽니다. "
            "잠시 후 다시 시도하거나 .env에 NVD_API_KEY를 설정하세요.")
    resp.raise_for_status()
    items = resp.json().get("vulnerabilities", [])
    return items[0]["cve"] if items else None


# --------------------------------------------------------------------------
# CISA KEV: 실제 악용이 확인된 취약점 목록
# --------------------------------------------------------------------------

def fetch_kev_catalog(cache: bool = True) -> dict[str, dict]:
    """KEV 전체 목록을 한 번 받아 CVE ID로 찾을 수 있는 딕셔너리로 만든다.

    KEV는 CVE별 조회 API가 따로 없고 전체 목록(약 1700건)을 통째로 주는
    JSON 피드 하나뿐이다. CVE마다 요청하는 대신 한 번만 받아 메모리에서
    찾는 편이 훨씬 빠르다.

    KEV에 올라와 있다는 것은 '실제 공격에 쓰인 것이 확인됐다'는 사실이다.
    뒤에 나오는 EPSS(확률 예측)와는 성격이 다르므로 구분해서 다뤄야 한다.
    """
    common.RAW_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = common.RAW_DIR / "kev.json"

    if cache and cache_path.exists():
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    else:
        print("[KEV] 다운로드 중...")
        resp = requests.get(KEV_FEED_URL, timeout=120)
        resp.raise_for_status()
        payload = resp.json()
        cache_path.write_text(json.dumps(payload), encoding="utf-8")

    print(f"[KEV] {payload.get('count')}건 (갱신일 {payload.get('dateReleased', '')[:10]})")
    return {v["cveID"]: v for v in payload.get("vulnerabilities", [])}


# --------------------------------------------------------------------------
# EPSS: 향후 30일 악용 확률 예측
# --------------------------------------------------------------------------

def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """EPSS 점수를 한 번의 요청으로 여러 CVE만큼 받아온다.

    EPSS API는 cve 파라미터에 쉼표로 여러 개를 넘길 수 있다. CVE마다 따로
    요청할 이유가 없으므로 한 번에 묶어 보낸다(너무 길면 URL 길이 제한에
    걸리므로 100개씩 나눈다).

    주의: EPSS는 '확률'이지 사실이 아니다. 0.97은 위험 신호이지 공격을 실제로
    받았다는 뜻이 아니다. 이 구분은 3_query.py의 프롬프트에서도 지켜야 한다.
    """
    scores: dict[str, dict] = {}
    for start in range(0, len(cve_ids), 100):
        batch = cve_ids[start:start + 100]
        resp = requests.get(EPSS_API_URL, params={"cve": ",".join(batch)}, timeout=60)
        resp.raise_for_status()
        for row in resp.json().get("data", []):
            scores[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
            }
    print(f"[EPSS] {len(scores)}건 확보")
    return scores


# --------------------------------------------------------------------------
# OSV.dev: 오픈소스 패키지 어드바이저리
# --------------------------------------------------------------------------

def _osv_get(vuln_id: str) -> dict | None:
    resp = requests.get(OSV_VULN_URL.format(vuln_id=vuln_id), timeout=60)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _osv_to_advisory(record: dict, cve_id: str) -> dict:
    """OSV 레코드를 이 프로젝트의 어드바이저리 스키마로 바꾼다.

    affected[].ranges 는 '어느 버전에서 생겨서(introduced) 어느 버전에서
    고쳐졌는지(fixed)'를 담는다. 이것이 2단계에서 가장 값진 데이터다.
    1단계의 CWE 문서로는 절대 답할 수 없었던 "내 버전이 영향받나?"에
    답할 수 있게 해준다.

    이 버전 정보는 임베딩해서 검색하면 안 된다. 2.14.1과 2.15.0은 임베딩
    공간에서 거의 같은 위치라 LLM이 반대로 읽을 수 있다. 구조화 필드로
    남겨두고 3_query.py의 check_version()이 정확히 비교한다.
    """
    affected = []
    for item in record.get("affected", []):
        package = item.get("package", {})
        for rng in item.get("ranges", []):
            # OSV는 버전 범위를 두 가지로 준다.
            #   ECOSYSTEM / SEMVER -- '2.13.0', '2.15.0' 같은 사람이 쓰는 버전
            #   GIT                -- 'c30a1398a...' 같은 커밋 해시
            # 사용자는 "우리는 2.14.1을 씁니다"라고 말하지 커밋 해시를 대지 않는다.
            # GIT 범위는 버전 비교가 불가능하므로 여기서 걸러낸다.
            if rng.get("type") == "GIT":
                continue
            introduced = fixed = None
            for event in rng.get("events", []):
                introduced = event.get("introduced", introduced)
                fixed = event.get("fixed", fixed)
            # 패키지 이름이 없으면 어느 라이브러리 얘기인지 알 수 없어 쓸모가 없다.
            if not package.get("name"):
                continue
            affected.append({
                "ecosystem": package.get("ecosystem", ""),
                "package": package.get("name", ""),
                "introduced": introduced,
                "fixed": fixed,
            })

    return {
        "advisory_id": record.get("id", ""),
        "cve_id": cve_id,
        "source": "osv",
        "vendor": affected[0]["ecosystem"] if affected else "OSV",
        "summary": record.get("summary", ""),
        "details": record.get("details", ""),
        "mitigation": "",
        "affected": affected,
        "url": f"https://osv.dev/vulnerability/{record.get('id', '')}",
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def fetch_osv(cve_id: str) -> list[dict]:
    """OSV에서 어드바이저리를 받아온다. CVE 레코드와 GHSA 레코드를 모두 본다.

    같은 취약점이라도 OSV의 CVE 레코드보다 GHSA(GitHub Security Advisory)
    레코드가 훨씬 풍부하다. Log4Shell로 확인한 차이:

        CVE-2021-44228        details 713자,  affected 패키지 1개
        GHSA-jfh8-c2jp-5v3q   details 3014자, affected 패키지 다수

    그래서 CVE로 먼저 조회한 뒤 aliases에 있는 GHSA ID를 따라가 한 번 더 받는다.
    """
    advisories = []
    record = _osv_get(cve_id)
    if record is None:
        return advisories
    advisories.append(_osv_to_advisory(record, cve_id))

    for alias in record.get("aliases", []):
        if not alias.startswith("GHSA-"):
            continue
        ghsa = _osv_get(alias)
        if ghsa:
            advisories.append(_osv_to_advisory(ghsa, cve_id))

    return advisories


# --------------------------------------------------------------------------
# Red Hat: 벤더 어드바이저리
# --------------------------------------------------------------------------

def fetch_redhat(cve_id: str) -> dict | None:
    """Red Hat 보안 데이터 API에서 벤더 어드바이저리를 받아온다.

    다른 소스에 없는 두 가지를 준다.
      mitigation       -- 패치를 못 올릴 때 쓸 우회책 본문.
                          (예: log4j2.formatMsgNoLookups 시스템 속성 설정)
      affected_release -- 제품별 수정 패키지 버전과 RHSA 권고 번호.
                          Log4Shell은 영향 릴리스가 43개였다.

    Red Hat 제품을 안 쓰더라도 mitigation의 우회책은 일반적으로 참고할 만하다.
    다만 어디까지나 '한 벤더의 관점'이라는 점은 답변에 밝혀야 한다.
    """
    resp = requests.get(REDHAT_CVE_URL.format(cve_id=cve_id), timeout=60)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()

    # details와 mitigation은 API가 문자열로 줄 때도, 리스트나 딕셔너리로 줄 때도
    # 있어서 형태를 하나로 맞춘다. 실제 응답에서 mitigation은 {'value': ...} 였다.
    def as_text(value) -> str:
        if isinstance(value, dict):
            return str(value.get("value", ""))
        if isinstance(value, list):
            return "\n".join(str(v) for v in value)
        return str(value or "")

    releases = [
        {
            "product": r.get("product_name", ""),
            "package": r.get("package", ""),
            "advisory": r.get("advisory", ""),
        }
        for r in data.get("affected_release", [])
    ]

    return {
        "advisory_id": f"redhat:{cve_id}",
        "cve_id": cve_id,
        "source": "redhat",
        "vendor": "Red Hat",
        "summary": as_text(data.get("bugzilla", {}).get("description")),
        "details": as_text(data.get("details")) + "\n\n" + as_text(data.get("statement")),
        "mitigation": as_text(data.get("mitigation")),
        "affected": [],
        "affected_releases": releases,
        "threat_severity": data.get("threat_severity", ""),
        "url": f"https://access.redhat.com/security/cve/{cve_id}",
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# --------------------------------------------------------------------------
# 조립
# --------------------------------------------------------------------------

def build_cve_core(cve_id: str, nvd_cve: dict, kev: dict | None,
                   epss: dict | None) -> dict:
    """여러 소스에서 온 CVE 정보를 하나의 레코드로 합친다.

    여기 담기는 값들은 '검색'이 아니라 '계산·조회'로 얻은 확정된 사실이다.
    3_query.py는 이 값을 벡터 검색에 넣지 않고 프롬프트에 직접 주입한다.
    LLM이 숫자를 지어내지 않게 하는 가장 확실한 방법은, 애초에 숫자를
    LLM에게 계산시키지 않는 것이다.
    """
    score, severity = _extract_cvss(nvd_cve)
    record = {
        "cve_id": cve_id,
        "cwe_ids": _extract_cwe_ids(nvd_cve),
        "cvss_score": score,
        "severity": severity,
        "published": nvd_cve.get("published", "")[:10],
        "description": next(
            (d["value"] for d in nvd_cve.get("descriptions", []) if d.get("lang") == "en"),
            ""),
        "epss": None,
        "epss_percentile": None,
        "kev": {"listed": False},
        "references": _extract_references(nvd_cve),
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    if epss:
        record["epss"] = epss["epss"]
        record["epss_percentile"] = epss["percentile"]

    if kev:
        record["kev"] = {
            "listed": True,
            "vendor_project": kev.get("vendorProject", ""),
            "product": kev.get("product", ""),
            "name": kev.get("vulnerabilityName", ""),
            "date_added": kev.get("dateAdded", ""),
            "due_date": kev.get("dueDate", ""),
            "required_action": kev.get("requiredAction", ""),
            "short_description": kev.get("shortDescription", ""),
            "ransomware": kev.get("knownRansomwareCampaignUse", ""),
        }

    return record


def filter_catalog_to_mapped(catalog: list[dict], cores: list[dict]) -> list[dict]:
    """수집한 CVE가 실제로 가리키는 CWE만 남긴다.

    CWE는 1391개지만 CVE 몇 건이 참조하는 것은 수십 개뿐이다. 나머지는 검색될
    일이 없는데도 임베딩 시간과 비용, 저장 공간을 잡아먹는다.
    """
    used = {cwe for c in cores for cwe in c["cwe_ids"]}
    kept = [c for c in catalog if c["cwe_id"] in used]
    missing = used - {c["cwe_id"] for c in kept}
    if missing:
        print(f"[경고] 카탈로그에 없는 CWE {len(missing)}개: {sorted(missing)[:10]}")
    return kept


def main() -> None:
    """수집 전체를 지휘한다.

    흐름:
      1. 옵션 해석, .env에서 NVD 키 확인
      2. 대상 CVE 목록 결정 (--cve-ids / --from-kev / 기본 목록)
      3. KEV 전체 목록과 EPSS 점수를 한 번에 받아둔다
      4. CVE마다 NVD → OSV → Red Hat 순회
      5. CWE 카탈로그를 받아 필요한 것만 남긴다
      6. 세 개의 JSON으로 저장
    """
    parser = argparse.ArgumentParser(description="CWE + 벤더 어드바이저리 수집")
    parser.add_argument("--cve-ids", nargs="+", default=[], metavar="CVE-ID",
                        help="수집할 CVE ID 목록")
    parser.add_argument("--from-kev", type=int, default=0, metavar="N",
                        help="KEV 목록에서 최근 추가된 N건을 대상에 추가")
    parser.add_argument("--cwe-scope", choices=["mapped", "all"], default="mapped",
                        help="mapped=참조되는 CWE만, all=전체 (기본: mapped)")
    parser.add_argument("--no-cache", action="store_true",
                        help="CWE XML과 KEV 캐시를 무시하고 다시 받는다")
    args = parser.parse_args()

    common.load_env()
    import os
    # .env에 적어둔 이름이 사람마다 다를 수 있어 두 가지를 모두 받는다.
    api_key = os.getenv("NVD_API_KEY") or os.getenv("NVD_KEY")
    sleep_s = NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_NO_KEY
    print(f"[NVD] API 키 {'사용' if api_key else '없음 (요청 간 6초 대기)'}")

    kev_catalog = fetch_kev_catalog(cache=not args.no_cache)

    # 대상 CVE 결정
    cve_ids = list(args.cve_ids)
    if args.from_kev > 0:
        recent = sorted(kev_catalog.values(),
                        key=lambda v: v.get("dateAdded", ""), reverse=True)
        cve_ids += [v["cveID"] for v in recent[:args.from_kev]]
    if not cve_ids:
        cve_ids = list(DEFAULT_CVE_IDS)
        print(f"[대상] 옵션이 없어 기본 예제 {len(cve_ids)}건을 씁니다.")

    # 중복 제거(순서 유지)
    seen, targets = set(), []
    for cve_id in cve_ids:
        cve_id = cve_id.upper()
        if cve_id not in seen:
            seen.add(cve_id)
            targets.append(cve_id)
    print(f"[대상] CVE {len(targets)}건: {', '.join(targets[:5])}"
          + (" ..." if len(targets) > 5 else ""))

    epss_scores = fetch_epss(targets)

    cores, advisories = [], []
    for i, cve_id in enumerate(targets):
        nvd_cve = fetch_nvd_cve(cve_id, api_key)
        if nvd_cve is None:
            print(f"[{cve_id}] NVD에 없음 - 건너뜀")
            continue

        core = build_cve_core(cve_id, nvd_cve,
                              kev_catalog.get(cve_id), epss_scores.get(cve_id))
        cores.append(core)

        osv_items = fetch_osv(cve_id)
        redhat_item = fetch_redhat(cve_id)
        if redhat_item:
            osv_items.append(redhat_item)
        advisories.extend(osv_items)

        kev_mark = "KEV" if core["kev"]["listed"] else "-"
        epss_mark = f"EPSS {core['epss']:.3f}" if core["epss"] is not None else "EPSS -"
        print(f"[{cve_id}] CWE {len(core['cwe_ids'])}개 | 어드바이저리 "
              f"{len(osv_items)}건 | {kev_mark} | {epss_mark}")

        if i < len(targets) - 1:
            time.sleep(sleep_s)

    catalog = parse_cwe_catalog(download_cwe_xml(cache=not args.no_cache))
    print(f"[CWE] 파싱 완료: {len(catalog)}개 항목")
    if args.cwe_scope == "mapped":
        catalog = filter_catalog_to_mapped(catalog, cores)
        print(f"[CWE] 참조되는 CWE만 유지: {len(catalog)}개")

    common.write_json(common.CWE_CATALOG_PATH, catalog)
    common.write_json(common.CVE_CORE_PATH, cores)
    common.write_json(common.ADVISORIES_PATH, advisories)

    print(f"\n저장 완료:")
    print(f"  {common.CWE_CATALOG_PATH}   CWE {len(catalog)}개")
    print(f"  {common.CVE_CORE_PATH}      CVE {len(cores)}건")
    print(f"  {common.ADVISORIES_PATH}    어드바이저리 {len(advisories)}건")
    print("다음 단계: python src/1_chunk.py")


if __name__ == "__main__":
    main()
