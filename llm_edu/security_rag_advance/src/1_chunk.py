"""
1단계: 청크 분할 (Chunking)

0단계가 만든 세 개의 JSON을 하나의 청크 목록으로 합친다.
2단계 프로젝트의 핵심은 **성격이 다른 두 종류의 문서를 한 컬렉션에 담되,
메타데이터로 구분할 수 있게 하는 것**이다.

  scope="type"      CWE 문서. 여러 CVE가 공유하는 '유형 지식'.
                    cwe_id로 필터링한다. "왜 위험한가, 근본 예방책은"에 답한다.

  scope="instance"  어드바이저리 문서. 이 CVE 전용 '사건 지식'.
                    cve_id로 필터링한다. "무엇을 해야 하는가"에 답한다.

소스마다 문서 구조가 달라 분할 전략도 다르게 간다.

  CWE               섹션 단위 (정의 / 상세 / 완화 / 사례)
  OSV details       문단 경계, 최대 1200자
  Red Hat mitigation/details  필드 하나 = 청크 하나
  KEV required_action         필드 하나 = 청크 하나

입력: data/cwe_catalog.json, data/advisories.json, data/cve_core.json
출력: data/chunks.json
"""
import common

MAX_CHARS = 1200

# CWE 문서의 섹션. 실데이터가 영문이라 라벨도 영문으로 맞춘다.
# 이 라벨은 청크 맨 앞에 붙어 검색어와 함께 매칭되므로, 본문과 같은 언어여야
# 검색에 유리하다.
CWE_SECTIONS = {
    "description": "Description",
    "extended_description": "Extended Description",
    "potential_mitigations": "Potential Mitigations",
    "observed_examples": "Observed Examples",
}


def make_chunk(chunk_id: str, header: str, body: str, *, scope: str,
               source_type: str, cve_id: str = "", cwe_id: str = "",
               vendor: str = "", section: str = "",
               fetched_at: str = "") -> dict:
    """청크 하나를 만든다. 모든 청크가 같은 필드를 갖도록 이 함수를 거친다.

    본문 앞에 header를 붙이는 이유:
      완화 방법 본문만 떼어놓고 보면 "무엇에 대한" 완화 방법인지 알 수 없다.
      임베딩은 글자만 보고 의미를 계산하므로, 앞에 한 줄을 덧붙이는 것만으로
      검색 정확도가 눈에 띄게 좋아진다. 사람이 결과를 확인할 때도 편하다.

          [CWE-502 Deserialization of Untrusted Data - Potential Mitigations]
          Avoid having unnecessary types or gadgets...

    메타데이터에 빈 문자열을 쓰는 이유:
      Chroma의 메타데이터 값은 None을 허용하지 않는다. CWE 청크에는 cve_id가
      없고 어드바이저리 청크에는 cwe_id가 없는데, 그럴 때 None 대신 ""를 넣는다.
      또 모든 청크가 같은 필드를 갖고 있어야 where 필터를 쓸 때 예외가 없다.
    """
    return {
        "chunk_id": chunk_id,
        "text": f"{header}\n{body}",
        "header": header,
        "scope": scope,
        "source_type": source_type,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "vendor": vendor,
        "section": section,
        "fetched_at": fetched_at,
    }


def chunk_cwe_catalog(catalog: list[dict]) -> list[dict]:
    """CWE 문서를 섹션 단위로 나눈다 (scope="type").

    왜 섹션 단위인가:
      흔히 배우는 '500자마다 자르기'는 형식이 제각각인 문서에나 쓰는 방법이다.
      CWE는 MITRE가 정한 규격을 모든 항목이 따르므로, 섹션 경계로 자르면
      청크 하나가 곧 하나의 완결된 주제가 된다. 그래서 "어떻게 예방하나"라는
      질문에는 완화 방법 청크가 정확히 걸린다.

    이 청크들은 CVE에 매이지 않는다. CWE-502 문서 하나를 Log4Shell도 쓰고
    다른 역직렬화 취약점도 함께 쓴다. 그래서 cve_id를 비워둔다.
    """
    chunks = []
    for cwe in catalog:
        for key, label in CWE_SECTIONS.items():
            text = (cwe.get(key) or "").strip()
            if not text:
                continue
            pieces = common.split_long_section(text, MAX_CHARS)
            for i, piece in enumerate(pieces):
                suffix = f"::{i}" if len(pieces) > 1 else ""
                chunks.append(make_chunk(
                    chunk_id=f"{cwe['cwe_id']}::{key}{suffix}",
                    header=f"[{cwe['cwe_id']} {cwe['name']} - {label}]",
                    body=piece,
                    scope="type",
                    source_type="cwe_catalog",
                    cwe_id=cwe["cwe_id"],
                    section=key,
                ))
    return chunks


def chunk_advisories(advisories: list[dict]) -> list[dict]:
    """벤더 어드바이저리를 소스별 전략으로 나눈다 (scope="instance").

    필드마다 성격이 달라 다르게 처리한다.

      summary   -- 한 줄 요약. 짧으니 그대로 청크 하나.
      details   -- 서술형 산문. 문단 경계로 나눈다(OSV는 3000자가 넘기도 한다).
      mitigation-- 패치를 못 올릴 때의 우회책. 짧고 목적이 분명해 통째로 둔다.
                   실무에서 가장 자주 찾게 되는 내용이라 따로 청크로 남긴다.

    영향 버전 범위(affected)는 청크로 만들지 않는다:
      "2.13.0에서 도입되어 2.15.0에서 수정됨" 같은 정보를 임베딩해서 검색하면
      안 된다. 2.14.1과 2.15.0은 임베딩 공간에서 거의 같은 위치라, LLM이
      근거를 잘못 읽으면 안전한 버전을 취약하다고 말할 수 있다.
      이 데이터는 advisories.json에 구조화된 채로 남겨두고,
      3_query.py의 check_version()이 정확히 비교해 결과를 문장으로 만든다.

      다만 사람이 읽을 요약 한 줄은 청크로 넣는다. "어떤 패키지가 영향을
      받는가" 같은 질문에는 검색으로 답할 수 있어야 하기 때문이다.
    """
    chunks = []
    for adv in advisories:
        base = adv["advisory_id"]
        vendor = adv.get("vendor", "")
        cve_id = adv["cve_id"]
        fetched = adv.get("fetched_at", "")
        label = f"{cve_id} {vendor} 어드바이저리"

        summary = (adv.get("summary") or "").strip()
        if summary:
            chunks.append(make_chunk(
                chunk_id=f"{base}::summary",
                header=f"[{label} - 요약]",
                body=summary,
                scope="instance", source_type="vendor_advisory",
                cve_id=cve_id, vendor=vendor, section="summary",
                fetched_at=fetched,
            ))

        details = (adv.get("details") or "").strip()
        for i, piece in enumerate(common.split_paragraphs(details, MAX_CHARS)):
            chunks.append(make_chunk(
                chunk_id=f"{base}::details::{i}",
                header=f"[{label} - 상세]",
                body=piece,
                scope="instance", source_type="vendor_advisory",
                cve_id=cve_id, vendor=vendor, section="details",
                fetched_at=fetched,
            ))

        mitigation = (adv.get("mitigation") or "").strip()
        if mitigation:
            chunks.append(make_chunk(
                chunk_id=f"{base}::mitigation",
                header=f"[{label} - 우회책/완화]",
                body=mitigation,
                scope="instance", source_type="vendor_advisory",
                cve_id=cve_id, vendor=vendor, section="mitigation",
                fetched_at=fetched,
            ))

        # 영향받는 패키지 목록을 사람이 읽을 한 줄로 요약해 넣는다.
        # 판정용이 아니라 '무엇이 영향받는가'를 검색으로 찾기 위한 것이다.
        affected = adv.get("affected", [])
        if affected:
            lines = [
                f"{a['ecosystem']} 패키지 {a['package']}: "
                f"{a['introduced'] or '초기 버전'} 이상 "
                f"{a['fixed'] + ' 미만이 취약' if a['fixed'] else '(수정 버전 미상)'}"
                for a in affected
            ]
            chunks.append(make_chunk(
                chunk_id=f"{base}::affected",
                header=f"[{label} - 영향 패키지]",
                body="\n".join(lines),
                scope="instance", source_type="vendor_advisory",
                cve_id=cve_id, vendor=vendor, section="affected",
                fetched_at=fetched,
            ))

        # Red Hat의 제품별 수정 패키지와 RHSA 번호는 '표'에 가까운 데이터다.
        # Log4Shell은 이 목록이 43개나 되는데, 이것을 줄 경계로 나눠 여러 청크로
        # 만들었더니 문제가 생겼다.
        #
        #   질문: "당장 업그레이드가 어렵습니다. 임시 우회책이 있나요?"
        #   결과: affected_releases 청크 2개 + affected 청크 1개가 쿼터를 다 차지하고,
        #         정작 답인 mitigation 청크(우회책 본문)는 밀려났다.
        #
        # 패키지 이름 나열은 의미가 옅은데 청크 수만 많아서, 하나뿐인 우회책
        # 청크를 수적으로 눌러버린 것이다. 그래서 목록은 **한 청크로 압축**한다.
        # 전체 목록이 필요하면 advisories.json에 구조화된 채로 남아 있으므로
        # 그쪽을 조회하면 된다(버전 범위를 검색 대신 계산으로 다루는 것과 같은 이유).
        releases = [r for r in adv.get("affected_releases", []) if r.get("package")]
        if releases:
            shown = releases[:12]
            lines = [f"{r['product']}: {r['package']} ({r['advisory']})" for r in shown]
            if len(releases) > len(shown):
                lines.append(f"... 외 {len(releases) - len(shown)}개 제품 "
                             f"(전체 목록은 advisories.json 참고)")
            chunks.append(make_chunk(
                chunk_id=f"{base}::releases",
                header=f"[{label} - 제품별 수정 버전 (총 {len(releases)}개)]",
                body="\n".join(lines),
                scope="instance", source_type="vendor_advisory",
                cve_id=cve_id, vendor=vendor, section="affected_releases",
                fetched_at=fetched,
            ))

    return chunks


def chunk_kev_actions(cores: list[dict]) -> list[dict]:
    """CISA KEV의 '필수 조치' 지시문을 청크로 만든다 (scope="instance").

    KEV 자체는 cve_core.json에 있지만(기한·랜섬웨어 여부 같은 숫자와 상태는
    프롬프트에 직접 주입해야 하므로), required_action은 서술형 지시문이라
    검색 대상으로도 가치가 있다. 그래서 이 필드만 따로 청크로 뽑는다.

    이 지시문은 미국 연방기관에 대한 법적 구속력이 있는 조치 요구사항이라
    문장을 쪼개지 않고 통째로 둔다.
    """
    chunks = []
    for core in cores:
        kev = core.get("kev", {})
        action = (kev.get("required_action") or "").strip()
        if not kev.get("listed") or not action:
            continue
        chunks.append(make_chunk(
            chunk_id=f"kev::{core['cve_id']}::action",
            header=f"[{core['cve_id']} CISA KEV - 필수 조치 (기한 {kev.get('due_date', '')})]",
            body=action,
            scope="instance",
            source_type="cisa_kev",
            cve_id=core["cve_id"],
            vendor="CISA",
            section="required_action",
            fetched_at=core.get("fetched_at", ""),
        ))
    return chunks


def main() -> None:
    catalog = common.read_json(common.CWE_CATALOG_PATH, [])
    advisories = common.read_json(common.ADVISORIES_PATH, [])
    cores = common.read_json(common.CVE_CORE_PATH, [])

    if not catalog and not advisories:
        raise SystemExit("수집된 데이터가 없습니다. 먼저 0_fetch_advisories.py를 실행하세요.")

    cwe_chunks = chunk_cwe_catalog(catalog)
    adv_chunks = chunk_advisories(advisories)
    kev_chunks = chunk_kev_actions(cores)
    chunks = cwe_chunks + adv_chunks + kev_chunks

    common.write_json(common.CHUNKS_PATH, chunks)

    print(f"청크 {len(chunks)}개 생성 완료")
    print(f"  scope=type     (CWE 유형 문서)     {len(cwe_chunks):4}개")
    print(f"  scope=instance (벤더 어드바이저리)  {len(adv_chunks):4}개")
    print(f"  scope=instance (CISA KEV 조치)     {len(kev_chunks):4}개")
    print("\n예시:")
    for c in (cwe_chunks[:1] + adv_chunks[:2] + kev_chunks[:1]):
        print(f"  - [{c['scope']:8}] {c['chunk_id'][:44]:46} {c['header'][:52]}")
    print("\n다음 단계: python src/2_embed_and_store.py")


if __name__ == "__main__":
    main()
