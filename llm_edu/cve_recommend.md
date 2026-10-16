"""
1단계: 청크 분할 (Chunking)

CWE 카탈로그 항목을 섹션 단위(description / extended_description /
potential_mitigations / observed_examples)로 분할한다.
CWE 문서는 MITRE가 정한 표준 구조를 따르므로, 고정 길이 분할 대신
'섹션 기준 분할'을 사용하는 것이 문맥을 보존하는 데 더 유리하다.

각 청크에는 검색 시 필터링에 쓸 메타데이터를 함께 저장한다:
- cwe_id, cwe_name, section, source_type

입력: data/cwe_catalog.json  (0_fetch_real_data.py가 만든 MITRE 실데이터)
출력: data/chunks.json
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"

# 실데이터(MITRE 원문)는 영문이므로 섹션 라벨도 영문을 앞에 둔다.
# 이 라벨은 청크 본문 맨 앞에 붙어 검색어와 함께 매칭되기 때문에,
# 데이터와 같은 언어로 맞추는 편이 검색 품질에 유리하다.
SECTION_LABELS = {
    "description": "Description",
    "extended_description": "Extended Description",
    "potential_mitigations": "Potential Mitigations",
    "observed_examples": "Observed Examples",
}

# 원문 섹션이 너무 길면(특히 Potential Mitigations) 하나의 청크가
# 여러 주제를 담게 되어 검색 정확도가 떨어진다. 문단 경계에서 잘라
# 이 길이를 넘지 않도록 나눈다.
MAX_CHARS = 1200


def split_long_section(text: str, max_chars: int = MAX_CHARS) -> list[str]:
    """너무 긴 글을 줄 경계에서 여러 조각으로 나눈다. 단어나 문장은 자르지 않는다.

    왜 나눠야 하나:
      RAG에서 검색의 최소 단위를 '청크(chunk)'라고 한다. 청크가 너무 크면
      한 덩어리 안에 여러 주제가 섞여서, 질문과 관련된 한 문장 때문에 관련 없는
      내용까지 통째로 딸려 온다. 반대로 너무 작으면 문맥이 끊겨 무슨 말인지
      알 수 없게 된다. 그래서 적당한 크기로 자르는 것이 검색 품질을 좌우한다.

      MITRE의 Potential Mitigations 섹션은 길면 5000자가 넘는다. 그 안에는
      '설계 단계에서 할 일', '구현 단계에서 할 일', '운영 단계에서 할 일'이
      다 들어 있어서, 통째로 두면 어떤 질문에도 애매하게 걸리는 청크가 된다.

    어떻게 나누나 (줄 단위로 모으기):
      글자 수를 세다가 1200자에서 무조건 싹둑 자르면 문장이 한가운데서 끊긴다.
      "Use parameterized que" 에서 끝나버리면 검색에도 나쁘고 사람이 읽기에도
      나쁘다. 그래서 줄바꿈을 경계로 삼는다.

      0_fetch_real_data.py가 완화 방법 하나하나를 한 줄로 만들어 줄바꿈으로
      이어붙여 두었기 때문에, 줄 경계에서 자르면 항목이 통째로 보존된다.
      앞 단계에서 형식을 정해둔 덕을 여기서 보는 셈이다.

    buffer를 쓰는 방식:
      buffer는 '지금 만들고 있는 조각'을 담아두는 임시 상자다. 한 줄씩 보면서
      이렇게 판단한다.

        - 이 줄을 넣으면 1200자를 넘는다  -> 지금까지 모은 buffer를 완성품으로
                                             내보내고, 이 줄부터 새 조각을 시작
        - 아직 여유가 있다                -> buffer 뒤에 이 줄을 이어붙인다

      조건에 buffer and 가 붙어 있는 이유가 중요하다. buffer가 비어 있는데도
      길이 초과로 판정해버리면 빈 조각이 결과에 들어가고, 그 줄은 다시 빈
      buffer에 담겨 같은 상황이 반복된다. 즉 한 줄 자체가 1200자보다 길면 이
      조건이 없을 때 무한히 잘못 동작한다. buffer가 비어 있을 때는 무조건
      담도록 해서, 긴 줄 하나는 그냥 기준을 넘기더라도 통째로 유지한다.

      마지막의 if buffer: 도 빠뜨리기 쉬운 부분이다. for 문이 끝난 시점에
      buffer에는 아직 내보내지 않은 마지막 조각이 남아 있어서, 이 줄이 없으면
      글의 끝부분이 조용히 사라진다.

    반환값:
      항상 문자열 리스트다. 자를 필요가 없을 만큼 짧아도 [text] 처럼 리스트에
      담아 돌려준다. 어떨 땐 문자열, 어떨 땐 리스트를 주면 호출부가 매번
      타입을 확인해야 해서, 형태를 하나로 통일하는 편이 훨씬 쓰기 편하다.

    예시:
      len(text)=3000, max_chars=1200 이면 결과는 대략 세 조각이 된다.
      각 조각은 1200자에 '가까운' 크기이지 정확히 1200자는 아니다.
      줄 경계를 지키느라 조금씩 모자란 상태로 끊기기 때문이다.
    """
    if len(text) <= max_chars:
        return [text]

    parts, buffer = [], ""
    for line in text.split("\n"):
        if buffer and len(buffer) + len(line) + 1 > max_chars:
            parts.append(buffer)
            buffer = line
        else:
            buffer = f"{buffer}\n{line}" if buffer else line
    if buffer:
        parts.append(buffer)
    return parts


def chunk_cwe_catalog(cwe_list: list[dict]) -> list[dict]:
    """CWE 문서들을 검색 단위인 '청크' 목록으로 쪼갠다. 이 파일의 핵심 함수다.

    무슨 일을 하나:
      CWE 하나에는 정의, 상세 설명, 완화 방법, 실제 사례라는 네 개의 섹션이
      들어 있다. 이 함수는 각 섹션을 독립된 청크로 떼어내고, 섹션이 너무 길면
      split_long_section()으로 한 번 더 나눈다.

      CWE 57개 -> 청크 298개가 나오는 식이다. 한 CWE가 평균 5개 남짓의 청크가
      되는데, 섹션이 비어 있는 CWE도 있고 완화 방법이 길어 여러 조각으로 나뉘는
      CWE도 있어서 개수가 일정하지 않다.

    왜 섹션 단위로 자르나 (이 프로젝트의 중요한 설계 결정):
      RAG 강의에서 흔히 배우는 방식은 '500자마다 기계적으로 자르기'다. 형식이
      제각각인 문서에는 그 방법밖에 없지만, 여기서는 더 좋은 방법이 있다.
      CWE 문서는 MITRE가 정한 규격을 모든 항목이 똑같이 따르기 때문이다.

      섹션 경계로 자르면 청크 하나가 곧 하나의 완결된 주제가 된다. 그래서
      "어떻게 예방하나요?"라는 질문에는 완화 방법 청크가, "실제 사고 사례가
      있나요?"라는 질문에는 사례 청크가 정확히 걸린다. 500자로 기계적으로
      잘랐다면 정의 끝부분과 완화 방법 앞부분이 한 청크에 섞여, 어느 질문에도
      어중간하게 반응했을 것이다.

      교훈: 문서에 이미 구조가 있다면 그 구조를 살려서 자르는 것이 거의 항상 낫다.

    각 청크에 담기는 것:
      chunk_id    -- 청크마다 겹치지 않는 고유 이름. 벡터 DB가 이걸로 청크를
                     구분하므로 절대 중복되면 안 된다. 'CWE-89::description'
                     처럼 CWE 번호와 섹션 이름을 조합해서 만든다.
      cwe_id      -- 어느 CWE에서 나왔는지. 3_query.py가 "이 CVE에 연결된
                     CWE 문서만 검색해줘"라고 범위를 좁힐 때 쓰는 핵심 열쇠다.
      cwe_name    -- 사람이 결과를 볼 때 필요한 이름.
      section     -- 어느 섹션인지. 검색 결과에 출처를 표시할 때 쓴다.
      source_type -- 데이터 출처 종류. 지금은 전부 "cwe_catalog"지만, 나중에
                     벤더 권고문 같은 다른 출처를 추가하면 이 값으로 구분해
                     걸러낼 수 있다. 미리 자리를 마련해 둔 것이다.
      text        -- 실제로 임베딩되고 검색되는 본문.

      chunk_id를 뺀 나머지 항목들을 '메타데이터(metadata)'라고 부른다. 본문 자체는
      아니지만 '이 본문이 무엇인지'를 설명하는 정보이고, RAG에서는 이것이
      검색 범위를 좁히는 데 결정적인 역할을 한다.

    본문 앞에 header를 붙이는 이유:
      text에 본문만 넣지 않고 앞에 이런 한 줄을 덧붙인다.

          [CWE-89 SQL Injection - Potential Mitigations]
          Use parameterized queries...

      완화 방법 본문만 떼어놓고 보면 "무엇에 대한" 완화 방법인지 알 수 없다.
      임베딩은 글자만 보고 의미를 계산하므로, 이 한 줄이 있고 없고가 검색
      정확도를 눈에 띄게 바꾼다. 사람이 검색 결과를 눈으로 확인할 때도 훨씬
      읽기 편해진다.

    suffix가 하는 일:
      한 섹션이 세 조각으로 나뉘면 chunk_id가 세 개 다 'CWE-89::potential_mitigations'
      로 같아져서 벡터 DB에 넣을 때 충돌한다. 그래서 조각이 둘 이상일 때만
      '::0', '::1' 같은 번호를 뒤에 붙인다. 조각이 하나뿐이면 번호를 안 붙여
      ID를 깔끔하게 유지한다.

      enumerate(pieces)는 (0, 첫 조각), (1, 둘째 조각)처럼 순번과 값을 함께
      돌려주는 내장 함수다. 순번을 직접 세는 변수를 만들 필요가 없어진다.

    빈 섹션 건너뛰기:
      text = cwe.get(section_key, "").strip() 뒤의 if not text: continue 가
      그 역할을 한다. .strip()은 앞뒤 공백과 줄바꿈을 없애므로, 공백만 있던
      섹션도 빈 문자열이 되어 걸러진다. 빈 청크를 임베딩하면 의미 없는 벡터가
      DB에 쌓여 검색 결과를 어지럽힌다.
    """
    chunks = []
    for cwe in cwe_list:
        for section_key, section_label in SECTION_LABELS.items():
            text = cwe.get(section_key, "").strip()
            if not text:
                continue
            pieces = split_long_section(text)
            for i, piece in enumerate(pieces):
                # 한 섹션이 여러 조각으로 나뉘면 chunk_id에 번호를 붙여 구분한다.
                suffix = f"::{i}" if len(pieces) > 1 else ""
                chunk_id = f"{cwe['cwe_id']}::{section_key}{suffix}"
                # 검색 품질을 위해 청크 앞부분에 CWE 이름과 섹션명을 명시적으로 포함
                header = f"[{cwe['cwe_id']} {cwe['name']} - {section_label}]"
                chunks.append({
                    "chunk_id": chunk_id,
                    "cwe_id": cwe["cwe_id"],
                    "cwe_name": cwe["name"],
                    "section": section_key,
                    "source_type": "cwe_catalog",
                    "text": f"{header}\n{piece}",
                })
    return chunks


def main():
    """이 파일의 시작점. 카탈로그를 읽어 청크로 나누고 파일로 저장한다.

    전체 흐름:
      1. data/cwe_catalog.json 읽기   (0단계가 만들어 둔 파일)
      2. chunk_cwe_catalog()로 청크 만들기
      3. data/chunks.json 으로 저장   (2단계가 읽어갈 파일)
      4. 결과를 요약해 화면에 출력

      각 단계가 파일로 결과를 남기고 다음 단계가 그 파일을 읽는 구조다.
      덕분에 뒤 단계에서 문제가 생겨도 앞 단계를 처음부터 다시 돌릴 필요가 없고,
      중간 결과 파일을 직접 열어보며 무엇이 잘못됐는지 확인할 수 있다.

    파일 다루기 문법:
      with open(경로, encoding="utf-8") as f:
        - with를 쓰면 블록이 끝날 때 파일이 자동으로 닫힌다. 직접 close()를
          부르다 보면 중간에 에러가 났을 때 파일이 열린 채로 남는데, with는
          그런 경우에도 확실히 닫아준다.
        - 두 번째 인자가 없으면 읽기 모드, "w"면 쓰기 모드다. "w"는 기존 내용을
          지우고 새로 쓰므로 주의해야 한다.
        - encoding="utf-8"은 윈도우에서 특히 중요하다. 생략하면 시스템 기본
          인코딩이 쓰여서 한글이 깨지거나 저장 중 에러가 날 수 있다.

      json.load(f)  -- 파일에서 읽어 파이썬 객체로 (load = 파일에서)
      json.dump(x,f)-- 파이썬 객체를 파일로 쓰기
      이름이 비슷한 json.loads / json.dumps는 끝에 s가 붙는데, 이건 파일이 아니라
      문자열(string)을 다룬다는 뜻이다. 초보자가 자주 헷갈리는 부분이다.

    마지막 출력:
      chunks[:3]으로 앞의 세 개만 출력하고, 각 본문도 [:60]으로 앞 60자만
      보여준다. 298개를 전부 출력하면 화면이 넘쳐 정작 확인해야 할 개수 요약이
      위로 밀려나기 때문이다. 결과가 제대로 나왔는지 눈으로 훑어보는 용도다.
    """
    with open(DATA_DIR / "cwe_catalog.json", encoding="utf-8") as f:
        cwe_catalog = json.load(f)

    chunks = chunk_cwe_catalog(cwe_catalog)

    with open(DATA_DIR / "chunks.json", "w", encoding="utf-8") as f:
        json.dump(chunks, f, ensure_ascii=False, indent=2)

    print(f"CWE {len(cwe_catalog)}개 -> 청크 {len(chunks)}개 생성 완료")
    for c in chunks[:3]:
        print(f"  - {c['chunk_id']}: {c['text'][:60]}...")


# `python src/1_chunk.py`로 직접 실행할 때만 main()이 호출된다.
# 다른 파일에서 import 할 때는 실행되지 않는다.
if __name__ == "__main__":
    main()
