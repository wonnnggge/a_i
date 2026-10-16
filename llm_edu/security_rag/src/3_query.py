"""
3단계: CVE ID로 CWE 문서 검색 (+ LLM 답변 생성)

CVE ID를 받아 cve_cwe_mapping.json에서 연결된 CWE를 찾고(메타데이터 필터),
그 CWE 문서들 안에서만 질문과 의미가 가까운 청크를 검색한다.
--ui 로 실행하면 검색된 근거를 LLM에 넘겨 한국어 답변까지 만든다.

    python src/3_query.py                                   # 데이터에서 CVE 3건을 골라 데모
    python src/3_query.py CVE-2008-2992                     # 기본 질문으로 조회
    python src/3_query.py CVE-2008-2992 "how should developers prevent this?"
    python src/3_query.py --ui [--share]                    # gradio 챗봇

환경변수 (.env 또는 셸):
    EMBEDDING_BACKEND / EMBEDDING_MODEL  2단계와 같은 값이어야 한다
    CHAT_MODEL       답변 생성 모델 (기본 gpt-4.1-nano)
    CHAT_BASE_URL    OpenAI 호환 주소. 로컬 Ollama 를 쓰려면 http://localhost:11434/v1
"""
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import chromadb

SRC_DIR = Path(__file__).parent
DATA_DIR = SRC_DIR.parent / "data"
MAPPING_PATH = DATA_DIR / "cve_cwe_mapping.json"

DEFAULT_QUESTION = "what kind of weakness is this and how can it be prevented?"
DEFAULT_CHAT_MODEL = "gpt-4.1-nano"
TOP_K = 3

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _load_step2():
    """2_embed_and_store.py 를 모듈로 불러온다.

    파일 이름이 숫자로 시작해서 `import 2_embed_and_store` 는 문법 오류다.
    그래서 importlib로 경로를 직접 지정해 불러온다. 2단계와 '같은' 임베딩 함수를
    써야 질문 벡터와 청크 벡터가 같은 공간에 놓인다. 코드를 복사하지 않고
    불러다 쓰는 이유다.
    """
    spec = importlib.util.spec_from_file_location("embed_step", SRC_DIR / "2_embed_and_store.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


step2 = _load_step2()


def load_mapping() -> dict[str, dict]:
    """CVE ID -> 매핑 정보(CWE 목록, 제품, CVSS, 공개일) 사전."""
    with open(MAPPING_PATH, encoding="utf-8") as f:
        return {m["cve_id"].upper(): m for m in json.load(f)}


def open_collection():
    """벡터 DB와 임베딩 함수를 연다. 2단계와 백엔드가 다르면 여기서 막는다.

    다른 백엔드로 만든 질문 벡터는 저장된 청크 벡터와 차원도 의미도 달라서,
    에러 없이 엉뚱한 결과만 돌려준다. 조용히 틀리는 것보다 멈추는 편이 낫다.
    """
    embedding_fn = step2.build_embedding_function()
    saved = json.loads(step2.CONFIG_PATH.read_text(encoding="utf-8"))["backend"]
    if saved != embedding_fn.name():
        raise RuntimeError(
            f"색인은 '{saved}' 백엔드로 만들었는데 지금은 '{embedding_fn.name()}' 입니다. "
            f"EMBEDDING_BACKEND 를 2단계와 같게 맞추세요."
        )
    client = chromadb.PersistentClient(path=str(step2.CHROMA_DIR))
    return client.get_collection(step2.COLLECTION_NAME), embedding_fn


def clean_query(text: str) -> str:
    """검색어에서 CVE ID를 지운다.

    observed_examples 섹션은 본문이 CVE 번호 나열이라, 검색어에 CVE ID가 있으면
    '질문의 의도'가 아니라 'CVE 번호가 많은 글'과 매칭된다. CVE ID는 이미
    메타데이터 필터로 쓰고 있으므로 의미 검색에는 의도가 담긴 문장만 넘긴다.
    """
    cleaned = CVE_PATTERN.sub(" ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" ,.?은는이가을를")
    return cleaned or DEFAULT_QUESTION


def search(collection, embedding_fn, cve: dict, question: str, k: int = TOP_K) -> list[dict]:
    """CVE에 연결된 CWE 청크 안에서만 의미 검색한다."""
    query_vec = embedding_fn([clean_query(question)])
    res = collection.query(
        query_embeddings=query_vec,
        n_results=k,
        where={"cwe_id": {"$in": cve["cwe_ids"]}},   # 메타데이터 필터: 이 CVE의 CWE만
    )
    return [
        {"distance": d, "text": doc, **meta}
        for d, doc, meta in zip(res["distances"][0], res["documents"][0], res["metadatas"][0])
    ]


def format_cve(cve: dict) -> str:
    return (f"[CVE 조회] {cve['cve_id']}\n"
            f"  제품: {cve.get('product') or '-'}\n"
            f"  CVSS: {cve.get('cvss_score')} ({cve.get('severity') or '-'})   "
            f"공개일: {(cve.get('published') or '-')[:10]}\n"
            f"  연결된 CWE: {', '.join(cve['cwe_ids'])}")


def format_hits(hits: list[dict]) -> str:
    lines = ["[검색된 근거 청크]"]
    for h in hits:
        body = h["text"].split("\n", 1)[-1]          # 첫 줄의 [CWE ... - 섹션] 머리글은 빼고
        lines.append(f"  - {h['cwe_id']} / {h['section']}  (거리 {h['distance']:.3f})")
        lines.append(f"    {h['cwe_name']}")
        lines.append(f"    {' '.join(body.split())[:160]} ...")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 답변 생성 (RAG의 G)
# --------------------------------------------------------------------------
SYSTEM_PROMPT = """당신은 보안 취약점 유형(CWE)을 가르치는 교육 도우미입니다.
아래 [CVE 정보]와 [근거]만 사용해서 답하세요.
- [근거]에 없는 제품별 패치 버전, 날짜, 수치는 지어내지 마세요.
- 근거에 없는 내용은 "제공된 CWE 문서에서 찾을 수 없습니다"라고 쓰세요.
- 문장 끝에 근거 번호를 [1], [2] 형식으로 표시하세요.
- 반드시 한국어(한글)로만 답하세요. CWE 이름 같은 고유명사만 영어를 그대로 씁니다."""


def build_prompt(cve: dict, hits: list[dict]) -> str:
    blocks = [f"[{i}] {h['cwe_id']} {h['cwe_name']} / {h['section']}\n{h['text']}"
              for i, h in enumerate(hits, 1)]
    return (f"[CVE 정보]\n{format_cve(cve)}\n\n[근거]\n" + "\n\n".join(blocks))


def generate_answer(cve: dict, hits: list[dict], question: str) -> str:
    """검색된 근거로 LLM 답변을 만든다. 실패하면 이유를 담은 문장을 돌려준다.

    키가 없거나 크레딧이 없어도 검색 결과는 의미가 있으므로, 예외를 밖으로
    던지지 않고 '답변 생성 건너뜀'으로 처리한다.
    """
    from openai import OpenAI

    base_url = os.getenv("CHAT_BASE_URL")
    if not base_url and not os.getenv("OPENAI_API_KEY"):
        return "(OPENAI_API_KEY 가 없어 답변 생성을 건너뜁니다. 아래 근거를 확인하세요.)"
    client = OpenAI(base_url=base_url, api_key="ollama") if base_url else OpenAI()
    try:
        resp = client.chat.completions.create(
            model=os.getenv("CHAT_MODEL", DEFAULT_CHAT_MODEL),
            temperature=0,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + build_prompt(cve, hits)},
                {"role": "user", "content": question},
            ],
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"(답변 생성 실패: {type(e).__name__} — 아래 근거를 확인하세요.)"


# --------------------------------------------------------------------------
# 명령줄 실행
# --------------------------------------------------------------------------
def run_cli(cve_id: str, question: str, mapping, collection, embedding_fn) -> None:
    cve = mapping.get(cve_id.upper())
    if not cve:
        print(f"[CVE 조회] {cve_id}: 매핑 정보가 없습니다. "
              f"(data/cve_cwe_mapping.json 에 있는 CVE만 조회할 수 있습니다)")
        return
    print(format_cve(cve))
    print(f"  질문: {question}\n")
    print(format_hits(search(collection, embedding_fn, cve, question)))
    print()


def run_ui(mapping, collection, embedding_fn, share: bool = False) -> None:
    import gradio as gr

    def respond(message: str, history):
        found = CVE_PATTERN.findall(message)
        if not found:
            examples = ", ".join(list(mapping)[:3])
            return f"질문에 CVE ID를 함께 적어 주세요. 예: `{examples.split(', ')[0]}은 왜 위험한가요?`\n\n조회 가능한 CVE 예: {examples}"
        cve = mapping.get(found[0].upper())
        if not cve:
            return f"`{found[0]}` 는 수집된 데이터에 없습니다. `data/cve_cwe_mapping.json` 에 있는 CVE만 조회할 수 있습니다."
        hits = search(collection, embedding_fn, cve, message)
        answer = generate_answer(cve, hits, message)
        evidence = "\n".join(
            f"{i}. **{h['cwe_id']} / {h['section']}** (거리 {h['distance']:.3f}) — {h['cwe_name']}"
            for i, h in enumerate(hits, 1))
        return (f"**{cve['cve_id']}** · CVSS {cve.get('cvss_score')} ({cve.get('severity') or '-'}) · "
                f"CWE: {', '.join(cve['cwe_ids'])}\n\n{answer}\n\n"
                f"<details><summary>검색된 근거 보기</summary>\n\n{evidence}\n\n</details>")

    gr.ChatInterface(
        respond,
        title="CVE → CWE 취약점 유형 학습 챗봇",
        description="질문에 CVE ID를 적으면 연결된 CWE 문서에서 근거를 찾아 답합니다.",
        examples=[f"{cid}은 왜 위험한가요?" for cid in list(mapping)[:3]],
    ).launch(server_name="127.0.0.1", share=share)


def main() -> None:
    args = sys.argv[1:]
    mapping = load_mapping()
    collection, embedding_fn = open_collection()

    if args and args[0] == "--ui":
        run_ui(mapping, collection, embedding_fn, share="--share" in args)
    elif args:
        question = args[1] if len(args) > 1 else DEFAULT_QUESTION
        run_cli(args[0], question, mapping, collection, embedding_fn)
    else:
        print(f"[데모] 데이터에 있는 CVE {len(mapping)}건 중 3건을 조회합니다.\n")
        for cve_id in list(mapping)[:3]:
            run_cli(cve_id, DEFAULT_QUESTION, mapping, collection, embedding_fn)


if __name__ == "__main__":
    main()
