"""
2단계: 임베딩 생성 → 벡터 DB 저장

1단계 프로젝트와 구조는 같지만, **부분 갱신**이 추가됐다.

왜 부분 갱신이 필요한가:
  1단계는 CWE 문서만 다뤘고 CWE는 거의 안 바뀌므로, 매번 컬렉션을 통째로
  지우고 다시 만들어도 문제가 없었다. 그러나 2단계의 어드바이저리는
  패치가 나올 때마다 내용이 바뀐다. CVE 하나의 어드바이저리가 갱신됐다고
  CWE 문서까지 전부 다시 임베딩하면 시간과 비용이 낭비된다.

  그래서 기본 동작은 upsert(있으면 갱신, 없으면 추가)이고,
  --full을 주면 1단계처럼 전체를 새로 만든다.

임베딩 백엔드는 EMBEDDING_BACKEND 환경변수로 고른다.
  openai (기본) / tfidf (키 없이 비교용) / sentence-transformers

사용 예:
    python src/2_embed_and_store.py              # 부분 갱신(upsert)
    python src/2_embed_and_store.py --full       # 전체 재색인

    # 백엔드를 바꿔 비교할 때 (PowerShell)
    $env:EMBEDDING_BACKEND = "tfidf"
    python src/2_embed_and_store.py --full
"""
import argparse
import json

import chromadb

import common

BATCH_SIZE = 200

# Chroma 메타데이터로 넘길 필드. 본문(text)과 헤더는 문서로 따로 들어가므로 제외한다.
METADATA_KEYS = ("scope", "source_type", "cve_id", "cwe_id",
                 "vendor", "section", "fetched_at")


def get_or_create_collection(client, embedding_fn, reset: bool):
    """컬렉션을 가져오거나 새로 만든다.

    metadata={"hnsw:space": "cosine"}:
      벡터 사이의 거리를 코사인으로 재라는 설정이다. 코사인은 두 벡터가 이루는
      각도만 보고 길이는 무시한다. 글이 길어서 벡터 값이 전반적으로 커지는 것과
      내용이 실제로 비슷한 것을 혼동하지 않으려면 이 방식이 맞다.
      결과의 거리 값은 0에 가까울수록 비슷하고 1에 가까우면 무관하다는 뜻이다.

    reset=True(--full)면 기존 컬렉션을 지우고 새로 만든다. 임베딩 백엔드를
    바꿨을 때는 벡터의 차원 자체가 달라지므로 반드시 이 방식으로 다시 만들어야 한다.
    """
    existing = [c.name for c in client.list_collections()]
    if reset and common.COLLECTION_NAME in existing:
        client.delete_collection(common.COLLECTION_NAME)
        existing.remove(common.COLLECTION_NAME)

    if common.COLLECTION_NAME in existing:
        return client.get_collection(common.COLLECTION_NAME,
                                     embedding_function=embedding_fn), False

    return client.create_collection(
        name=common.COLLECTION_NAME,
        embedding_function=embedding_fn,
        metadata={"hnsw:space": "cosine"},
    ), True


def drop_stale_instance_chunks(collection, chunks: list[dict]) -> None:
    """이번에 다시 넣을 CVE의 옛 어드바이저리 청크를 먼저 지운다.

    왜 필요한가:
      upsert는 '같은 chunk_id'를 덮어쓸 뿐, 사라진 청크는 지우지 못한다.
      예를 들어 어제는 어드바이저리 details가 문단 3개라 청크가 3개였는데
      오늘 벤더가 내용을 줄여 2개가 됐다면, 옛 3번째 청크가 DB에 남아
      검색 결과에 낡은 내용이 계속 딸려 나온다.

      그래서 이번에 갱신하는 CVE에 한해, 그 CVE의 instance 청크를 통째로
      지우고 새로 넣는다. CWE 청크(scope="type")는 건드리지 않으므로
      비싼 재임베딩이 일어나지 않는다.

    where 조건의 $and:
      Chroma에서 조건 두 개를 함께 걸 때 쓰는 문법이다. 여기서는
      "이 CVE의 것이면서 동시에 instance인 청크"만 지운다.
    """
    cve_ids = {c["cve_id"] for c in chunks if c["scope"] == "instance" and c["cve_id"]}
    for cve_id in sorted(cve_ids):
        collection.delete(where={"$and": [
            {"cve_id": cve_id},
            {"scope": "instance"},
        ]})
    if cve_ids:
        print(f"  기존 instance 청크 정리: CVE {len(cve_ids)}건")


def store(collection, chunks: list[dict], upsert: bool) -> None:
    """청크를 벡터 DB에 넣는다. 임베딩은 이 시점에 계산된다.

    create_collection에 embedding_function을 넘겨뒀기 때문에, add/upsert에
    글을 넣는 순간 Chroma가 그 함수를 불러 벡터를 만든다. openai 백엔드를
    쓸 때 이 부분에서 시간이 걸리는 이유가 그 안에서 API를 호출하기 때문이다.

    나눠 넣는 이유:
      Chroma는 한 번에 넣을 수 있는 개수에 상한이 있고, OpenAI API도 한 번에
      보낼 수 있는 양에 제한이 있다. 지금은 청크가 100여 개뿐이라 한 번에
      들어가지만, --from-kev 100 같은 옵션으로 CVE를 늘리면 상한에 걸린다.
      미리 나눠 넣도록 해두면 데이터가 커져도 코드를 고칠 필요가 없다.
    """
    write = collection.upsert if upsert else collection.add
    for start in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[start:start + BATCH_SIZE]
        write(
            ids=[c["chunk_id"] for c in batch],
            documents=[c["text"] for c in batch],
            metadatas=[{k: c[k] for k in METADATA_KEYS} for c in batch],
        )
        print(f"  저장 {min(start + BATCH_SIZE, len(chunks))}/{len(chunks)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="임베딩 생성 후 Chroma에 저장")
    parser.add_argument("--full", action="store_true",
                        help="컬렉션을 지우고 전체를 새로 만든다 "
                             "(임베딩 백엔드를 바꿨다면 반드시 사용)")
    args = parser.parse_args()

    chunks = common.read_json(common.CHUNKS_PATH, [])
    if not chunks:
        raise SystemExit("청크가 없습니다. 먼저 1_chunk.py를 실행하세요.")

    texts = [c["text"] for c in chunks]
    embedding_fn = common.build_embedding_function(texts)
    print(f"임베딩 백엔드: {embedding_fn.name()}")

    # 3_query.py가 같은 백엔드로 검색하도록 기록해둔다. 색인과 검색의 백엔드가
    # 다르면 벡터 차원이 안 맞아 검색이 실패하거나 무의미한 결과가 나온다.
    common.CONFIG_PATH.write_text(
        json.dumps({"backend": embedding_fn.name()}, indent=2), encoding="utf-8")

    client = chromadb.PersistentClient(path=str(common.CHROMA_DIR))
    collection, created = get_or_create_collection(client, embedding_fn, args.full)

    if created:
        print("새 컬렉션 생성 - 전체 색인")
        store(collection, chunks, upsert=False)
    else:
        print("기존 컬렉션에 부분 갱신")
        drop_stale_instance_chunks(collection, chunks)
        store(collection, chunks, upsert=True)

    total = collection.count()
    print(f"\n벡터 DB 저장 완료: {total}개 청크 -> {common.CHROMA_DIR}")
    print("다음 단계: python src/3_query.py")


if __name__ == "__main__":
    main()
