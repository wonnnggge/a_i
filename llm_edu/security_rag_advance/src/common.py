"""
공용 모듈: 경로, 임베딩 백엔드, 청킹 유틸, 질의 정리

1단계 프로젝트(../security_rag)에서 검증된 코드를 이 프로젝트의 경로에 맞춰
가져온 것이다. 1단계 모듈을 직접 import하지 않는 이유는, 그쪽 코드가
security_rag/data 를 가리키도록 경로가 박혀 있어 그대로 쓰면 이 프로젝트의
데이터가 아니라 1단계 데이터를 읽고 쓰게 되기 때문이다.

여기에 모아둔 것:
  - 경로 상수
  - 임베딩 백엔드 3종 (tfidf / openai / sentence-transformers)
  - 청킹 유틸 (줄 경계 분할, 문단 경계 분할)
  - 질의 정리 (검색어에서 CVE ID 제거)
  - CVE ID 추출
"""
from __future__ import annotations

import json
import os
import pickle
import re
from pathlib import Path

from chromadb import Documents, EmbeddingFunction, Embeddings
from sklearn.feature_extraction.text import TfidfVectorizer

# --------------------------------------------------------------------------
# 경로
# --------------------------------------------------------------------------
PROJECT_DIR = Path(__file__).parent.parent
DATA_DIR = PROJECT_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
CHROMA_DIR = DATA_DIR / "chroma_db"
VECTORIZER_PATH = DATA_DIR / "tfidf_vectorizer.pkl"
CONFIG_PATH = DATA_DIR / "embedding_config.json"

CWE_CATALOG_PATH = DATA_DIR / "cwe_catalog.json"
CVE_CORE_PATH = DATA_DIR / "cve_core.json"
ADVISORIES_PATH = DATA_DIR / "advisories.json"
CHUNKS_PATH = DATA_DIR / "chunks.json"

COLLECTION_NAME = "cve_advisory"

DEFAULT_ST_MODEL = "BAAI/bge-m3"
DEFAULT_OPENAI_MODEL = "text-embedding-3-small"

# 사용자가 문장 어디에 적어 넣었든 CVE ID를 찾아내기 위한 정규식.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

DEFAULT_QUESTION = "why is this dangerous and what should we do about it?"


def load_env() -> None:
    """프로젝트 루트의 .env를 읽어 환경변수로 올린다.

    python-dotenv가 없어도 동작해야 하므로 ImportError는 무시한다.
    API 키 없이도 (기능이 줄어든 채로) 파이프라인이 돌아가게 하기 위해서다.
    """
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass


def read_json(path: Path, default=None):
    """JSON 파일을 읽는다. 파일이 없으면 default를 돌려준다.

    파이프라인 단계마다 앞 단계의 산출물이 없을 수 있는데, 그때 예외로 죽는 대신
    빈 값으로 흘려보내고 호출부가 안내 문구를 내도록 한다.
    """
    if not path.exists():
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data) -> None:
    """JSON 파일로 저장한다.

    ensure_ascii=False로 한글을 그대로 저장하고, encoding="utf-8"을 명시해
    윈도우 기본 인코딩 때문에 글자가 깨지는 것을 막는다.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------
# 임베딩 백엔드
#
# 세 클래스 모두 '글 목록을 받아 숫자 목록을 돌려준다'는 같은 약속을 지킨다.
# 그래서 어느 것을 꽂아도 나머지 파이프라인은 바뀌지 않는다.
# --------------------------------------------------------------------------

class TfidfEmbeddingFunction(EmbeddingFunction):
    """단어 빈도 기반 임베딩. 설치가 가벼워 기본값으로 쓴다.

    의미를 모르고 글자만 보기 때문에 품질은 낮다. 특히 이 프로젝트는
    한국어 질문을 자주 던지게 되는데, 어휘 표가 영문 문서로 만들어져
    한국어 단어는 전부 버려진다. 실제로 쓸 때는 openai 백엔드를 권장한다.
    """

    def __init__(self, vectorizer: TfidfVectorizer):
        self.vectorizer = vectorizer

    def __call__(self, input: Documents) -> Embeddings:
        return self.vectorizer.transform(input).toarray().tolist()

    @staticmethod
    def name() -> str:
        return "tfidf"


class SentenceTransformerEmbeddingFunction(EmbeddingFunction):
    """로컬 신경망 임베딩. 첫 실행 시 모델을 내려받는다(2GB 이상일 수 있음)."""

    def __init__(self, model_name: str = DEFAULT_ST_MODEL):
        from sentence_transformers import SentenceTransformer
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)

    def __call__(self, input: Documents) -> Embeddings:
        return self.model.encode(list(input), normalize_embeddings=True).tolist()

    @staticmethod
    def name() -> str:
        return "sentence-transformers"


class OpenAIEmbeddingFunction(EmbeddingFunction):
    """OpenAI 임베딩 API. .env의 OPENAI_API_KEY를 사용한다."""

    def __init__(self, model_name: str = DEFAULT_OPENAI_MODEL):
        from openai import OpenAI
        self.model_name = model_name
        try:
            self.client = OpenAI()
        except Exception as error:
            # 키가 없으면 openai SDK가 긴 traceback을 뱉는다. 무엇을 해야 하는지
            # 알려주는 메시지로 바꾼다. 임베딩은 답변 생성과 달리 건너뛸 수 없다.
            # 색인이 openai 벡터로 만들어져 있으면 질문도 같은 방식으로 변환해야
            # 하기 때문이다. 그래서 여기서는 대안을 안내하고 멈춘다.
            raise SystemExit(
                f"OpenAI 임베딩을 쓰려면 API 키가 필요합니다 ({error}).\n"
                f"  - .env에 OPENAI_API_KEY를 설정하거나\n"
                f"  - 키 없이 쓰려면 tfidf로 다시 색인하세요:\n"
                f"      EMBEDDING_BACKEND=tfidf python src/2_embed_and_store.py --full"
            ) from None

    def __call__(self, input: Documents) -> Embeddings:
        resp = self.client.embeddings.create(model=self.model_name, input=list(input))
        return [d.embedding for d in resp.data]

    @staticmethod
    def name() -> str:
        return "openai"


def build_embedding_function(texts: list[str] | None = None) -> EmbeddingFunction:
    """EMBEDDING_BACKEND 환경변수에 맞는 임베딩 함수를 만들어 돌려준다.

    texts를 주면 '색인 단계'로 보고 TF-IDF를 새로 학습해 저장하고,
    주지 않으면 '검색 단계'로 보고 저장해둔 vectorizer를 불러온다.
    신경망/API 백엔드는 미리 학습할 것이 없어 양쪽이 같다.

    질문도 색인할 때와 같은 어휘 표로 변환해야 비교가 성립하므로,
    TF-IDF의 vectorizer는 반드시 파일로 저장했다가 재사용해야 한다.
    """
    load_env()
    backend = os.getenv("EMBEDDING_BACKEND", "openai").strip().lower()

    if backend == "sentence-transformers":
        return SentenceTransformerEmbeddingFunction(
            os.getenv("EMBEDDING_MODEL", DEFAULT_ST_MODEL))

    if backend == "openai":
        return OpenAIEmbeddingFunction(
            os.getenv("EMBEDDING_MODEL", DEFAULT_OPENAI_MODEL))

    if backend != "tfidf":
        # 오타를 조용히 기본값으로 흘려보내면, 사용자는 원하는 백엔드를 쓰고 있다고
        # 믿은 채 나쁜 결과를 보게 된다. 그 자리에서 알려주는 편이 낫다.
        raise ValueError(f"알 수 없는 EMBEDDING_BACKEND: {backend}")

    if texts is None:
        if not VECTORIZER_PATH.exists():
            raise SystemExit(
                f"{VECTORIZER_PATH} 가 없습니다. 먼저 2_embed_and_store.py를 실행하세요.")
        with open(VECTORIZER_PATH, "rb") as f:
            return TfidfEmbeddingFunction(pickle.load(f))

    vectorizer = TfidfVectorizer(max_features=8192, stop_words="english")
    vectorizer.fit(texts)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    return TfidfEmbeddingFunction(vectorizer)


def check_backend_match() -> None:
    """색인에 쓴 백엔드와 지금 검색에 쓰려는 백엔드가 같은지 확인한다.

    openai로 색인해두고 tfidf로 검색하면 벡터의 칸 수부터 달라(1536 대 8192)
    검색이 실패하거나 의미 없는 결과가 나온다. 그때 나오는 에러 메시지는
    원인을 알기 어려우므로, 여기서 미리 잡아 무엇을 고치면 되는지 알려준다.

    임베딩 함수를 '만들기 전에' 검사한다:
      이 검사를 build_embedding_function() 뒤에 두면, tfidf로 검색하려 할 때
      vectorizer 파일이 없다는 에러가 먼저 나서 진짜 원인(openai로 색인해둠)이
      가려진다. 환경변수만 읽어 비교하면 되므로 무거운 모델을 만들기 전에
      먼저 확인하는 편이 낫다.
    """
    if not CONFIG_PATH.exists():
        return
    load_env()
    wanted = os.getenv("EMBEDDING_BACKEND", "openai").strip().lower()
    indexed = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["backend"]
    if indexed != wanted:
        raise SystemExit(
            f"색인은 '{indexed}' 백엔드로 만들어졌는데 지금은 "
            f"'{wanted}'로 검색하려 합니다.\n"
            f"EMBEDDING_BACKEND={indexed} 로 맞추거나, "
            f"원하는 백엔드로 2_embed_and_store.py --full 을 다시 실행하세요."
        )


# --------------------------------------------------------------------------
# 청킹 유틸
# --------------------------------------------------------------------------

def split_long_section(text: str, max_chars: int = 1200) -> list[str]:
    """긴 글을 줄 경계에서 나눈다. 항목이 한 줄씩인 글(완화 방법, 사례)에 쓴다.

    글자 수로 무조건 자르면 문장이 한가운데서 끊겨 검색에도 나쁘고 읽기도 나쁘다.
    줄 경계를 지키면 항목이 통째로 보존된다.

    buffer가 비어 있을 때는 길이를 넘겨도 그냥 담는다. 이 조건이 없으면
    한 줄 자체가 max_chars보다 길 때 빈 조각이 계속 만들어진다.
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


def split_paragraphs(text: str, max_chars: int = 1200) -> list[str]:
    """긴 산문을 문단 경계에서 나눈다. OSV의 details처럼 서술형 글에 쓴다.

    split_long_section과 나누는 단위가 다르다. 어드바이저리 본문은 빈 줄로
    문단이 갈리는 산문이라, 줄 단위로 자르면 한 문단이 조각난다.

    문단 하나가 그 자체로 max_chars를 넘으면 줄 경계 분할로 한 번 더 쪼갠다.
    """
    if len(text) <= max_chars:
        return [text.strip()] if text.strip() else []

    parts, buffer = [], ""
    for para in re.split(r"\n\s*\n", text):
        para = para.strip()
        if not para:
            continue
        if buffer and len(buffer) + len(para) + 2 > max_chars:
            parts.append(buffer)
            buffer = para
        else:
            buffer = f"{buffer}\n\n{para}" if buffer else para
    if buffer:
        parts.append(buffer)

    # 문단 하나가 통째로 너무 길면 줄 단위로 한 번 더 나눈다.
    final = []
    for part in parts:
        final.extend(split_long_section(part, max_chars) if len(part) > max_chars else [part])
    return final


# --------------------------------------------------------------------------
# 질의 처리
# --------------------------------------------------------------------------

def detect_language(text: str) -> str:
    """질문이 한국어인지 영어인지 판단한다. 'ko' 또는 'en'을 돌려준다.

    왜 필요한가:
      영어로 물었는데 한국어로 답하면 사용자는 답을 다시 번역해 읽어야 한다.
      질문한 언어로 답하는 것이 맞다.

    판단 방법:
      한글 음절(가~힣)이 하나라도 있으면 한국어로 본다. 보안 문서를 다루다
      보면 "CVE-2021-44228 우리는 log4j-core 2.14.1을 씁니다"처럼 영어 낱말이
      섞인 한국어 질문이 흔한데, 이 규칙이면 그런 경우도 한국어로 제대로 잡는다.

      반대로 한글이 하나도 없으면 영어로 본다. 영어 질문에 한국어 단어가
      섞일 일은 거의 없으므로 이 비대칭이 실용적이다.

      언어 감지 라이브러리를 쓰지 않는 이유는, 짧은 질문에서는 오히려 정확도가
      떨어지고 의존성만 늘기 때문이다. 두 언어만 구분하면 되는 상황에서는
      이 정도가 충분하다.
    """
    return "ko" if re.search(r"[가-힣]", text or "") else "en"


def extract_cve_id(message: str) -> str | None:
    """사용자가 쓴 문장 어디에 섞여 있든 CVE ID를 찾아낸다.

    "CVE-2021-44228이 왜 위험한가요?", "cve-2014-0160 알려줘",
    "Log4Shell(CVE-2021-44228) 예방법" 같은 문장에서 ID만 뽑는다.
    매핑 테이블의 열쇠가 대문자이므로 찾은 뒤 대문자로 맞춘다.
    """
    found = CVE_PATTERN.search(message)
    return found.group().upper() if found else None


def clean_query(question: str) -> str:
    """검색어에서 CVE ID를 제거한다. 검색 품질에 큰 영향을 준다.

    1단계 프로젝트에서 확인한 문제다. 질문을 그대로 검색어로 넘기면
    '예방 방법'을 물었는데 CVE 번호가 나열된 섹션이 최상위로 올라온다.
    임베딩이 질문의 '의도'가 아니라 'CVE 번호라는 글자 모양'을 보고 매칭하기
    때문이다.

        검색어에 CVE ID 포함 -> observed_examples (거리 0.495~0.514)
        검색어에서 CVE 제거   -> potential_mitigations (거리 0.686~0.711)

    2단계에서는 더 중요하다. 어드바이저리 본문에도 CVE 번호가 잔뜩 들어 있어
    같은 현상이 더 심하게 나타난다.

    CVE ID는 이미 메타데이터 필터로 검색 범위를 좁히는 데 쓰이므로,
    의미 검색에는 의도가 담긴 문장만 넘기면 된다.
    """
    stripped = " ".join(CVE_PATTERN.sub(" ", question).split())
    return stripped or DEFAULT_QUESTION
