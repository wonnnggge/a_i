"""
2단계: 임베딩 생성 -> 벡터 DB 저장

기본 임베딩은 OpenAI(text-embedding-3-small)다. .env의 OPENAI_API_KEY만 있으면
바로 동작하고, 이 프로젝트에서 실제로 가장 좋은 검색 품질을 냈다.

    같은 질문 "how should developers prevent this?" 에 대한 코사인 거리
      TF-IDF  0.94 ~ 1.00   (사실상 무매칭)
      OpenAI  0.52 ~ 0.54   (관련 섹션을 제대로 찾음)

환경변수로 임베딩 방식을 바꿀 수 있다:

    EMBEDDING_BACKEND=openai   (기본)          # OPENAI_API_KEY 필요
    EMBEDDING_BACKEND=tfidf                    # 키 없이 동작, 품질 낮음(비교 실습용)
    EMBEDDING_BACKEND=sentence-transformers    # pip install sentence-transformers

어느 쪽을 고르든 이후 단계(3_query.py)는 코드 변경 없이 동작한다.
단, 색인과 검색은 반드시 같은 백엔드여야 한다. 다르면 3_query.py가 막아준다.
"""
import json
import os
import pickle
from pathlib import Path

import chromadb
from chromadb import Documents, EmbeddingFunction, Embeddings
from sklearn.feature_extraction.text import TfidfVectorizer

DATA_DIR = Path(__file__).parent.parent / "data"
CHROMA_DIR = DATA_DIR / "chroma_db"
VECTORIZER_PATH = DATA_DIR / "tfidf_vectorizer.pkl"
CONFIG_PATH = DATA_DIR / "embedding_config.json"
COLLECTION_NAME = "cwe_catalog"

DEFAULT_ST_MODEL = "BAAI/bge-m3"
DEFAULT_OPENAI_MODEL = "text-embedding-3-small"


# --------------------------------------------------------------------------
# 임베딩 함수 세 가지
#
# '임베딩(embedding)'이란 글을 숫자 목록(벡터)으로 바꾸는 일이다. 컴퓨터는
# 글의 의미를 직접 이해하지 못하므로, 의미가 비슷한 글이 비슷한 숫자 목록이
# 되도록 변환해두고 숫자끼리 거리를 재서 '비슷하다'를 판단한다.
#
#     "SQL 주입을 막는 방법"  ->  [0.021, -0.184, 0.339, ... ]  (숫자 수백~수천 개)
#
# 아래 세 클래스는 모두 '글 목록을 받아 숫자 목록들을 돌려준다'는 같은 약속을
# 지킨다. 그래서 어느 것을 꽂아도 나머지 코드는 바꿀 필요가 없다. 이렇게
# 겉모습(인터페이스)만 맞추면 속을 갈아끼울 수 있게 만드는 것이 좋은 설계다.
# --------------------------------------------------------------------------

class TfidfEmbeddingFunction(EmbeddingFunction):
    """단어의 등장 빈도만으로 글을 숫자로 바꾸는, 가장 단순한 임베딩 방식.

    TF-IDF가 뭔가:
      Term Frequency - Inverse Document Frequency의 약자다. 두 가지를 곱한다.
        TF  (단어 빈도)      -- 이 단어가 이 문서에 몇 번 나왔나. 많이 나올수록 중요.
        IDF (역문서 빈도)    -- 이 단어가 전체 문서 중 몇 개에 나왔나.
                                모든 문서에 다 나오는 흔한 단어일수록 덜 중요.

      그래서 'the'나 'is' 같은 단어는 점수가 거의 0이 되고, 'deserialization'처럼
      특정 문서에만 나오는 단어는 점수가 높아진다. 결과적으로 문서마다 '어떤
      단어가 이 문서를 특징짓는가'가 숫자로 표현된다.

    한계 (매우 중요):
      TF-IDF는 글자만 볼 뿐 의미를 모른다. 그래서 '자동차'와 '승용차'가 같은
      뜻이라는 걸 전혀 알지 못하고, 질문에 문서와 똑같은 단어가 들어 있지 않으면
      아무것도 찾지 못한다. 실제로 이 프로젝트에서 영어 질문을 던졌을 때
      TF-IDF는 코사인 거리 0.94~1.00(사실상 무매칭)이 나왔지만, 아래 두 신경망
      방식은 0.52까지 내려갔다. 파이프라인 구조를 설치 없이 보여주는 기본값으로만
      쓰고, 실제로 써볼 때는 백엔드를 바꾸는 것이 좋다.

    왜 vectorizer를 저장해야 하나:
      TF-IDF는 미리 문서들을 훑어 '어떤 단어들을 쓸지, 각 단어가 몇 번째 칸에
      들어갈지'를 정해둔다. 이 표를 어휘(vocabulary)라고 한다. 검색할 때 질문도
      반드시 같은 표를 써야 같은 칸에 같은 단어가 놓여 비교가 성립한다.
      그래서 학습한 vectorizer를 pickle 파일로 저장해 3_query.py가 다시 불러 쓴다.

    __init__ 과 __call__:
      __init__은 객체를 만들 때 한 번 불리는 '생성자'다. 여기서는 받은
      vectorizer를 self에 보관해둔다. self는 이 객체 자신을 가리키는 이름이라,
      self.vectorizer에 넣어두면 다른 메서드에서도 꺼내 쓸 수 있다.

      __call__은 특별한 이름의 메서드로, 이걸 정의해두면 객체를 함수처럼
      괄호를 붙여 부를 수 있다.

          fn = TfidfEmbeddingFunction(v)
          fn(["문장1", "문장2"])     # 이 순간 __call__이 실행된다

      Chroma가 임베딩 함수를 이런 식으로 호출하기로 약속돼 있어서 이 이름을 쓴다.

    toarray()와 tolist()를 부르는 이유:
      transform()의 결과는 '희소 행렬(sparse matrix)'이다. 8192칸 중 대부분이
      0이라 0을 저장하지 않고 아낀 형태인데, Chroma는 평범한 리스트를 원한다.
      toarray()로 0까지 다 채운 배열로 펴고, tolist()로 파이썬 리스트로 바꾼다.

    name()에 붙은 @staticmethod:
      객체(self) 없이도 부를 수 있는 메서드라는 표시다. 이 함수는 self의 값을
      전혀 쓰지 않고 항상 "tfidf"만 돌려주므로 굳이 객체가 필요 없다.
      이 이름은 '어떤 방식으로 색인했는지'를 파일에 기록해, 나중에 3_query.py가
      다른 방식으로 검색하려 하면 막는 데 쓰인다.
    """

    def __init__(self, vectorizer: TfidfVectorizer):
        self.vectorizer = vectorizer

    def __call__(self, input: Documents) -> Embeddings:
        matrix = self.vectorizer.transform(input)
        return matrix.toarray().tolist()

    @staticmethod
    def name() -> str:
        return "tfidf"


class SentenceTransformerEmbeddingFunction(EmbeddingFunction):
    """내 컴퓨터에서 직접 돌리는 신경망 임베딩. 의미를 이해하므로 품질이 훨씬 좋다.

    TF-IDF와 뭐가 다른가:
      단어가 겹치는지가 아니라 '뜻이 통하는지'를 본다. 수많은 문장으로 미리
      학습된 신경망이 문장 전체를 읽고 의미를 벡터로 압축하기 때문에,
      "어떻게 막나요"와 "prevention methods"처럼 겹치는 글자가 하나도 없어도
      가까운 벡터가 나온다.

    장단점:
      장점 -- 인터넷 연결이나 API 키 없이 무료로 무제한 쓸 수 있고, 데이터가
              외부로 나가지 않아 보안이 중요한 환경에 적합하다.
      단점 -- 처음 실행할 때 모델 파일을 내려받아야 한다. 기본값인 BAAI/bge-m3는
              2GB가 넘고, GPU가 없으면 문서가 많을 때 꽤 느리다.

    import를 함수 안에서 하는 이유:
      보통 import는 파일 맨 위에 모아 쓰지만, 여기서는 __init__ 안에 넣었다.
      sentence_transformers는 이 프로젝트의 필수 패키지가 아니라서 설치돼 있지
      않을 수 있는데, 파일 맨 위에 두면 이 방식을 안 쓰는 사람까지 파일을
      여는 순간 ImportError로 막힌다. 실제로 이 클래스를 만들 때만 import하면
      쓰는 사람만 설치하면 된다. 이런 것을 '지연 임포트(lazy import)'라고 한다.

    normalize_embeddings=True:
      벡터의 길이를 전부 1로 맞춰달라는 뜻이다. 코사인 유사도는 원래 벡터의
      '방향'만 보는 계산인데, 길이를 1로 통일해두면 계산이 단순해지고 값도
      안정적이다. 아래에서 Chroma에 "hnsw:space": "cosine"을 지정하는 것과
      짝을 이루는 설정이다.
    """

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
    """OpenAI 서버에 글을 보내 임베딩을 받아오는 방식. 설치가 필요 없고 빠르다.

    언제 쓰나:
      품질은 신경망 수준으로 좋으면서 무거운 모델을 내려받을 필요가 없다.
      이 프로젝트에서 실제로 가장 좋은 결과를 낸 방식이다.

    준비물:
      OPENAI_API_KEY가 있어야 한다. build_embedding_function()이 .env 파일을
      먼저 읽어 환경변수로 올려두므로, 프로젝트 루트 .env에 적어두면 된다.
      OpenAI() 생성자는 인자를 안 줘도 알아서 환경변수에서 키를 찾는다.
      코드에 키를 직접 적으면 git에 올라가 유출되므로 절대 그렇게 하면 안 된다.

    비용:
      글자 수만큼 돈이 나가지만 임베딩은 매우 싸다. 이 프로젝트의 청크 298개는
      전부 합쳐도 몇 원 수준이다. 다만 문서가 수십만 개로 늘면 얘기가 달라지니,
      2_embed_and_store.py를 습관적으로 반복 실행하지는 않는 게 좋다.

    리스트 컴프리헨션:
      return [d.embedding for d in resp.data]
      OpenAI는 결과를 객체 목록으로 주는데, 각 객체의 embedding 속성만 뽑아
      새 리스트를 만드는 문법이다. for 문으로 풀어 쓰면 이것과 같다.

          result = []
          for d in resp.data:
              result.append(d.embedding)
          return result

      보낸 글의 순서와 받은 결과의 순서는 OpenAI가 보장하므로, 그대로 이어
      쓰면 어느 벡터가 어느 글의 것인지 어긋나지 않는다.

    list(input)로 감싸는 이유:
      Chroma가 넘겨주는 input이 리스트가 아닐 수도 있어서, API에 보내기 전에
      확실히 리스트로 바꿔둔다. 방어적으로 형을 맞춰두면 예상 못 한 입력에도
      안전하다.
    """

    def __init__(self, model_name: str = DEFAULT_OPENAI_MODEL):
        from openai import OpenAI
        self.model_name = model_name
        self.client = OpenAI()

    def __call__(self, input: Documents) -> Embeddings:
        resp = self.client.embeddings.create(model=self.model_name, input=list(input))
        return [d.embedding for d in resp.data]

    @staticmethod
    def name() -> str:
        return "openai"


def build_embedding_function(texts: list[str] | None = None) -> EmbeddingFunction:
    """설정에 맞는 임베딩 함수를 골라 만들어 준다. 이 파일에서 가장 중요한 함수다.

    무슨 일을 하나:
      EMBEDDING_BACKEND 환경변수를 읽어서, 위의 세 클래스 중 하나를 만들어
      돌려준다. 이런 식으로 '설정에 따라 알맞은 객체를 만들어 주는' 함수를
      팩토리(factory) 함수라고 부른다.

      덕분에 2_embed_and_store.py와 3_query.py 어디에도 "TF-IDF를 쓴다"거나
      "OpenAI를 쓴다"는 내용이 적혀 있지 않다. 두 파일 모두 그냥 이 함수를
      부르기만 하면 된다. 나중에 다른 임베딩을 추가하고 싶으면 클래스 하나를
      만들고 이 함수에 if 한 덩어리만 더하면 되고, 나머지 코드는 손댈 필요가 없다.

    사용법 (한 함수가 두 가지 상황을 처리한다):
      build_embedding_function(texts)  -- 색인할 때. 이 글들로 TF-IDF를 새로
                                          학습하고 그 결과를 파일에 저장한다.
      build_embedding_function()       -- 검색할 때. 저장해둔 학습 결과를
                                          파일에서 불러온다.

      texts에 기본값 None이 있어서 인자 없이도 부를 수 있고, 함수는 그 값이
      None인지 보고 지금이 어느 상황인지 판단한다. 신경망이나 API 방식은 미리
      학습해둘 것이 없으므로 양쪽 상황에서 하는 일이 똑같다.

    환경변수란:
      코드를 고치지 않고 프로그램의 동작을 바꾸는 통로다. 명령 앞에 붙여 쓴다.

          EMBEDDING_BACKEND=openai python src/2_embed_and_store.py

      os.getenv("EMBEDDING_BACKEND", "openai")는 그 값을 읽되 없으면 "openai"를
      쓰라는 뜻이다. 뒤에 붙은 .strip().lower()는 실수로 들어간 공백을 없애고
      대문자를 소문자로 바꾸는 것으로, "OpenAI "라고 적어도 동작하게 해준다.
      사용자의 사소한 실수를 너그럽게 받아주는 작은 배려다.

    모르는 값이면 에러를 내는 이유:
      if backend != "tfidf": raise ValueError(...)
      EMBEDDING_BACKEND=openia 처럼 오타를 냈다고 치자. 여기서 막지 않고 조용히
      TF-IDF로 넘어가면, 사용자는 OpenAI를 쓰고 있다고 믿는 채로 한참 나쁜
      검색 결과를 보며 원인을 찾게 된다. 잘못된 설정은 그 자리에서 분명하게
      알려주는 편이 훨씬 친절하다.

    pickle이란:
      파이썬 객체를 파일로 통째로 저장했다가 그대로 되살리는 기능이다.
      학습을 마친 vectorizer 객체에는 어휘 표와 IDF 값이 들어 있는데, 이걸
      JSON으로 옮기려면 직접 변환 코드를 써야 한다. pickle은 객체를 그대로
      저장해주므로 간단하다.

      "wb"의 b는 바이너리(binary) 모드라는 뜻이다. pickle은 사람이 읽는 글자가
      아니라 바이트를 쓰기 때문에 반드시 b가 필요하다. 읽을 때는 "rb"다.

      주의: pickle 파일은 열 때 코드가 실행될 수 있는 형식이라, 남이 준 pickle
      파일을 함부로 열면 위험하다. 여기서는 우리가 방금 만든 파일만 읽으므로
      문제가 없다.

    TfidfVectorizer의 두 옵션:
      max_features=8192   -- 가장 중요한 단어 8192개만 쓴다. 실제 CWE 원문에는
                             단어 종류가 훨씬 많은데, 전부 쓰면 벡터가 쓸데없이
                             커지고 느려진다. 상위 몇 개만 남기는 것이 보통이다.
      stop_words="english"-- 'the', 'is', 'and'처럼 어느 문서에나 나와서 구별에
                             도움이 안 되는 영어 단어를 미리 뺀다.
      이 두 값을 바꿔가며 검색 결과가 어떻게 달라지는지 실험해보면 TF-IDF의
      동작을 이해하는 데 도움이 된다.
    """
    # 프로젝트 루트 .env의 OPENAI_API_KEY 등을 읽어온다.
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    backend = os.getenv("EMBEDDING_BACKEND", "openai").strip().lower()

    if backend == "sentence-transformers":
        model = os.getenv("EMBEDDING_MODEL", DEFAULT_ST_MODEL)
        return SentenceTransformerEmbeddingFunction(model)

    if backend == "openai":
        model = os.getenv("EMBEDDING_MODEL", DEFAULT_OPENAI_MODEL)
        return OpenAIEmbeddingFunction(model)

    if backend != "tfidf":
        raise ValueError(f"알 수 없는 EMBEDDING_BACKEND: {backend}")

    if texts is None:
        with open(VECTORIZER_PATH, "rb") as f:
            return TfidfEmbeddingFunction(pickle.load(f))

    # 실데이터는 CWE 원문이라 어휘가 넓다. 샘플 6개짜리 데모보다 넉넉히 잡는다.
    vectorizer = TfidfVectorizer(max_features=8192, stop_words="english")
    vectorizer.fit(texts)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    return TfidfEmbeddingFunction(vectorizer)


def main():
    """이 파일의 시작점. 청크를 임베딩해 벡터 DB에 저장한다.

    전체 흐름:
      1. data/chunks.json 읽기            (1단계가 만든 파일)
      2. 임베딩 함수 준비                 -> build_embedding_function(texts)
      3. 어떤 방식을 썼는지 파일에 기록    -> embedding_config.json
      4. Chroma 컬렉션을 새로 만들기
      5. 청크를 500개씩 나눠 저장 (이때 임베딩이 실제로 계산된다)

    벡터 DB(Chroma)가 뭔가:
      벡터를 저장해두고 "이 벡터와 가장 가까운 것 3개를 찾아줘"라는 질문에
      빠르게 답해주는 특수한 데이터베이스다. 일반 DB는 값이 정확히 같은 것을
      찾지만, 벡터 DB는 '가장 비슷한 것'을 찾는다는 점이 다르다.

      PersistentClient는 결과를 디스크(data/chroma_db/)에 저장하는 방식이다.
      메모리에만 두는 방식도 있지만 그러면 프로그램이 끝날 때 다 사라져서,
      3_query.py에서 다시 쓸 수가 없다.

      '컬렉션(collection)'은 일반 DB의 테이블에 해당하는 개념으로, 관련된
      데이터를 담는 묶음이다.

    기존 컬렉션을 지우고 다시 만드는 이유:
      if COLLECTION_NAME in [...]: client.delete_collection(...)
      이 줄이 없으면 스크립트를 두 번 돌렸을 때 같은 ID가 이미 있다며 에러가
      나거나, 옛 데이터와 새 데이터가 뒤섞인다. 매번 깨끗한 상태에서 시작하면
      몇 번을 실행하든 결과가 같아져서 훨씬 안전하다. 이런 성질을 멱등성
      (idempotency)이라고 부른다.

    metadata={"hnsw:space": "cosine"}:
      벡터 사이의 '거리'를 어떻게 잴지 정하는 설정이다. cosine(코사인)은 두
      벡터가 이루는 각도만 보고 길이는 무시한다. 글이 길어서 벡터 값이 전반적으로
      커지는 것과, 내용이 실제로 비슷한 것을 혼동하지 않으려면 이 방식이 좋다.

      결과의 '거리' 값은 0에 가까울수록 비슷하고 1에 가까우면 거의 무관하다는
      뜻이다. 3_query.py 출력에 나오는 그 숫자가 이것이다.

      hnsw는 수십만 개 벡터 중에서 가까운 것을 빠르게 찾아내는 알고리즘 이름이다.
      전부 하나씩 비교하면 너무 느리므로, 약간의 정확도를 포기하는 대신 훨씬
      빠르게 근사적으로 찾는 방식이다.

    임베딩은 언제 계산되나:
      create_collection에 embedding_function을 넘겨두면, collection.add()에
      글을 넣는 순간 Chroma가 알아서 그 함수를 불러 벡터를 만든다. 우리가 직접
      임베딩을 계산해 넘길 필요가 없다. OpenAI 방식을 쓸 때 이 add() 부분에서
      시간이 걸리는 이유가 그 안에서 실제로 API를 호출하기 때문이다.

    500개씩 나눠 넣는 이유:
      Chroma는 한 번에 넣을 수 있는 개수에 상한이 있고, OpenAI API도 한 번에
      보낼 수 있는 양에 제한이 있다. 지금은 298개라 사실 한 번에 들어가지만,
      --cwe-scope all로 수천 개를 만들면 상한에 걸린다. 미리 나눠 넣도록 해두면
      데이터가 커져도 코드를 고칠 필요가 없다.

      range(0, len(chunks), 500)은 0, 500, 1000... 처럼 500씩 건너뛴 숫자를
      만들어 준다. chunks[start:end]는 그 구간만 잘라내는 슬라이싱인데,
      end가 리스트 길이를 넘어가도 에러 없이 남은 만큼만 잘라주므로 마지막
      묶음이 500개가 안 되어도 안전하다.

      진행률 출력에 min(end, len(chunks))를 쓰는 것은, 마지막 묶음에서 end가
      실제 개수보다 커져 '500/298' 같은 이상한 숫자가 나오는 것을 막기 위해서다.

    embedding_config.json에 기록하는 이유:
      OpenAI로 색인해두고 TF-IDF로 검색하면, 벡터의 칸 수부터 달라서 검색이
      실패하거나 의미 없는 결과가 나온다. 어떤 방식으로 색인했는지 적어두면
      3_query.py가 그걸 읽고 불일치를 미리 잡아 알려줄 수 있다.
    """
    with open(DATA_DIR / "chunks.json", encoding="utf-8") as f:
        chunks = json.load(f)

    texts = [c["text"] for c in chunks]

    embedding_fn = build_embedding_function(texts)
    # 3_query.py가 색인할 때와 같은 백엔드를 쓰도록 기록해둔다.
    CONFIG_PATH.write_text(
        json.dumps({"backend": embedding_fn.name()}, indent=2), encoding="utf-8"
    )
    print(f"임베딩 백엔드: {embedding_fn.name()}")

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    # 재실행 시 기존 컬렉션 초기화
    if COLLECTION_NAME in [c.name for c in client.list_collections()]:
        client.delete_collection(COLLECTION_NAME)
    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
        metadata={"hnsw:space": "cosine"},
    )

    metadatas = [
        {
            "cwe_id": c["cwe_id"],
            "cwe_name": c["cwe_name"],
            "section": c["section"],
            "source_type": c["source_type"],
        }
        for c in chunks
    ]

    # 실데이터는 청크 수가 수천 개가 될 수 있어 한 번에 넣으면 Chroma의
    # 배치 상한에 걸린다. 나눠서 넣는다.
    batch_size = 500
    for start in range(0, len(chunks), batch_size):
        end = start + batch_size
        collection.add(
            ids=[c["chunk_id"] for c in chunks[start:end]],
            documents=texts[start:end],
            metadatas=metadatas[start:end],
        )
        print(f"  저장 {min(end, len(chunks))}/{len(chunks)}")

    print(f"벡터 DB 저장 완료: {collection.count()}개 청크 -> {CHROMA_DIR}")


# `python src/2_embed_and_store.py`로 직접 실행할 때만 main()이 호출된다.
# 3_query.py는 이 파일을 import해서 위의 클래스와 build_embedding_function()만
# 가져다 쓰는데, 이 블록 덕분에 그때 색인이 다시 실행되는 사고가 나지 않는다.
if __name__ == "__main__":
    main()
