# uv 명령어 레퍼런스

[uv](https://docs.astral.sh/uv/)는 Rust로 작성된 빠른 Python 패키지·프로젝트 관리 도구입니다.
`pip`, `pip-tools`, `virtualenv`, `pyenv`, `pipx`, `poetry`의 역할을 하나로 통합합니다.

---

## 1. 설치 및 업데이트

| 명령어 | 설명 |
|---|---|
| `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 \| iex"` | Windows 설치 (공식 스크립트) |
| `curl -LsSf https://astral.sh/uv/install.sh \| sh` | macOS / Linux 설치 |
| `winget install --id=astral-sh.uv -e` | winget으로 설치 |
| `pip install uv` | pip으로 설치 |
| `uv self update` | uv 자체 업데이트 (스크립트로 설치한 경우) |
| `uv --version` | uv 버전 확인 |
| `uv help <명령어>` | 명령어 도움말 |

---

## 2. Python 버전 관리

| 명령어 | 설명 |
|---|---|
| `uv python list` | 설치 가능한 버전과 설치된 버전 목록 |
| `uv python install 3.12` | 특정 Python 버전 설치 |
| `uv python install 3.11 3.12` | 여러 버전 한 번에 설치 |
| `uv python find 3.12` | 설치된 Python 경로 찾기 |
| `uv python pin 3.12` | 현재 디렉터리에 `.python-version` 파일 생성 (버전 고정) |
| `uv python uninstall 3.12` | Python 버전 삭제 |

---

## 3. 프로젝트 관리 (`pyproject.toml` 기반)

### 프로젝트 생성

| 명령어 | 설명 |
|---|---|
| `uv init` | 현재 디렉터리를 프로젝트로 초기화 |
| `uv init my-project` | 새 디렉터리에 프로젝트 생성 |
| `uv init --app` | 애플리케이션 프로젝트 (기본값) |
| `uv init --lib` | 라이브러리 프로젝트 (`src/` 구조, 빌드 설정 포함) |
| `uv init --python 3.12` | Python 버전을 지정하여 생성 |

### 의존성 추가·삭제

| 명령어 | 설명 |
|---|---|
| `uv add requests` | 패키지 추가 (`pyproject.toml` + `uv.lock` 갱신 + 설치) |
| `uv add "fastapi>=0.110"` | 버전 조건을 지정하여 추가 |
| `uv add --dev pytest ruff` | 개발용 의존성 추가 (`dev` 그룹) |
| `uv add --group docs mkdocs` | 지정한 의존성 그룹에 추가 |
| `uv add --optional gpu torch` | 선택적 의존성(extra)에 추가 |
| `uv add -r requirements.txt` | requirements.txt의 패키지를 일괄 추가 |
| `uv add git+https://github.com/user/repo` | Git 저장소에서 추가 |
| `uv add --editable ./local-pkg` | 로컬 패키지를 편집 가능 모드로 추가 |
| `uv remove requests` | 패키지 제거 |
| `uv remove --dev pytest` | 개발 의존성 제거 |

### 동기화·잠금

| 명령어 | 설명 |
|---|---|
| `uv sync` | `uv.lock` 기준으로 `.venv`를 동기화 (없으면 생성) |
| `uv sync --no-dev` | 개발 의존성 제외하고 동기화 |
| `uv sync --all-extras` | 모든 선택적 의존성 포함 |
| `uv sync --frozen` | lock 파일을 갱신하지 않고 그대로 사용 |
| `uv sync --locked` | lock 파일이 최신이 아니면 오류 (CI용) |
| `uv lock` | `uv.lock` 파일 생성·갱신 |
| `uv lock --upgrade` | 모든 패키지를 허용 범위 내 최신으로 업그레이드 |
| `uv lock --upgrade-package requests` | 특정 패키지만 업그레이드 |
| `uv tree` | 의존성 트리 출력 |
| `uv tree --outdated` | 업데이트 가능한 패키지 표시 |
| `uv export --format requirements-txt -o requirements.txt` | lock 파일을 requirements.txt로 내보내기 |

### 실행

| 명령어 | 설명 |
|---|---|
| `uv run main.py` | 프로젝트 가상환경에서 스크립트 실행 (자동 sync) |
| `uv run python` | 프로젝트 환경의 Python REPL 실행 |
| `uv run pytest` | 프로젝트 환경에 설치된 명령 실행 |
| `uv run --with rich main.py` | 일회성으로 패키지를 추가하여 실행 |
| `uv run --python 3.11 main.py` | 특정 Python 버전으로 실행 |

> 💡 `uv run`을 사용하면 가상환경을 **activate하지 않아도** 됩니다.
> PowerShell 실행 정책 때문에 `Activate.ps1`이 막히는 경우에도 유용합니다.

---

## 4. 가상환경

| 명령어 | 설명 |
|---|---|
| `uv venv` | 현재 디렉터리에 `.venv` 생성 |
| `uv venv myenv` | 이름을 지정하여 생성 |
| `uv venv --python 3.12` | Python 버전을 지정하여 생성 |
| `uv venv --seed` | pip, setuptools를 함께 설치 |

### 활성화 / 비활성화

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1

# Windows cmd
.venv\Scripts\activate.bat

# macOS / Linux
source .venv/bin/activate

# 비활성화 (공통)
deactivate
```

> ⚠️ PowerShell에서 "스크립트를 실행할 수 없으므로…" 오류가 나면 실행 정책을 변경합니다.
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

---

## 5. pip 호환 인터페이스 (`uv pip`)

기존 `pip` 워크플로우를 그대로 쓰면서 속도만 높이고 싶을 때 사용합니다.

| 명령어 | 설명 |
|---|---|
| `uv pip install requests` | 패키지 설치 |
| `uv pip install -r requirements.txt` | requirements.txt로 설치 |
| `uv pip install -e .` | 현재 프로젝트를 편집 가능 모드로 설치 |
| `uv pip install --system requests` | 가상환경이 아닌 시스템 Python에 설치 |
| `uv pip uninstall requests` | 패키지 삭제 |
| `uv pip list` | 설치된 패키지 목록 |
| `uv pip show requests` | 패키지 정보 확인 |
| `uv pip freeze > requirements.txt` | 설치된 패키지를 파일로 저장 |
| `uv pip compile requirements.in -o requirements.txt` | 의존성을 고정 버전으로 컴파일 |
| `uv pip sync requirements.txt` | 환경을 파일 내용과 정확히 일치시킴 (나머지는 삭제) |
| `uv pip check` | 의존성 충돌 확인 |

---

## 6. 도구(Tool) 실행 및 설치 — pipx 대체

| 명령어 | 설명 |
|---|---|
| `uvx ruff check .` | 도구를 임시 환경에서 바로 실행 (`uv tool run`의 축약) |
| `uvx ruff@0.6.0 check .` | 특정 버전으로 실행 |
| `uvx --from httpie http` | 패키지명과 명령어 이름이 다를 때 |
| `uv tool install ruff` | 도구를 전역 설치 (PATH에 등록) |
| `uv tool list` | 설치된 도구 목록 |
| `uv tool upgrade ruff` | 도구 업그레이드 |
| `uv tool upgrade --all` | 모든 도구 업그레이드 |
| `uv tool uninstall ruff` | 도구 삭제 |
| `uv tool update-shell` | 도구 실행 경로를 PATH에 추가 |

---

## 7. 단일 스크립트 (인라인 메타데이터)

| 명령어 | 설명 |
|---|---|
| `uv init --script example.py` | 인라인 메타데이터가 포함된 스크립트 생성 |
| `uv add --script example.py requests` | 스크립트에 의존성 선언 추가 |
| `uv run example.py` | 선언된 의존성을 자동 설치 후 실행 |

스크립트 상단에 아래와 같은 블록이 추가됩니다.

```python
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests",
# ]
# ///
```

---

## 8. 빌드 및 배포

| 명령어 | 설명 |
|---|---|
| `uv build` | sdist와 wheel 빌드 (`dist/`에 생성) |
| `uv publish` | PyPI에 업로드 |
| `uv publish --token <TOKEN>` | 토큰을 지정하여 업로드 |

---

## 9. 캐시 관리

| 명령어 | 설명 |
|---|---|
| `uv cache dir` | 캐시 디렉터리 경로 확인 |
| `uv cache clean` | 캐시 전체 삭제 |
| `uv cache clean requests` | 특정 패키지 캐시만 삭제 |
| `uv cache prune` | 사용하지 않는 캐시 정리 |

---

## 10. 자주 쓰는 전역 옵션

| 옵션 | 설명 |
|---|---|
| `--python <버전>` | 사용할 Python 버전 지정 |
| `--index-url <URL>` | 기본 패키지 인덱스 변경 |
| `--extra-index-url <URL>` | 추가 패키지 인덱스 지정 (예: PyTorch CUDA) |
| `--offline` | 네트워크 없이 캐시만 사용 |
| `--no-cache` | 캐시 사용 안 함 |
| `-q`, `--quiet` | 출력 최소화 |
| `-v`, `--verbose` | 상세 출력 |

---

## 11. 실전 워크플로우 예시

### 새 프로젝트 시작

```powershell
uv init llm-project
cd llm-project
uv python pin 3.12
uv add openai anthropic python-dotenv
uv add --dev pytest ruff
uv run main.py
```

### 기존 프로젝트 clone 후 환경 구성

```powershell
git clone <repo-url>
cd <repo>
uv sync
uv run python main.py
```

### requirements.txt 기반 프로젝트를 uv로 전환

```powershell
uv init
uv add -r requirements.txt
```

### PyTorch(CUDA) 설치 예시

```powershell
uv pip install torch --index-url https://download.pytorch.org/whl/cu124
```

---

## 12. pip ↔ uv 명령어 대응표

| pip / 기존 도구 | uv |
|---|---|
| `python -m venv .venv` | `uv venv` |
| `pip install requests` | `uv add requests` (프로젝트) / `uv pip install requests` |
| `pip uninstall requests` | `uv remove requests` / `uv pip uninstall requests` |
| `pip install -r requirements.txt` | `uv pip install -r requirements.txt` |
| `pip freeze` | `uv pip freeze` |
| `pip-compile` | `uv pip compile` |
| `pipx run ruff` | `uvx ruff` |
| `pipx install ruff` | `uv tool install ruff` |
| `pyenv install 3.12` | `uv python install 3.12` |
| `poetry add` / `poetry install` | `uv add` / `uv sync` |
