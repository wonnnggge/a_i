# Git 명령어 레퍼런스 (a_i 프로젝트)

이 프로젝트(`D:\a_i`)에서 Git을 사용할 때 필요한 명령어를 정리한 문서입니다.

| 항목 | 값 |
|---|---|
| 로컬 경로 | `D:\a_i` |
| GitHub 저장소 | https://github.com/wonnnggge/a_i |
| 원격 이름 | `origin` → `https://github.com/wonnnggge/a_i.git` |
| 기본 브랜치 | `main` |
| 환경 | Windows 11 · PowerShell · uv 가상환경(`.venv`) |

---

## 1. 설치 및 확인

| 명령어 | 설명 |
|---|---|
| `winget install --id Git.Git -e --source winget` | Git 설치 |
| `git --version` | 설치 확인 |
| `winget upgrade --id Git.Git` | Git 업데이트 |

> ⚠️ **설치 직후 `git`을 찾을 수 없다는 오류가 날 때**
> 설치 전에 열려 있던 터미널과 VS Code는 새 PATH를 모릅니다.
> **VS Code를 완전히 종료한 뒤 다시 여세요.** 당장 쓰려면 현재 창에서 다음을 실행합니다.
> ```powershell
> $env:Path = "C:\Program Files\Git\cmd;" + $env:Path
> ```

---

## 2. 최초 설정 (PC당 한 번)

| 명령어 | 설명 |
|---|---|
| `git config --global user.name "wonnnggge"` | 커밋 작성자 이름 |
| `git config --global user.email "이메일"` | 커밋 작성자 이메일 |
| `git config --global init.defaultBranch main` | 새 저장소의 기본 브랜치를 `main`으로 |
| `git config --global core.autocrlf true` | Windows 줄바꿈(CRLF) 자동 변환 |
| `git config --list` | 현재 설정 확인 |
| `git config --local --list` | 이 저장소에만 적용된 설정 확인 |

> 이 프로젝트는 저장소 단위(`--local`)로 `user.name`과 `user.email`이 설정되어 있습니다.

---

## 3. 일상 작업 흐름 ⭐

파일을 수정한 뒤 GitHub에 올리는 기본 순서입니다.

```powershell
git status                       # 무엇이 바뀌었는지 확인
git add .                        # 변경된 파일 전체를 스테이징
git commit -m "변경 내용 설명"     # 커밋 (로컬 저장)
git push                         # GitHub에 업로드
```

다른 PC나 GitHub 웹에서 수정한 내용을 가져올 때는 다음을 실행합니다.

```powershell
git pull
```

---

## 4. 상태 확인

| 명령어 | 설명 |
|---|---|
| `git status` | 변경·스테이징 상태 확인 |
| `git status -sb` | 짧게 보기 (브랜치와 원격 대비 상태 포함) |
| `git diff` | 아직 스테이징하지 않은 변경 내용 |
| `git diff --staged` | 스테이징된(커밋 예정인) 변경 내용 |
| `git log --oneline` | 커밋 기록을 한 줄씩 보기 |
| `git log --oneline --graph --all` | 브랜치 그래프로 보기 |
| `git show <커밋ID>` | 특정 커밋의 내용 |
| `git ls-files` | Git이 추적 중인 파일 목록 |

---

## 5. 스테이징과 커밋

| 명령어 | 설명 |
|---|---|
| `git add 파일명` | 특정 파일만 스테이징 |
| `git add llm_edu/` | 특정 폴더만 스테이징 |
| `git add .` | 모든 변경 스테이징 |
| `git restore --staged 파일명` | 스테이징 취소 (수정 내용은 유지) |
| `git commit -m "메시지"` | 커밋 |
| `git commit --amend -m "새 메시지"` | 직전 커밋 메시지 수정 (**push 전에만**) |

### 커밋 메시지 예시

```text
docs: uv 명령어 레퍼런스 추가
feat: OpenAI API 호출 예제 추가
fix: .env 경로 오류 수정
chore: 의존성 업데이트 (uv.lock)
```

---

## 6. 원격 저장소 (GitHub)

| 명령어 | 설명 |
|---|---|
| `git remote -v` | 연결된 원격 주소 확인 |
| `git remote add origin <URL>` | 원격 저장소 연결 (최초 1회) |
| `git remote set-url origin <URL>` | 원격 주소 변경 |
| `git push -u origin main` | 첫 push (이후에는 `git push`만 써도 됨) |
| `git push` | 업로드 |
| `git pull` | 원격 변경 가져오기와 병합 |
| `git fetch` | 원격 변경 가져오기만 (병합 안 함) |
| `git clone https://github.com/wonnnggge/a_i.git` | 다른 PC에서 저장소 내려받기 |

### 다른 PC에서 이 프로젝트 시작하기

```powershell
git clone https://github.com/wonnnggge/a_i.git
cd a_i
uv sync                          # uv.lock 기준으로 .venv 생성과 패키지 설치
```

---

## 7. 브랜치

| 명령어 | 설명 |
|---|---|
| `git branch` | 로컬 브랜치 목록 |
| `git branch -a` | 원격 포함 전체 브랜치 |
| `git switch -c feature/rag` | 새 브랜치 만들고 이동 |
| `git switch main` | `main`으로 이동 |
| `git merge feature/rag` | 현재 브랜치에 병합 |
| `git branch -d feature/rag` | 병합된 브랜치 삭제 |
| `git push -u origin feature/rag` | 브랜치를 GitHub에 올리기 |

---

## 8. 되돌리기

| 명령어 | 설명 |
|---|---|
| `git restore 파일명` | 파일 수정 취소, 마지막 커밋 상태로 복원 (**수정 내용 사라짐**) |
| `git restore --staged 파일명` | 스테이징만 취소 |
| `git reset --soft HEAD~1` | 직전 커밋 취소 (변경 내용은 스테이징 상태로 유지) |
| `git revert <커밋ID>` | 해당 커밋을 되돌리는 새 커밋 생성 (**push 후에는 이 방법 사용**) |
| `git stash` | 작업 중인 변경을 임시 보관 |
| `git stash pop` | 임시 보관한 변경 다시 적용 |

> ⚠️ `git reset --hard`와 `git push --force`는 작업 내용을 영구히 지울 수 있으니 사용 전에 반드시 확인하세요.

---

## 9. .gitignore — 올리면 안 되는 파일

현재 `.venv/`는 uv가 넣어 둔 `.venv\.gitignore` 덕분에 자동으로 제외됩니다.
API 키를 다룰 예정이라면 프로젝트 루트에 `.gitignore`를 만들어 두는 것을 권장합니다.

```gitignore
# 가상환경
.venv/

# 환경 변수 (API 키 등)
.env

# Python
__pycache__/
*.pyc

# 빌드 결과물
dist/
build/
*.egg-info/

# IDE
.vscode/
.idea/
```

| 파일 | 커밋 여부 |
|---|---|
| `pyproject.toml`, `uv.lock`, `.python-version` | ✅ 커밋 (환경 재현에 필요) |
| `.venv/` | ❌ 제외 (`uv sync`로 다시 만들 수 있음) |
| `.env` (API 키) | ❌ **절대 커밋 금지** |

> 이미 커밋된 파일을 추적에서만 빼려면 `git rm --cached 파일명`을 실행합니다. 로컬 파일은 남습니다.

---

## 10. 문제 해결 (이 프로젝트에서 실제로 겪은 것)

### `git` 용어가 cmdlet … 으로 인식되지 않습니다
- **원인:** Git 설치 전에 열린 터미널이라 PATH가 갱신되지 않았습니다.
- **해결:** VS Code를 완전히 재시작합니다. 임시로는 `$env:Path = "C:\Program Files\Git\cmd;" + $env:Path`를 실행합니다.

### `remote: Repository not found.`
- **원인 1:** GitHub에 저장소가 아직 만들어지지 않았습니다. `github.com/new`에서 **Create repository**까지 눌러야 합니다.
- **원인 2:** 원격 주소의 계정과 브라우저에 로그인한 계정이 다릅니다. Private 저장소는 다른 계정에서 404로 보입니다.
- **확인:** 브라우저에서 저장소 주소를 열어 보고, `git remote -v`의 주소와 같은지 비교합니다.
- **해결:**
  ```powershell
  git remote set-url origin https://github.com/<올바른계정>/a_i.git
  ```

### 다른 GitHub 계정으로 로그인되어 버렸을 때
```powershell
cmdkey /delete:git:https://github.com    # 저장된 로그인 정보 삭제
git push                                  # 다시 로그인 창이 뜸 → 올바른 계정으로 승인
```
> 로그인 창은 **기본 브라우저**에서 열립니다. 그 브라우저에 원하는 GitHub 계정으로 로그인되어 있는지 확인하세요.

### `remote origin already exists`
- 원격이 이미 등록되어 있다는 뜻입니다. 주소를 바꾸려면 `git remote set-url origin <URL>`을 사용합니다.

### `! [rejected] main -> main (fetch first)`
- GitHub에 로컬에 없는 커밋이 있습니다. 예를 들어 웹에서 README를 수정한 경우입니다.
- **해결:** `git pull` 후 다시 `git push` 합니다.

### `Everything up-to-date`
- 오류가 아닙니다. 올릴 새 커밋이 없다는 뜻입니다. 먼저 `git add`와 `git commit`을 했는지 확인하세요.

---

## 11. 자주 쓰는 조합 요약

```powershell
# 변경 확인 → 커밋 → 업로드
git status
git add .
git commit -m "docs: git 명령어 문서 추가"
git push

# 최신 상태로 맞추기
git pull

# 새 기능은 브랜치에서
git switch -c feature/새기능
# ... 작업, 커밋 ...
git push -u origin feature/새기능
```
