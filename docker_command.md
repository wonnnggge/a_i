# Docker 명령어 레퍼런스 (a_i 프로젝트)

이 프로젝트(`D:\a_i`)에서 Docker를 사용할 때 필요한 명령어를 정리한 문서입니다.
주로 [llm_edu/mcp_basic.ipynb](llm_edu/mcp_basic.ipynb)의 Docker 기반 MCP 서버 실습에서 사용합니다.

| 항목 | 값 |
|---|---|
| 로컬 경로 | `D:\a_i` |
| Docker 버전 | Docker Desktop (Engine 29.x) |
| 사용 이미지 | `mcp/filesystem`, `mcp/fetch` |
| 환경 | Windows 11 · PowerShell · uv 가상환경(`.venv`) |

---

## 1. 설치 및 확인

| 명령어 | 설명 |
|---|---|
| `winget install --id Docker.DockerDesktop -e` | Docker Desktop 설치 |
| `docker --version` | 설치 확인 |
| `docker info` | 엔진이 실행 중인지 확인 (오류가 나면 Docker Desktop이 꺼져 있는 것) |
| `docker run --rm hello-world` | 동작 테스트 |

> ⚠️ **`docker`를 찾을 수 없다는 오류가 날 때**
> 설치 전에 열려 있던 터미널, VS Code, Jupyter 커널은 새 PATH를 모릅니다.
> **VS Code를 완전히 종료한 뒤 다시 열고, 노트북 커널도 재시작하세요.**

> ⚠️ **`error during connect` / `cannot find the file specified` 오류가 날 때**
> Docker Desktop 앱이 실행되지 않은 상태입니다. 시작 메뉴에서 Docker Desktop을 실행하고
> 고래 아이콘이 "Engine running"이 될 때까지 기다린 뒤 다시 시도하세요.

---

## 2. 이미지 관리

| 명령어 | 설명 |
|---|---|
| `docker pull mcp/filesystem` | 파일시스템 MCP 서버 이미지 받기 |
| `docker pull mcp/fetch` | 웹 페이지 가져오기(fetch) MCP 서버 이미지 받기 |
| `docker images` | 내려받은 이미지 목록 |
| `docker image inspect mcp/fetch` | 이미지 상세 정보 (엔트리포인트, 환경변수 등) |
| `docker rmi mcp/fetch` | 이미지 삭제 |
| `docker image prune` | 사용하지 않는(태그 없는) 이미지 정리 |

> 💡 노트북에서 처음 `docker run`을 하면 이미지를 내려받느라 오래 걸려 **MCP 연결이 타임아웃**될 수 있습니다.
> 실습 전에 터미널에서 `docker pull`을 먼저 한 번 실행해 두세요.

---

## 3. 컨테이너 실행 ⭐

```powershell
docker run [옵션] <이미지> [이미지에 넘길 인자]
```

| 옵션 | 설명 |
|---|---|
| `-i` | 표준입력을 열어 둠 (**MCP stdio 서버에 필수**) |
| `-t` | 터미널(TTY) 할당 — 사람이 직접 셸을 쓸 때 `-it`로 함께 사용 |
| `--rm` | 컨테이너가 끝나면 자동 삭제 |
| `-d` | 백그라운드 실행 |
| `--name <이름>` | 컨테이너 이름 지정 |
| `-p 8080:80` | 포트 연결 (내 PC 8080 → 컨테이너 80) |
| `-e KEY=VALUE` | 환경변수 전달 |
| `--mount type=bind,src=<내PC경로>,dst=<컨테이너경로>` | 내 PC 폴더를 컨테이너에 연결 |
| `--mount ...,readonly` | 위와 같지만 읽기 전용 |
| `--entrypoint <명령>` | 이미지의 기본 실행 명령을 바꿈 |

> ⚠️ MCP 서버를 Python(`MCPServerStdio`)에서 띄울 때는 **`-t`를 넣지 마세요.**
> TTY가 붙으면 JSON-RPC 메시지가 깨져서 연결이 실패합니다. `-i --rm`만 사용합니다.

---

## 4. MCP 서버 실습용 명령어

### 4-1. filesystem 서버

내 PC의 `sandbox` 폴더만 컨테이너 안 `/projects/sandbox`로 연결하고, 서버는 `/projects` 아래만 접근하도록 제한합니다.

```powershell
docker run -i --rm `
  --mount type=bind,src=D:\a_i\llm_edu\sandbox,dst=/projects/sandbox `
  mcp/filesystem /projects
```

노트북에서는 같은 명령을 다음처럼 표현합니다.

```python
docker_files_params = {
    "command": "docker",
    "args": [
        "run", "-i", "--rm",
        "--mount", f"type=bind,src={sandbox_path},dst=/projects/sandbox",
        "mcp/filesystem",
        "/projects",
    ],
}
```

### 4-2. fetch 서버

```powershell
docker run -i --rm mcp/fetch
```

> 💡 노트북에서 연결이 안 될 때 위 명령을 터미널에서 직접 실행해 보면 원인(이미지 없음, 엔진 꺼짐 등)을 바로 확인할 수 있습니다.
> 정상이라면 아무 출력 없이 입력을 기다립니다. `Ctrl+C`로 종료하세요.

### 4-3. 컨테이너 안에서 sandbox 확인하기

```powershell
# 마운트된 폴더 목록 보기
docker run --rm --mount type=bind,src=D:\a_i\llm_edu\sandbox,dst=/projects/sandbox `
  --entrypoint ls mcp/filesystem -la /projects/sandbox

# 컨테이너 셸로 들어가서 직접 둘러보기
docker run --rm -it --mount type=bind,src=D:\a_i\llm_edu\sandbox,dst=/projects/sandbox `
  --entrypoint sh mcp/filesystem
```

---

## 5. 실행 중인 컨테이너 확인·제어

| 명령어 | 설명 |
|---|---|
| `docker ps` | 실행 중인 컨테이너 목록 |
| `docker ps -a` | 종료된 컨테이너까지 모두 보기 |
| `docker logs <컨테이너>` | 컨테이너 로그 |
| `docker logs -f <컨테이너>` | 로그 실시간 보기 |
| `docker exec -it <컨테이너> sh` | 실행 중인 컨테이너에 셸로 접속 |
| `docker stop <컨테이너>` | 정상 종료 |
| `docker kill <컨테이너>` | 강제 종료 |
| `docker rm <컨테이너>` | 종료된 컨테이너 삭제 |
| `docker stats` | CPU·메모리 사용량 실시간 보기 |

> 💡 `<컨테이너>` 자리에는 `docker ps`에 나오는 **CONTAINER ID 앞 몇 글자** 또는 **NAMES**를 넣으면 됩니다.

---

## 6. 정리 (디스크 공간 확보)

| 명령어 | 설명 |
|---|---|
| `docker system df` | 이미지·컨테이너·볼륨이 차지하는 용량 |
| `docker container prune` | 종료된 컨테이너 모두 삭제 |
| `docker image prune -a` | 컨테이너가 쓰지 않는 이미지 모두 삭제 |
| `docker system prune` | 종료된 컨테이너·네트워크·임시 이미지 정리 |

> ⚠️ `prune` 계열은 확인 질문 후 되돌릴 수 없이 삭제합니다. `-a`를 붙이면 다시 `docker pull` 해야 하는 이미지까지 지워집니다.

---

## 7. 자주 만나는 문제

| 증상 | 원인 / 해결 |
|---|---|
| `docker: command not found` / `용어가 cmdlet... 인식되지 않습니다` | Docker 미설치 또는 PATH 미반영 → VS Code·커널 재시작 |
| `error during connect` | Docker Desktop이 꺼져 있음 → 앱 실행 후 재시도 |
| MCP `list_tools()` 타임아웃 | 이미지 미다운로드 → `docker pull` 먼저 실행, `client_session_timeout_seconds` 늘리기 |
| 컨테이너에서 파일이 안 보임 | `--mount`의 `src`는 **절대경로**여야 함 → `os.path.abspath()` 사용 |
| `Access denied - path outside allowed directories` | filesystem 서버 인자(`/projects`) 밖의 경로를 요청함 |
| `the input device is not a TTY` | 파이프/노트북 환경에서 `-t` 사용 → `-t` 제거 |
