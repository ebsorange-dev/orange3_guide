# orange3web

EBS Orange3 웹 배포 — Docker 기반 한국어 Orange3 GUI를 브라우저에서 다중 세션으로 제공하는 시스템.

각 사용자에게 격리된 Orange3 컨테이너를 동적으로 할당하고, 화면을 noVNC(WebSocket RFB)로 브라우저에 전송한다. 세션 매니저가 워밍풀·라우팅·언어 전환·워크플로우 업로드 등을 담당한다.

## 구성

| 구성 요소 | 설명 |
|-----------|------|
| `session_manager/` | FastAPI 세션 매니저 — 컨테이너 spawn·워밍풀·래퍼 페이지(WRAPPER_PAGE)·API |
| `Dockerfile` | Orange3 GUI 컨테이너 이미지 (noVNC + Xvnc + openbox + Orange3) |
| `Dockerfile.webserver` | 웹 API 서버 이미지 |
| `Dockerfile.xpra` | Xpra 전송 실험 이미지 (PoC) |
| `docker-compose.yml` | 세션 매니저 · 웹 서버 · 이미지 빌드 타깃 |
| `docker-compose.nginx.yml` | Nginx 정적 오프로드 오버레이 (opt-in) |
| `orange3_launcher.py` | 컨테이너 내 Orange3 기동 + IPC(위젯 추가·삭제·언어 등) |
| `ko_gui_patch.py` | Orange3 GUI 한국어 패치 |
| `widgets_override/` | 한국어/기능 커스터마이징된 위젯 오버라이드 |
| `html/` | 래퍼 UI·모달·데이터셋 페이지 |
| `nginx/` | Nginx 리버스 프록시 + 정적 alias 설정 |
| `Korean.json` | orangecanvas 한국어 번역 |
| `startapp.sh` / `startapp.xpra.sh` | 컨테이너 기동 스크립트 |

## 설정

```bash
cp .env.example .env   # HOST_BASE, Google OAuth 값 입력 (.env 는 커밋 금지)
```

## 배포 / 실행 (Docker)

이 프로젝트는 **Docker 기반 배포만** 사용한다(서버리스/Vercel 미사용 — `vercel.json` 에서
git 배포 비활성). 멀티 컨테이너(세션 매니저 + 동적 GUI 컨테이너 + 웹 서버)라 Docker
호스트가 필요하다.

```bash
docker compose -f docker-compose.yml --profile build-only build   # 이미지 빌드
docker compose up -d                                              # 세션 매니저·웹 서버 기동
# 세션 매니저: http://localhost:8888
```

> **참고**: Docker 빌드는 한국어 번역이 적용된 Orange3 소스 트리(`orange3/`)에 의존한다.
> `orange3/` 는 별도 벤더 저장소라 이 리포에는 포함되지 않는다(`.gitignore` 참조).

## 참고

- 화면 전송은 noVNC WebSocket RFB (스크린샷 폴링 아님)
- 런타임 데이터(`sessions/`, `config/`, `data/`)·대용량 교재 콘텐츠(`_upload_ows_/`)는 리포에서 제외
