# Nginx 정적 오프로드 — 적용 가이드

성능 개선 보고서 **Strategy 3 (Nginx 정적 파일 오프로딩)** 구현 준비물.

## 파일 구성

| 파일 | 역할 |
|------|------|
| `nginx/nginx.conf` | Nginx 설정 (정적 alias + SSE/WS reverse proxy) |
| `docker-compose.nginx.yml` | Nginx 컨테이너 정의 (운영 무중단 opt-in 오버레이) |
| `nginx/README.md` | 본 문서 |

## 작동 원리

```
                                ┌────────────────────────┐
사용자  ──── /static/* ────────▶│  Nginx (alias)         │── 디스크 직접
                                │  /logo                 │
                                │  /static/orange_logo.. │
                                └────────────────────────┘
                                          │
                                          ▼ (그 외 모든 요청)
                                ┌────────────────────────┐
                                │ session-manager:8080   │── FastAPI
                                │ (SSE, WS, API, 폴링)   │
                                └────────────────────────┘
```

## 정적 핸들러 매핑

| FastAPI 핸들러 | 파일 후보 | Nginx 처리 |
|----------------|-----------|------------|
| `/logo` | `/app/orange_logo.png` | ✅ alias (변경 없음) |
| `/splash-image` | `orange-splash-{02,01,03}.png` | ⚠️ proxy 유지 (동적 선택) |
| `/footer-logo` | `footer_logo.{png,svg,jpg}` | ⚠️ proxy 유지 (동적 선택) |
| `/splash-mascot` | `splash-mascot.{png,svg}` | ⚠️ proxy 유지 |
| `/splash-loading` | `splash-loading.{png,jpg}`, `orange-splash-01.png` | ⚠️ proxy 유지 |
| `/static/html/*` | `html/` 폴더 전체 | ✅ alias (신규 경로) |

> 동적 선택 핸들러는 우선순위 파일을 확정한 뒤 alias 로 전환 가능 (2단계 작업).

## 적용 단계

### 1단계 — 검증 (병행 구동, 운영 영향 0)

```powershell
docker compose -f docker-compose.yml -f docker-compose.nginx.yml up -d nginx
```

- Nginx 가 `localhost:8889` 에 노출됨 (기존 `8888` 그대로 유지)
- 다음 항목 확인:
  - `curl http://localhost:8889/nginx-health` → `ok`
  - `curl -I http://localhost:8889/logo` → `X-Served-By: nginx-static-fastpath` 헤더
  - `curl -I http://localhost:8889/api/orange-info` → FastAPI 응답
  - SSE: `curl -N http://localhost:8889/stream?sid=test` → 즉시 첫 이벤트 수신
  - WebSocket: noVNC 접속 정상 동작

### 2단계 — 전환 (외부 8888 을 nginx 로 이전)

1. `docker-compose.yml` 의 `session-manager.ports` 에서 `"8888:8080"` 제거
2. `docker-compose.nginx.yml` 의 `nginx.ports` 를 `"8888:80"` 으로 변경
3. 재시작:
   ```powershell
   docker compose -f docker-compose.yml -f docker-compose.nginx.yml up -d
   ```

### 3단계 — 동적 핸들러 alias 화 (선택)

`/splash-image` 등 동적 선택 핸들러를 alias 로 전환하려면:
1. `html/orange-splash.png` 단일 파일로 통합 (또는 우선순위 1 파일을 표준화)
2. `nginx.conf` 의 location 블록 추가:
   ```nginx
   location = /splash-image {
       alias /srv/html/orange-splash.png;
       expires 30d;
       try_files $uri @fastapi;
   }
   ```

## 롤백

```powershell
docker compose stop nginx
docker compose rm -f nginx
# docker-compose.yml 의 session-manager.ports 복원 (필요 시)
docker compose up -d session-manager
```

## 예상 효과

- **정적 자산 응답 시간**: FastAPI Python 핸들러 (~10ms) → Nginx sendfile (~1ms)
- **FastAPI 이벤트 루프 부담**: 정적 트래픽 분리로 동적 API 처리 여유 확보
- **동시 접속 처리**: Nginx worker_connections 4096 × CPU 코어
- **캐시 효과**: 30일 immutable 헤더로 브라우저 측 재요청 최소화

## 주의사항

- **SSE 첫 이벤트 버퍼링 방지**: `proxy_buffering off` + `X-Accel-Buffering: no` 헤더 필수
  (main.py 의 `Content-Encoding: identity` 패턴과 별개 — nginx 단도 막아야 함)
- **WebSocket Upgrade 헤더**: noVNC/Xpra 경로는 반드시 `proxy_http_version 1.1` + `Upgrade/Connection` 헤더
- **client_max_body_size**: 200MB 설정. 더 큰 업로드 필요 시 nginx.conf 수정
- **upstream keepalive**: `keepalive 64` + 기본 location 의 `Connection ""` 헤더로 TCP 재사용

## 다음 단계 (보고서 Strategy 1: HTTP/2 + HTTPS)

Nginx 가 안정화되면 동일 구성에 HTTP/2 추가 가능:
```nginx
listen 443 ssl http2;
ssl_certificate     /etc/nginx/certs/orange3.crt;
ssl_certificate_key /etc/nginx/certs/orange3.key;
```

인증서 결정 필요:
- self-signed: 내부 테스트용, 브라우저 경고 발생
- Let's Encrypt: 외부 도메인 필요
- 사내 PKI: 내부 CA 발급

> HTTP/2 도입은 Nginx 정적 오프로드가 안정 운영된 뒤 별도 트랙으로 진행 권장.
