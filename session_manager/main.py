"""
Orange3 Session Manager — URL 기반 세션 격리
- GET /            → 새 UUID 생성 → 컨테이너 기동 → /?sid=<uuid> 리다이렉트
- GET /?sid=<uuid> → 컨테이너 running → WRAPPER_PAGE (noVNC iframe)
                    → 기동 중      → LOADING_PAGE (JS가 /ready 폴링)
                    → 미존재       → / 리다이렉트 (새 세션)
- GET /ready       → {"ready": true/false}
- GET /upload-poll → 위젯 업로드 신호 확인
- POST /upload     → 파일을 메모리에서 Docker API로 컨테이너 /tmp/ 에 직접 복사
"""
import asyncio
import io
import os
import re
import shlex
import glob
import shutil
import uuid
import time
import tarfile
import threading
import logging

import docker
from fastapi import FastAPI, Request, UploadFile, File, Form, WebSocket
from starlette.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response, StreamingResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# ── 반복 폴링 엔드포인트 접근 로그 억제 ────────────────────────────────────────
class _NoiseFilter(logging.Filter):
    # Phase 5 (2026-05-21): /upload-poll, /upload-poll-model, /dataset-poll 제거 — 핸들러 삭제됨.
    # /api/events 는 영구 연결이라 로그 1회만 찍히고 자체적으로 노이즈 적음.
    _SKIP = {"/ready", "/ready-sse", "/ping", "/screenshot"}

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return not any(ep in msg for ep in self._SKIP)


# ── Tier B6 (2026-05-21): 액세스 로그의 SID 값 마스킹 ────────────────────────
# 진단보고서 S2: ?sid=<uuid> 가 액세스 로그에 그대로 적재되면 로그 유출 시 세션 도용 가능.
# uvicorn.access 가 args 로 request line(`GET /path?sid=... HTTP/1.1`)을 넘기므로
# args 안의 sid 값만 마스킹 → 로그 가독성 유지하면서 SID 노출만 차단.
import re as _re_for_sid
_SID_MASK_RE = _re_for_sid.compile(r"sid=[0-9A-Za-z_\-]{6,}")

class _SidMaskFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            try:
                record.args = tuple(
                    _SID_MASK_RE.sub("sid=***", a) if isinstance(a, str) else a
                    for a in record.args
                )
            except Exception:
                pass
        return True


logging.getLogger("uvicorn.access").addFilter(_NoiseFilter())
logging.getLogger("uvicorn.access").addFilter(_SidMaskFilter())

app = FastAPI(title="Orange3 Session Manager")
app.add_middleware(GZipMiddleware, minimum_size=1000)


# ── Rate Limiting (2026-05-28 보안 패치) ────────────────────────────────────
# 후속 권장 항목 4 — brute-force / DoS 방어.
# - SID 우선 키 (NAT 환경에서 정상 사용자 차단 방지: 학교·회사 한 IP 다수 사용자)
# - SID 없으면 IP fallback
# - 메모리 백엔드 (단일 인스턴스 운영 가정 — 다중 인스턴스 시 Redis 전환)
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address as _get_remote_address

    def _rl_key(request):
        """SID 가 있으면 SID, 없으면 client IP. NAT 환경 한 IP 다수 사용자 보호."""
        try:
            sid = request.query_params.get("sid")
            if sid and sid != "new":
                return f"sid:{sid}"
        except Exception:
            pass
        return f"ip:{_get_remote_address(request)}"

    limiter = Limiter(key_func=_rl_key, default_limits=["1000/hour"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    _RL_ENABLED = True
    log.info("[rate-limit] slowapi 활성 — SID 우선 / IP fallback / 기본 1000/hour")
except ImportError:
    # slowapi 미설치 시 무력화 (개발 환경 호환). 데코레이터를 no-op 으로 대체.
    class _NoopLimiter:
        def limit(self, *_a, **_kw):
            def _decorator(fn): return fn
            return _decorator
    limiter = _NoopLimiter()
    _RL_ENABLED = False
    log.warning("[rate-limit] slowapi 미설치 — rate limit 비활성 (보안 약화)")


# ── 관리자 인증 (Firebase, 2026-05-30) ───────────────────────────────────────
# /admin/* 페이지는 셸만 서빙(클라이언트 로그인 오버레이가 가림). 실제 보호는
# /api/admin/* + DELETE /admin/sessions/{sid} 를 서버에서 Firebase ID 토큰 검증.
# 검증은 google-auth 의 verify_firebase_token 사용(projectId 만 필요 — 서비스
# 계정 키 불필요). FIREBASE_PROJECT_ID 미설정 시 인증 비활성(개발 모드) —
# env 로 점진 활성화 가능.
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "").strip()
# 페이지에 주입되는 웹 config(JSON, 공개 가능 — apiKey/authDomain/projectId 등)
FIREBASE_WEB_CONFIG = os.environ.get("FIREBASE_WEB_CONFIG", "").strip()
# 허용 관리자 이메일(쉼표 구분). 비우면 해당 Firebase 프로젝트의 모든 계정 허용.
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}
try:
    from google.oauth2 import id_token as _g_id_token
    from google.auth.transport import requests as _g_auth_requests
    _g_auth_request = _g_auth_requests.Request()
    _FIREBASE_VERIFY_OK = True
except Exception:
    _g_id_token = None
    _FIREBASE_VERIFY_OK = False

_ADMIN_AUTH_ENABLED = bool(FIREBASE_PROJECT_ID and _FIREBASE_VERIFY_OK)
if FIREBASE_PROJECT_ID and not _FIREBASE_VERIFY_OK:
    log.warning("[admin-auth] FIREBASE_PROJECT_ID 설정됐으나 google-auth 미설치 → 인증 비활성. "
                "requirements 에 google-auth 추가 필요")
elif _ADMIN_AUTH_ENABLED:
    log.info(f"[admin-auth] Firebase 검증 활성 (project={FIREBASE_PROJECT_ID}, "
             f"allowlist={len(ADMIN_EMAILS) or '제한없음'})")
else:
    log.warning("[admin-auth] FIREBASE_PROJECT_ID 미설정 → 관리자 인증 비활성(개발 모드)")


def _verify_admin_email(authz_header: str):
    """Authorization: Bearer <Firebase ID token> 검증 → 허용된 이메일 반환, 아니면 None.
       동기 함수 — 미들웨어에서 run_in_executor 로 호출(첫 호출만 공개키 fetch, 이후 캐시)."""
    if not authz_header or not authz_header.lower().startswith("bearer "):
        return None
    token = authz_header.split(" ", 1)[1].strip()
    try:
        claims = _g_id_token.verify_firebase_token(token, _g_auth_request, FIREBASE_PROJECT_ID)
    except Exception:
        return None
    if not claims:
        return None
    email = str(claims.get("email", "")).lower()
    if ADMIN_EMAILS and email not in ADMIN_EMAILS:
        return None
    return email or "(unknown)"


def _is_admin_protected(path: str, method: str) -> bool:
    """서버 검증이 필요한 경로 — /api/admin/* (모든 메서드) + DELETE /admin/sessions/{sid}.
       /admin/* 페이지 GET 은 셸만 서빙하므로 보호 안 함(클라 오버레이가 가림)."""
    if path.startswith("/api/admin"):
        return True
    if method == "DELETE" and path.startswith("/admin/sessions/"):
        return True
    return False


@app.middleware("http")
async def _admin_auth_guard(request: Request, call_next):
    if _ADMIN_AUTH_ENABLED and _is_admin_protected(request.url.path, request.method):
        authz = request.headers.get("authorization", "")
        loop = asyncio.get_event_loop()
        email = await loop.run_in_executor(None, _verify_admin_email, authz)
        if not email:
            return JSONResponse(
                {"ok": False, "error": "unauthorized — 관리자 로그인이 필요합니다"},
                status_code=401)
        request.state.admin_email = email
    return await call_next(request)


# ── 보안 헤더 ────────────────────────────────────────────────────────────────
# Tier A1 (2026-05-21): 진단보고서 S5/U5 대응
# - X-Content-Type-Options: MIME 스니핑 방지
# - X-Frame-Options: SAMEORIGIN — 외부에서 이 래퍼 페이지 iframe 금지
#   (래퍼는 자기 자신이 워밍풀 iframe을 임베드하는 쪽이므로 SAMEORIGIN으로 무방)
# - Referrer-Policy: SID URL 노출 기간 동안 Referer 헤더로 SID 유출 차단
# - Content-Security-Policy (2026-05-22): HTTP 에서도 안전하게 적용 가능한
#   하드닝 directive 만 강제. script-src/style-src 는 인라인 스크립트·이벤트
#   핸들러가 많아 'unsafe-inline' 없이는 앱이 깨지고, 'unsafe-inline' 을 쓰면
#   XSS 방어 실효가 거의 없어 제외. object-src/base-uri/frame-ancestors 는
#   앱 동작에 영향 없이 플러그인·base 태그 주입·클릭재킹을 차단.
# - HSTS 는 HTTP 에서 브라우저가 무시하므로 HTTPS 도입(S1) 후 추가.
@app.middleware("http")
async def _add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    return response


# ── Cache-Control 헤더 ───────────────────────────────────────────────────────
# Tier A2 (2026-05-21): 진단보고서 P4 대응
# - 정적 자산(.png/.svg/.css/.js/...): 1년 immutable
# - 폴링/스트림 응답(/screenshot, *-poll, /ready, /ping): no-store (캐시 절대 금지)
# - 그 외: no-cache (재검증 강제)
_STATIC_EXTS = (".png", ".svg", ".ico", ".jpg", ".jpeg", ".gif",
                ".woff", ".woff2", ".ttf", ".css", ".js", ".map")
_POLL_PATH_SEGMENTS = ("/screenshot", "-poll", "/ready", "/ping",
                       "/dataset-poll", "/pc_download/check")

@app.middleware("http")
async def _add_cache_headers(request, call_next):
    response = await call_next(request)
    if "Cache-Control" in response.headers:
        return response
    path = request.url.path
    if path.endswith(_STATIC_EXTS):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif any(seg in path for seg in _POLL_PATH_SEGMENTS):
        response.headers["Cache-Control"] = "no-store"
    else:
        response.headers["Cache-Control"] = "no-cache"
    return response


# ── 감사 로그: 변경 요청 일괄 기록 ────────────────────────────────────────────
# Tier B8 (2026-05-21): 진단보고서 O3 대응
# - 모든 POST/PUT/DELETE/PATCH 요청을 [AUDIT] 태그로 로그 출력
# - 기록: 메서드·경로·SID(short)·클라이언트 IP·상태 코드·소요 시간
# - 별도 핸들러로 분리하지 않고 stdout 동일 채널 사용 → docker logs 한 곳에서 추적
audit_log = logging.getLogger("orange3.audit")

@app.middleware("http")
async def _audit_log_middleware(request, call_next):
    if request.method in _MUTATING_METHODS:
        sid = request.query_params.get("sid", "?")
        client_ip = request.client.host if request.client else "?"
        start = time.time()
        response = await call_next(request)
        dur_ms = (time.time() - start) * 1000
        audit_log.info(
            f"[AUDIT] {request.method} {request.url.path} "
            f"sid={s8(sid)} ip={client_ip} status={response.status_code} "
            f"dur={dur_ms:.0f}ms"
        )
        return response
    return await call_next(request)


# ── CSRF: Origin/Referer 검증 ────────────────────────────────────────────────
# Tier B7 (2026-05-21): 진단보고서 S6 대응
# - POST/PUT/DELETE/PATCH 요청은 Origin 또는 Referer 헤더가 Host 와 일치해야 통과
# - 둘 다 없으면 통과(CLI/스크립트 — 다른 SID 검증 메커니즘에 의존)
# - 불일치 시 403. CSRF 시도를 로그에 기록해 침해 탐지 근거 확보
from urllib.parse import urlparse as _urlparse

_MUTATING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

@app.middleware("http")
async def _csrf_origin_check(request, call_next):
    if request.method in _MUTATING_METHODS:
        host = request.headers.get("host", "")
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        ok = True
        src = None
        if origin:
            try:
                ok = (_urlparse(origin).netloc == host)
                src = origin
            except Exception:
                ok = False
        elif referer:
            try:
                ok = (_urlparse(referer).netloc == host)
                src = referer
            except Exception:
                ok = False
        if not ok:
            log.warning(
                f"CSRF 거부: {request.method} {request.url.path} "
                f"host={host} src={src}"
            )
            return JSONResponse(
                {"error": "CSRF: Origin/Referer 불일치"},
                status_code=403,
            )
    return await call_next(request)


# ── SID-IP 바인딩 (탐지 전용) ────────────────────────────────────────────────
# Tier B6 (2026-05-21): 진단보고서 S2/S3 대응 (쿠키화 대신 채택)
# - 세션이 처음 사용된 IP를 sessions[sid]["client_ip"] 에 기록
# - 이후 다른 IP에서 같은 SID 사용 시 WARN 로그 (거부 안 함 — NAT/VPN 정당 사유 가능)
# - 침해 의심 시 로그로 추적·차단 정책 결정 근거 제공
@app.middleware("http")
async def _sid_ip_binding(request, call_next):
    qs_sid = request.query_params.get("sid")
    if qs_sid and qs_sid != "new":
        client_ip = request.client.host if request.client else None
        if client_ip:
            with _lock:
                sess = sessions.get(qs_sid)
                if sess is not None:
                    bound = sess.get("client_ip")
                    if bound is None:
                        sess["client_ip"] = client_ip
                        log.info(f"[{s8(qs_sid)}] SID-IP 바인딩: {client_ip}")
                    elif bound != client_ip:
                        log.warning(
                            f"[{s8(qs_sid)}] SID 다른 IP에서 사용 "
                            f"(bound={bound} now={client_ip})"
                        )
    return await call_next(request)


# ── Docker 클라이언트 ──
try:
    client = docker.from_env()
    client.ping()
    log.info("Docker 연결 성공")
except Exception as e:
    log.error(f"Docker 연결 실패: {e}")
    client = None

# ── 환경 변수 ──
ORANGE3_IMAGE      = os.environ.get("ORANGE3_IMAGE", "orange3-gui")
PORT_START         = int(os.environ.get("PORT_START", "8090"))
PORT_END           = int(os.environ.get("PORT_END", "8199"))
SESSION_TIMEOUT    = int(os.environ.get("SESSION_TIMEOUT", "1800"))
# 워밍풀 컨테이너 최대 생존 시간 (초) — 초과 시 자동 교체 (디스크 누적 방지)
WARM_MAX_AGE       = int(os.environ.get("WARM_MAX_AGE", "1800"))
# ── #2 컨테이너 메모리 상한 (2026-05-31) ──────────────────────────────────────
# GUI 컨테이너 1개당 폭주 세션 상한선. 유휴 baseline(~775MB)은 그대로지만
# 대용량 데이터 작업 시 호스트 RAM 과점유를 방지. 모든 spawn 경로(warm/hot/xpra)
# 공통. 큰 데이터셋 분석 중 OOM 이 잦으면 "2560m"~"3g" 로 상향.
CONTAINER_MEM_LIMIT = os.environ.get("CONTAINER_MEM_LIMIT", "2g")
COOKIE_NAME        = "orange3_sid"

HOST_SESSIONS_PATH      = os.environ.get("HOST_SESSIONS_PATH",      "/sessions_host")
CONTAINER_SESSIONS_PATH = os.environ.get("CONTAINER_SESSIONS_PATH", "/sessions")
HOST_DATA_PATH          = os.environ.get("HOST_DATA_PATH",          "/data_host")

WIDGETS_HOST_PATH    = os.environ.get("WIDGETS_HOST_PATH",    "")
WIDGETS_LOCAL_PATH   = os.environ.get("WIDGETS_LOCAL_PATH",   "/widgets_override")
ORANGE3_WIDGETS_PATH = os.environ.get("ORANGE3_WIDGETS_PATH",
                                      "/usr/local/lib/python3.10/dist-packages/Orange/widgets")

# 사용자 업로드 .ows 워크플로우 (초등/중등 등) — orange3-gui 컨테이너에 ro 마운트
UPLOAD_OWS_HOST_PATH = os.environ.get("UPLOAD_OWS_HOST_PATH", "")

# 공유 썸네일 디렉토리 (2026-05-29) — 모든 세션이 같은 SVG 캐시 공유.
# 호스트 경로: ${HOST_BASE}/thumbs_shared
# 컨테이너 마운트: /shared_thumbs (rw — launcher 가 부족한 파일만 추가 생성)
# session-manager 자체에도 마운트되어 호스트 디스크 직접 read 가능.
SHARED_THUMBS_HOST_PATH = os.environ.get("SHARED_THUMBS_HOST_PATH", "")
SHARED_THUMBS_LOCAL_PATH = os.environ.get("SHARED_THUMBS_LOCAL_PATH", "/shared_thumbs")

MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_MB", "200")) * 1024 * 1024
# 다중 파일 업로드 개수 상한 — DoS 방지 (수만 개 작은 파일로 inode/메모리 고갈 차단)
MAX_FILES_PER_UPLOAD = int(os.environ.get("MAX_FILES_PER_UPLOAD", "500"))


CONTRIB_PREFIX_MAP = {
    "imageanalytics": "/usr/local/lib/python3.10/dist-packages/orangecontrib/imageanalytics/widgets",
    "timeseries": "/usr/local/lib/python3.10/dist-packages/orangecontrib/timeseries/widgets",
    "text": "/usr/local/lib/python3.10/dist-packages/orangecontrib/text/widgets",
    "geo": "/usr/local/lib/python3.10/dist-packages/orangecontrib/geo/widgets",
    "network": "/usr/local/lib/python3.10/dist-packages/orangecontrib/network/widgets",
    "single_cell": "/usr/local/lib/python3.10/dist-packages/orangecontrib/single_cell/widgets",
    "spectroscopy": "/usr/local/lib/python3.10/dist-packages/orangecontrib/spectroscopy/widgets",
    "bioinformatics": "/usr/local/lib/python3.10/dist-packages/orangecontrib/bioinformatics/widgets",
    "survival_analysis": "/usr/local/lib/python3.10/dist-packages/orangecontrib/survival_analysis/widgets",
    "fairness": "/usr/local/lib/python3.10/dist-packages/orangecontrib/fairness/widgets",
    "explain": "/usr/local/lib/python3.10/dist-packages/orangecontrib/explain/widgets",
    "educational": "/usr/local/lib/python3.10/dist-packages/orangecontrib/educational/widgets",
    "associate": "/usr/local/lib/python3.10/dist-packages/orangecontrib/associate/widgets",
    "_textable": "/usr/local/lib/python3.10/dist-packages/_textable/widgets",
    "pumice": "/usr/local/lib/python3.10/dist-packages/orangecontrib/pumice/widgets",
    "worldhappiness": "/usr/local/lib/python3.10/dist-packages/orangecontrib/worldhappiness/widgets",
    "snom": "/usr/local/lib/python3.10/dist-packages/orangecontrib/snom/widgets",
}

# 위젯 오버라이드 볼륨 매핑 캐시 — 첫 호출에서 빌드, 이후 재사용.
# 매 워밍 컨테이너 생성 시 50+ 파일 glob 스캔/로깅이 메인 이벤트 루프를 직렬화하던
# 문제를 해결 (GET / 응답 11ms → 15s 회귀 원인). 디렉토리 변경 시 세션매니저 재시작 필요.
_widget_volumes_cache: "dict | None" = None


def build_widget_override_volumes() -> dict:
    global _widget_volumes_cache
    if _widget_volumes_cache is not None:
        return _widget_volumes_cache
    volumes: dict = {}
    if not WIDGETS_HOST_PATH:
        _widget_volumes_cache = volumes
        return volumes
    count = 0
    # .py + .svg + .png 모두 마운트 — upstream 패키지에 누락된 아이콘 보충 (2026-05-28)
    _override_patterns = ("**/*.py", "**/*.svg", "**/*.png")
    _override_files = []
    for pat in _override_patterns:
        _override_files.extend(glob.glob(os.path.join(WIDGETS_LOCAL_PATH, pat), recursive=True))
    for local_file in _override_files:
        if not os.path.isfile(local_file):
            continue
        rel = os.path.relpath(local_file, WIDGETS_LOCAL_PATH).replace("\\", "/")
        host_file = WIDGETS_HOST_PATH.rstrip("/") + "/" + rel
        # 첫 번째 경로 세그먼트가 CONTRIB_PREFIX_MAP에 있으면 별도 컨테이너 경로 사용
        top = rel.split("/")[0]
        if top in CONTRIB_PREFIX_MAP:
            sub = "/".join(rel.split("/")[1:])
            container_file = CONTRIB_PREFIX_MAP[top].rstrip("/") + "/" + sub
        else:
            container_file = ORANGE3_WIDGETS_PATH.rstrip("/") + "/" + rel
        volumes[host_file] = {"bind": container_file, "mode": "ro"}
        count += 1
    log.info(f"[widget_override] 위젯 오버라이드 볼륨 매핑 캐시 빌드: {count}개 파일")
    _widget_volumes_cache = volumes
    return volumes


def build_upload_ows_volume() -> dict:
    """사용자 업로드 .ows 디렉터리 마운트 (UPLOAD_OWS_HOST_PATH 가 설정된 경우만)"""
    if not UPLOAD_OWS_HOST_PATH:
        return {}
    return {UPLOAD_OWS_HOST_PATH: {"bind": "/upload_ows", "mode": "ro"}}


def build_shared_thumbs_volume() -> dict:
    """공유 썸네일 디렉토리 마운트 (2026-05-29).
    모든 orange3-gui 컨테이너가 같은 SVG 캐시를 rw 공유 →
    launcher 가 처음 부팅 시 1회 생성, 이후 컨테이너는 skip."""
    if not SHARED_THUMBS_HOST_PATH:
        return {}
    return {SHARED_THUMBS_HOST_PATH: {
        "bind": SHARED_THUMBS_LOCAL_PATH, "mode": "rw"}}


# 호스트의 orange3_launcher.py 경로 — 이미지 내 /app/orange3_launcher.py 를 덮어쓰기
LAUNCHER_HOST_PATH = os.environ.get("LAUNCHER_HOST_PATH", "")


def build_launcher_volume() -> dict:
    """orange3_launcher.py 호스트 핫리로드 마운트 (LAUNCHER_HOST_PATH 가 설정된 경우만)"""
    if not LAUNCHER_HOST_PATH:
        return {}
    return {LAUNCHER_HOST_PATH: {"bind": "/app/orange3_launcher.py", "mode": "ro"}}


def _validate_host_mounts() -> None:
    """기동 시 호스트 바인드(위젯 오버라이드 + QSS 런처)가 실제로 유효한지 검증.

    GCP 등으로 이관 후 HOST_BASE 가 잘못되면(예: 로컬 .env 의 /e/... 가 그대로 남음)
    Docker 가 존재하지 않는 bind 소스를 '빈 디렉터리'로 자동 생성해, 위젯 스타일이
    아무 에러 없이 조용히 빠진다. 이를 시작 단계에서 크게 잡아낸다.

    STRICT_WIDGET_OVERRIDE=1 이면 문제 발견 시 기동을 중단(raise)한다.
    """
    strict = os.environ.get("STRICT_WIDGET_OVERRIDE", "0").lower() in ("1", "true", "yes")
    problems: list = []

    # 1) 정적 검사 — env 미설정
    if not WIDGETS_HOST_PATH:
        problems.append("WIDGETS_HOST_PATH 미설정 — 위젯 오버라이드(스타일) 마운트 비활성")
    if not LAUNCHER_HOST_PATH:
        problems.append("LAUNCHER_HOST_PATH 미설정 — QSS 스타일 런처 마운트 비활성")

    # 2) 세션매니저 자체 마운트(/widgets_override)에 파일이 있는지 (compose 마운트 점검)
    local_n = 0
    try:
        for pat in ("**/*.py", "**/*.svg", "**/*.png"):
            local_n += len(glob.glob(os.path.join(WIDGETS_LOCAL_PATH, pat), recursive=True))
    except Exception:
        pass
    if local_n == 0:
        problems.append(f"{WIDGETS_LOCAL_PATH} 가 비어있음 — './widgets_override' compose 마운트 확인 필요")

    # 3) 능동 프로브 — 실제 호스트 바인드가 컨테이너에서 비어있지 않은지(가장 확실한 검증)
    probe_size = None
    if client is not None and LAUNCHER_HOST_PATH \
            and os.environ.get("WIDGET_MOUNT_PROBE", "1").lower() not in ("0", "false", "no"):
        try:
            out = client.containers.run(
                ORANGE3_IMAGE,
                command=["sh", "-c", "cat /probe_launcher 2>/dev/null | wc -c"],
                volumes={LAUNCHER_HOST_PATH: {"bind": "/probe_launcher", "mode": "ro"}},
                network_mode="none", remove=True, stdout=True, stderr=False,
            )
            probe_size = int((out or b"0").decode(errors="ignore").strip() or "0")
        except Exception as e:  # 프로브 실패는 치명적이지 않게 — 경고만
            log.warning(f"[mount-check] 프로브 컨테이너 실행 실패(능동검증 건너뜀): {e}")
        if probe_size is not None and probe_size < 100:
            problems.append(
                f"호스트 바인드 검증 실패 — '{LAUNCHER_HOST_PATH}' 가 컨테이너에서 비어있음({probe_size}B). "
                f"HOST_BASE 가 이 호스트의 실제 repo 절대경로가 아닙니다."
            )

    if problems:
        win_drive = re.match(r"^/[A-Za-z]/", WIDGETS_HOST_PATH or "")
        msg = "위젯 스타일/오버라이드 마운트 문제 감지:\n  - " + "\n  - ".join(problems)
        if win_drive:
            msg += (f"\n  ※ WIDGETS_HOST_PATH='{WIDGETS_HOST_PATH}' 가 Windows 드라이브식 경로입니다 — "
                    f"리눅스(GCP) 호스트면 repo 절대경로(예: /opt/orange3web)로 HOST_BASE 를 바꾸세요.")
        msg += ("\n  → 조치: .env 의 HOST_BASE 를 이 호스트의 repo 절대경로로 설정 후 "
                "`docker compose down && docker compose up -d`. (자세한 내용: gcloud.md)")
        log.error("[mount-check] " + msg)
        if strict:
            raise RuntimeError("위젯 오버라이드 마운트 검증 실패 — STRICT_WIDGET_OVERRIDE=1 로 기동 중단")
    else:
        log.info(f"[mount-check] 위젯 오버라이드/런처 호스트 바인드 정상 "
                 f"(launcher {probe_size}B, override local {local_n}개)")


# 세션 저장소: {sid: {"container_id", "port", "last_seen"}}
sessions: dict = {}
_lock = threading.Lock()
_START_TIME = time.time()   # 프로세스 기동 시각 — /api/metrics uptime 계산용 (④ 2026-05-22)

# ── 예열(Pre-warm) 풀 ──
_warm_pool: list = []          # 배정 대기 중인 sid 목록
_warm_lock = threading.Lock()
WARM_POOL_SIZE = int(os.environ.get("WARM_POOL_SIZE", "4"))
# ── ② 워밍풀 메모리 튜닝 (2026-05-22) ───────────────────────────────────────
# 시간대별 목표 풀 크기: 피크 시간엔 WARM_POOL_SIZE, 유휴 시간엔 WARM_POOL_SIZE_IDLE.
# 워밍 컨테이너 1개당 ~467MB RAM 상시 점유 → 유휴 시간대 축소로 호스트 RAM 절감.
WARM_POOL_SIZE_IDLE = int(os.environ.get("WARM_POOL_SIZE_IDLE", str(WARM_POOL_SIZE)))
# env 로 정의된 값은 admin 페이지에서 풀 크기를 조정할 때의 상한(MAX) 으로 사용.
# 컨테이너 재시작 후에는 env 값 = 상한 으로 다시 셋팅됨. 실제 사용값은
# WARM_POOL_SIZE / WARM_POOL_SIZE_IDLE 로 admin 이 동적으로 줄일 수 있음.
WARM_POOL_SIZE_MAX = WARM_POOL_SIZE
_WARM_PEAK_HOURS = os.environ.get("WARM_PEAK_HOURS", "8-20")

def _effective_pool_size() -> int:
    """현재 시각(KST=UTC+9) 기준 목표 워밍풀 크기.
    WARM_PEAK_HOURS(예 "8-20") 안이면 WARM_POOL_SIZE, 아니면 WARM_POOL_SIZE_IDLE.
    컨테이너 TZ 와 무관하게 일관되도록 UTC+9 로 직접 계산."""
    try:
        start_h, end_h = (int(x) for x in _WARM_PEAK_HOURS.split("-"))
        hour = (time.gmtime().tm_hour + 9) % 24
        is_peak = (start_h <= hour < end_h) if start_h <= end_h \
            else (hour >= start_h or hour < end_h)
        return WARM_POOL_SIZE if is_peak else WARM_POOL_SIZE_IDLE
    except Exception:
        return WARM_POOL_SIZE

# 동시에 기동 가능한 워밍 컨테이너 수 — Orange3 startup CPU spike 분산용.
# 풀 크기와 무관하게 한 번에 N개씩 그룹으로 부팅 → 20-CPU 호스트도 안정.
WARM_BOOT_CONCURRENCY = int(os.environ.get("WARM_BOOT_CONCURRENCY", "6"))
_warm_boot_sem: "asyncio.Semaphore | None" = None  # 첫 startup_event에서 생성
# 생성 중(in-flight) 컨테이너 카운트 — _replenish_pool 중복 호출 방지.
# 풀에 아직 등록 안 됐지만 곧 들어올 컨테이너를 needed 계산에서 차감.
_warm_inflight: int = 0
# 좀비 컨테이너 정리 완료 신호 (2026-05-22).
# startup 의 좀비 정리(최대 수십 초)와 워밍풀 보충이 동시에 돌면 정리 중인 좀비가
# 아직 점유한 포트를 새 컨테이너가 시도해 "port is already allocated" 충돌이 난다.
# 정리가 끝날 때까지 _replenish_pool / cleanup_loop 의 보충을 보류시킨다.
_zombies_cleared = threading.Event()

# ── Xpra 전환 실험 (Phase 2, 2026-05-23) ─────────────────────────────────────
# 운영 noVNC 워밍풀과 완전 별개. /xpra 라우트가 호출될 때마다 신규 컨테이너 기동.
XPRA_IMAGE       = os.environ.get("XPRA_IMAGE", "orange3-xpra:poc")
XPRA_PORT_START  = int(os.environ.get("XPRA_PORT_START", "13901"))
XPRA_PORT_END    = int(os.environ.get("XPRA_PORT_END",   "13950"))
xpra_sessions: dict = {}            # {sid: {"container_id", "port", "last_seen"}}
_xpra_lock = threading.Lock()
# ── Xpra 워밍풀 (Phase 5 준비, 2026-05-23) ───────────────────────────────────
# /xpra 호출 시 즉시 pop → 부팅 10s 대기 우회. 운영 noVNC 워밍풀과 별개로 운영.
# 기본 0 (비활성) → 검증 후 .env 또는 docker-compose 에서 2~3 권장.
XPRA_WARM_POOL_SIZE = int(os.environ.get("XPRA_WARM_POOL_SIZE", "0"))
# env 로 정의된 값은 admin 페이지에서 조정할 때의 상한(MAX).
XPRA_WARM_POOL_SIZE_MAX = XPRA_WARM_POOL_SIZE
# ── #1 Xpra 유휴 시간대 축소 (2026-05-31) ────────────────────────────────────
# noVNC 워밍풀과 동일 패턴: 피크 시간(WARM_PEAK_HOURS)엔 XPRA_WARM_POOL_SIZE,
# 그 외 유휴 시간엔 XPRA_WARM_POOL_SIZE_IDLE 로 축소해 상시 RAM 절감.
# 기본값을 XPRA_WARM_POOL_SIZE 로 두면(미설정 시) 기존 동작과 동일(축소 없음).
XPRA_WARM_POOL_SIZE_IDLE = int(os.environ.get("XPRA_WARM_POOL_SIZE_IDLE", str(XPRA_WARM_POOL_SIZE)))

def _xpra_effective_pool_size() -> int:
    """현재 시각(KST=UTC+9) 기준 목표 Xpra 워밍풀 크기.
    WARM_PEAK_HOURS 안이면 XPRA_WARM_POOL_SIZE, 아니면 XPRA_WARM_POOL_SIZE_IDLE."""
    try:
        start_h, end_h = (int(x) for x in _WARM_PEAK_HOURS.split("-"))
        hour = (time.gmtime().tm_hour + 9) % 24
        is_peak = (start_h <= hour < end_h) if start_h <= end_h \
            else (hour >= start_h or hour < end_h)
        return XPRA_WARM_POOL_SIZE if is_peak else XPRA_WARM_POOL_SIZE_IDLE
    except Exception:
        return XPRA_WARM_POOL_SIZE
_xpra_warm_pool: list = []          # 사용자 미배정 워밍 sid 목록 (xpra_sessions 와 sessions[] 양쪽에 등록됨)
_xpra_warm_inflight = 0             # 현재 spawn 중인 워밍 컨테이너 수

_xpra_reserved_ports: set = set()   # spawn 중 race 차단 (xpra_sessions 등록 전)


def _find_free_xpra_port():
    """동시 spawn race 차단 — used 검사 시 reserved 도 포함, 반환 직전 reserve."""
    with _xpra_lock:
        used = {v["port"] for v in xpra_sessions.values()} | _xpra_reserved_ports
        for p in range(XPRA_PORT_START, XPRA_PORT_END + 1):
            if p not in used:
                _xpra_reserved_ports.add(p)
                return p
    return None


def _release_xpra_port(port: int):
    with _xpra_lock:
        _xpra_reserved_ports.discard(port)

def _get_target_network():
    """session-manager 컨테이너가 붙어 있는 docker network 이름 반환.
    Phase 3C-1 프록시가 같은 네트워크 안의 xpra 컨테이너를 이름으로 호출하기 위함."""
    if client is None:
        return None
    try:
        sm = client.containers.list(filters={"name": "orange3-session-manager"}, limit=1)
        if not sm:
            return None
        networks = sm[0].attrs.get("NetworkSettings", {}).get("Networks", {})
        return next(iter(networks.keys()), None)
    except Exception as e:
        log.warning(f"[xpra] 네트워크 자동 탐지 실패: {e}")
        return None


def _spawn_xpra_container(sid: str):
    """orange3-xpra 이미지로 새 컨테이너 1개 기동.
    Phase 3C-1: session-manager 와 같은 docker network 에 붙여서 프록시가
    container_name 으로 접근 가능하게 함. 호스트 포트도 매핑 유지(직접 접속용).
    Phase 3D-3 fix v5 (2026-05-23): session 디렉토리를 컨테이너의 /config 로
    bind-mount — backend 가 `/sessions/{sid}/.widget_catalog_query` 등 signal
    파일을 쓰면 launcher 가 `/config/.widget_catalog_query` 에서 그대로 읽음.
    운영 워밍풀과 동일 마운트 패턴 (host_session_dir → /config).
    반환: (container_id, host_port, container_name)"""
    if client is None:
        return None
    port = _find_free_xpra_port()
    if port is None:
        log.warning("[xpra] 가용 포트 없음")
        return None
    # session 디렉토리 사전 생성 (운영 _spawn_warm 패턴)
    container_session_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)
    os.makedirs(container_session_dir, exist_ok=True)
    host_session_dir = os.path.join(HOST_SESSIONS_PATH, sid)
    try:
        name = f"xpra-{uuid.uuid4().hex[:8]}"
        # admin_settings.splashes.loading 을 env var 로 전달 → launcher 가 읽어
        # Orange3 native splash 표시 여부 결정 (2026-05-25).
        try:
            _sp = _admin_load_settings().get("splashes", {}) or {}
            _splash_loading_env = "1" if _sp.get("loading", True) else "0"
        except Exception:
            _splash_loading_env = "1"
        run_kwargs = {
            "image": XPRA_IMAGE,
            "detach": True,
            "ports": {"10000/tcp": port},
            "labels": {"orange3.xpra": "true", "orange3.session": sid},
            "name": name,
            "mem_limit": CONTAINER_MEM_LIMIT,
            "memswap_limit": CONTAINER_MEM_LIMIT,
            "environment": {
                "ORANGE3_SPLASH_LOADING": _splash_loading_env,
            },
            "volumes": {
                host_session_dir: {"bind": "/config",  "mode": "rw"},
                HOST_DATA_PATH:   {"bind": "/data",    "mode": "ro"},
                **build_widget_override_volumes(),
                **build_upload_ows_volume(),
                **build_shared_thumbs_volume(),
                **build_launcher_volume(),
            },
        }
        net = _get_target_network()
        if net:
            run_kwargs["network"] = net
        container = client.containers.run(**run_kwargs)
        log.info(f"[xpra] 컨테이너 생성 {container.short_id} name={name} "
                 f"port={port} network={net or 'default'}")
        # Phase 3C-1 fix (2026-05-23): 첫 프록시 호출이 "Server disconnected" 502 로
        # 떨어지는 race 차단 — Xpra HTML5 서버가 실제 HTTP 200 을 돌려줄 때까지 대기.
        # session-manager 는 컨테이너 안에서 도므로 127.0.0.1:호스트포트 가 아니라
        # 같은 docker network 의 container_name:10000 으로 접근해야 한다.
        # 최대 15초(0.5s × 30회) 폴링. 타임아웃이어도 컨테이너는 유지 — 프록시의
        # TransportError retry 가 안전망으로 잡음.
        probe_host = f"{name}:10000" if net else f"127.0.0.1:{port}"
        try:
            import urllib.request as _ur
            for _ in range(30):
                try:
                    with _ur.urlopen(f"http://{probe_host}/", timeout=0.5) as r:
                        if r.status == 200:
                            log.info(f"[xpra] ready {name} (HTTP 200 via {probe_host})")
                            break
                except Exception:
                    pass
                time.sleep(0.5)
            else:
                log.warning(f"[xpra] {name} readiness 타임아웃(15s, probe={probe_host}) — 그래도 컨테이너 유지")
        except Exception as e:
            log.warning(f"[xpra] readiness probe 오류 {name}: {e}")
        return container.id, port, name
    except Exception as e:
        log.warning(f"[xpra] 컨테이너 생성 실패 port={port}: {e}")
        # Hyper-V 등 외부 포트 충돌 시 같은 포트 재시도 방지 — block_port 로 일시 차단.
        _msg = str(e).lower()
        if ("ports are not available" in _msg or "bind: only one usage" in _msg
                or "address already in use" in _msg):
            block_port(port)
        _release_xpra_port(port)
        return None


def _xpra_register(sid: str, cid: str, port: int, cname: str, warm: bool) -> None:
    """워밍·핫 spawn 결과를 양쪽 dict (xpra_sessions, sessions[]) 에 등록.
    등록 후 port reservation 해제 (xpra_sessions 가 권위 — 중복 방지)."""
    now = time.time()
    with _xpra_lock:
        xpra_sessions[sid] = {
            "container_id": cid, "port": port,
            "container_name": cname, "last_seen": now,
        }
        _xpra_reserved_ports.discard(port)
    with _lock:
        sessions[sid] = {
            "container_id": cid, "port": port,
            "container_name": cname, "last_seen": now,
            "warm": warm, "engine": "xpra", "display": ":100",
        }


async def _xpra_spawn_warm() -> bool:
    """워밍풀에 새 Xpra 컨테이너 1개 추가. spawn 자체는 동기지만 이벤트 루프
    block 방지를 위해 run_in_executor."""
    global _xpra_warm_inflight
    sid = uuid.uuid4().hex[:16]
    with _xpra_lock:
        _xpra_warm_inflight += 1
    try:
        res = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _spawn_xpra_container(sid))
        if not res:
            return False
        cid, port, cname = res
        _xpra_register(sid, cid, port, cname, warm=True)
        with _xpra_lock:
            _xpra_warm_pool.append(sid)
        log.info(f"[xpra-warm] pool +1 sid={sid[:8]} (size={len(_xpra_warm_pool)}/{XPRA_WARM_POOL_SIZE})")
        return True
    finally:
        with _xpra_lock:
            _xpra_warm_inflight -= 1


async def _xpra_replenish_pool() -> None:
    """워밍풀이 target 미만이면 부족분 만큼 spawn (포트 race 회피 위해 순차).
    target 은 시간대별 _xpra_effective_pool_size() (#1 2026-05-31)."""
    target = _xpra_effective_pool_size()
    if target <= 0:
        return
    with _xpra_lock:
        needed = target - len(_xpra_warm_pool) - _xpra_warm_inflight
    if needed <= 0:
        return
    for _ in range(needed):
        ok = await _xpra_spawn_warm()
        if not ok:
            # spawn 실패 (포트 충돌 등) — 1초 대기 후 다음 시도
            await asyncio.sleep(1)


def _xpra_pop_warm():
    """워밍풀에서 sid 1개 즉시 pop (없으면 None). 사용자 세션으로 격상."""
    with _xpra_lock:
        if not _xpra_warm_pool:
            return None
        sid = _xpra_warm_pool.pop(0)
    with _lock:
        if sid in sessions:
            sessions[sid]["warm"] = False
            sessions[sid]["last_seen"] = time.time()
    log.info(f"[xpra-warm] pool -1 sid={sid[:8]} (남은 size={len(_xpra_warm_pool)})")
    return sid


def _xpra_remove_warm(sid: str) -> None:
    """워밍풀의 Xpra 컨테이너 1개를 정지·제거 (#1 유휴 축소용).
    _xpra_warm_pool / xpra_sessions / sessions 세 곳 모두 정리."""
    with _xpra_lock:
        if sid in _xpra_warm_pool:
            _xpra_warm_pool.remove(sid)
        info = xpra_sessions.pop(sid, None)
    with _lock:
        sessions.pop(sid, None)
    if not info:
        return
    try:
        c = client.containers.get(info["container_id"])
        c.stop(timeout=3)
        c.remove()
    except Exception as e:
        log.warning(f"[xpra-warm] 축소 제거 오류 sid={sid[:8]}: {e}")
    finally:
        try:
            _release_xpra_port(info.get("port"))
        except Exception:
            pass


def used_ports() -> set:
    with _lock:
        return {s["port"] for s in sessions.values()}


# 할당됐으나 아직 sessions에 등록되지 않은 포트 (race condition 방지)
_reserved_ports: set = set()
# Windows Hyper-V 동적 예약 등 외부 요인으로 Docker bind 실패한 포트 — 임시 회피 (TTL 600s).
# {port: failed_at_timestamp}
_blocked_ports: dict[int, float] = {}
_BLOCKED_PORT_TTL = 600.0
_port_lock = threading.Lock()


def _cleanup_blocked_ports():
    """만료된 차단 포트 정리 (호출 전 _port_lock 보유 필요)."""
    now = time.time()
    expired = [p for p, ts in _blocked_ports.items() if now - ts > _BLOCKED_PORT_TTL]
    for p in expired:
        _blocked_ports.pop(p, None)


def allocate_port() -> int:
    """포트를 원자적으로 예약. Hyper-V 차단 포트는 자동 회피 (2026-05-28)."""
    with _port_lock:
        _cleanup_blocked_ports()
        occupied = used_ports() | _reserved_ports | _blocked_ports.keys()
        for port in range(PORT_START, PORT_END + 1):
            if port not in occupied:
                _reserved_ports.add(port)
                return port
        raise RuntimeError(f"포트 부족 ({PORT_START}-{PORT_END} 모두 사용 중)")


def block_port(port: int):
    """Docker bind 실패한 포트를 일시 차단 — TTL 동안 allocate_port 가 회피."""
    with _port_lock:
        _blocked_ports[port] = time.time()
        _reserved_ports.discard(port)
        log.warning(f"[port] {port} 차단 ({_BLOCKED_PORT_TTL:.0f}s) — Hyper-V 등 외부 점유 추정")


def release_port(port: int):
    """컨테이너 생성 실패 시 예약 해제."""
    with _port_lock:
        _reserved_ports.discard(port)


def confirm_port(port: int):
    """sessions에 등록 완료 후 예약 셋에서 제거 (used_ports()가 이미 추적)."""
    with _port_lock:
        _reserved_ports.discard(port)


# ── Docker 컨테이너 상태 캐시 (TTL 8초) ──────────────────────────────────────
_container_status_cache: dict = {}  # {container_id: (is_running, timestamp)}
_CONTAINER_CACHE_TTL = 8.0


def container_running(container_id: str) -> bool:
    """컨테이너 running 여부 확인. 결과를 TTL 내 캐싱해 Docker API 호출 최소화."""
    now = time.time()
    cached = _container_status_cache.get(container_id)
    if cached and now - cached[1] < _CONTAINER_CACHE_TTL:
        return cached[0]
    if client is None:
        _container_status_cache[container_id] = (False, now)
        return False
    try:
        result = client.containers.get(container_id).status == "running"
    except Exception:
        result = False
    _container_status_cache[container_id] = (result, now)
    return result


async def container_running_async(container_id: str) -> bool:
    """container_running()의 non-blocking 래퍼 — 이벤트 루프 블로킹 방지."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, container_running, container_id)


async def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """컨테이너 포트(5800)가 실제로 응답하는지 확인 (non-blocking)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


def s8(sid: str | None) -> str:
    """sid 앞 8자리 — None 안전 처리."""
    if not sid:
        return "?"
    result = ""
    for i in range(min(8, len(sid))):
        result += sid[i]
    return result


def remove_session(sid: str):
    with _lock:
        info = sessions.pop(sid, None)
    if not info or client is None:
        return
    try:
        c = client.containers.get(str(info["container_id"]))
        c.stop(timeout=5)
        c.remove()
        log.info(f"[{s8(sid)}] 컨테이너 제거 (포트 {info['port']})")
    except Exception as e:
        log.warning(f"[{s8(sid)}] 컨테이너 제거 오류: {e}")
    session_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)
    if os.path.isdir(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)
        log.info(f"[{s8(sid)}] 세션 디렉터리 삭제: {session_dir}")


# 메인 asyncio 이벤트 루프 핸들 (cleanup 스레드 → async 보충 함수 호출용)
_main_loop: "asyncio.AbstractEventLoop | None" = None


def _autosave_workflow(sid: str, info: dict) -> None:
    """세션 만료 직전 워크플로우를 _autosave/ 에 저장 (P3-O2).

    cleanup_loop(동기 스레드)에서 호출 — remove_session 으로 컨테이너가
    제거되기 직전에 현재 워크플로우 상태를 영구 보존한다.
    저장 위치는 세션 디렉터리 밖이라 remove_session 의 rmtree 영향을 받지 않는다.
    """
    if client is None:
        return
    import io as _io
    import tarfile as _tarfile
    try:
        container = client.containers.get(str(info["container_id"]))
        # launcher 에 저장 신호 (save_workflow_route 와 동일 프로토콜)
        container.exec_run(["sh", "-c",
            "rm -f /config/.save_done && printf '1' > /config/.save_workflow"])
        done_content = None
        for _ in range(50):           # 최대 10초 대기
            time.sleep(0.2)
            r = container.exec_run(["cat", "/config/.save_done"])
            if r.exit_code == 0:
                done_content = r.output.decode().strip()
                break
        if not done_content or done_content.startswith("ERROR:"):
            log.warning(f"[{s8(sid)}] 만료 자동저장 건너뜀: {done_content or '시간 초과'}")
            return
        parts = done_content.split("|", 1)
        save_path = parts[0]
        title = parts[1] if len(parts) > 1 else "workflow"
        # 컨테이너에서 .ows 추출
        raw, _ = container.get_archive(save_path)
        buf = _io.BytesIO()
        for chunk in raw:
            buf.write(chunk)
        buf.seek(0)
        with _tarfile.open(fileobj=buf) as tar:
            member = tar.getmembers()[0]
            extracted = tar.extractfile(member)
            file_content = extracted.read() if extracted else b""
        if not file_content:
            log.warning(f"[{s8(sid)}] 만료 자동저장 건너뜀: 빈 파일")
            return
        # _autosave/ — 세션 디렉터리 밖 (remove_session 의 rmtree 대상 아님)
        autosave_dir = os.path.join(CONTAINER_SESSIONS_PATH, "_autosave")
        os.makedirs(autosave_dir, exist_ok=True)
        safe_title = re.sub(r'[^\w\-_. ]', '_', title).strip() or "workflow"
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_name = f"{s8(sid)}_{ts}_{safe_title}.ows"
        with open(os.path.join(autosave_dir, out_name), "wb") as f:
            f.write(file_content)
        log.info(f"[{s8(sid)}] 만료 자동저장 완료: _autosave/{out_name} "
                 f"({len(file_content)} bytes)")
    except Exception as e:
        log.warning(f"[{s8(sid)}] 만료 자동저장 오류: {e}")


# ── 만료 세션 정리 + 워밍풀 자동 교체 스레드 ──
def cleanup_loop():
    while True:
        time.sleep(60)
        now = time.time()
        # 1) 활성/만료 세션 정리 (기존)
        with _lock:
            expired = [(s, dict(v)) for s, v in sessions.items()
                       if now - v["last_seen"] > SESSION_TIMEOUT]
        for sid, info in expired:
            log.info(f"[{s8(sid)}] 세션 만료 → 정리")
            # P3-O2: 만료 직전 워크플로우 자동 저장 (배정된 세션만 — warm 풀 제외)
            if not info.get("warm", False):
                _autosave_workflow(sid, info)
            remove_session(sid)
            with _warm_lock:
                if sid in _warm_pool:
                    _warm_pool.remove(sid)
                    log.info(f"[{s8(sid)}] warm pool에서도 제거")
        # 2) 워밍풀 노화 체크 (디스크 누적 방지를 위한 자동 교체)
        stale = []
        with _warm_lock:
            for warm_sid in list(_warm_pool):
                with _lock:
                    info = sessions.get(warm_sid)
                if not info:
                    continue
                age = now - info.get("last_seen", now)
                if age > WARM_MAX_AGE:
                    stale.append((warm_sid, age))
        for warm_sid, age in stale:
            log.info(f"[{s8(warm_sid)}] 워밍풀 노화 자동 교체 (생존 {int(age)}s > {WARM_MAX_AGE}s)")
            with _warm_lock:
                if warm_sid in _warm_pool:
                    _warm_pool.remove(warm_sid)
            remove_session(warm_sid)
        # 3) 시간대별 목표 크기에 맞춰 풀 보충/축소 (② 2026-05-22)
        #    좀비 정리가 끝나기 전에는 손대지 않음 — 포트 충돌 방지.
        if _zombies_cleared.is_set():
            target = _effective_pool_size()
            with _warm_lock:
                excess = len(_warm_pool) - target
            if excess > 0:
                # 유휴 시간대 진입 등으로 풀이 목표 초과 → 가장 오래된 초과분 제거
                with _warm_lock:
                    to_drop = list(_warm_pool[:excess])
                for warm_sid in to_drop:
                    with _warm_lock:
                        if warm_sid in _warm_pool:
                            _warm_pool.remove(warm_sid)
                    remove_session(warm_sid)
                    log.info(f"[{s8(warm_sid)}] 워밍풀 축소 (목표 {target} 초과분 제거)")
            elif excess < 0 and _main_loop is not None:
                try:
                    asyncio.run_coroutine_threadsafe(_replenish_pool(), _main_loop)
                except Exception as _e:
                    log.warning(f"[warm refresh] 풀 보충 호출 실패: {_e}")
            # 3-b) Xpra 워밍풀도 시간대별 목표로 조정 (#1 2026-05-31).
            #      유휴 진입 → 초과분 제거(RAM 절감), 피크 복귀 → 보충.
            xpra_target = _xpra_effective_pool_size()
            with _xpra_lock:
                xpra_excess = len(_xpra_warm_pool) - xpra_target
                xpra_drop = list(_xpra_warm_pool[:xpra_excess]) if xpra_excess > 0 else []
            for xsid in xpra_drop:
                _xpra_remove_warm(xsid)
                log.info(f"[xpra-warm] 유휴 축소 (목표 {xpra_target} 초과분 제거) sid={xsid[:8]}")
            if xpra_excess < 0 and _main_loop is not None:
                try:
                    asyncio.run_coroutine_threadsafe(_xpra_replenish_pool(), _main_loop)
                except Exception as _e:
                    log.warning(f"[xpra-warm refresh] 풀 보충 호출 실패: {_e}")


threading.Thread(target=cleanup_loop, daemon=True).start()


# ── noVNC HTML Delete 키 인터셉트 패치 ──────────────────────────────────────
# noVNC는 VNC 프로토콜로 Delete를 전달하지만 X11 창 포커스를 보장하지 않아
# Orange3가 키를 무시함. capture 단계 스크립트를 삽입해 postMessage로 우회.
# base64 인코딩: 셸 따옴표 중첩 문제를 완전히 우회
import base64 as _b64
_PATCH_PY = _b64.b64encode(b"""\
import glob
INJECT = (
    '<script id="x-del-intercept">'
    'document.addEventListener("keydown",function(e){'
    'if(e.key==="Delete"||e.key==="Backspace"){'
    'e.stopImmediatePropagation();e.preventDefault();'
    'window.parent.postMessage({type:"vnc-del",key:e.key},"*");'
    '}else if((e.ctrlKey||e.metaKey)&&(e.key==="a"||e.key==="A")){'
    'e.stopImmediatePropagation();e.preventDefault();'
    'window.parent.postMessage({type:"vnc-selectall"},"*");'
    '}else if((e.ctrlKey||e.metaKey)&&!e.shiftKey&&(e.key==="z"||e.key==="Z")){'
    'e.stopImmediatePropagation();e.preventDefault();'
    'window.parent.postMessage({type:"vnc-undo"},"*");'
    '}else if((e.ctrlKey||e.metaKey)&&((e.key==="y"||e.key==="Y")||(e.shiftKey&&(e.key==="z"||e.key==="Z")))){'
    'e.stopImmediatePropagation();e.preventDefault();'
    'window.parent.postMessage({type:"vnc-redo"},"*");'
    '}else if(e.key==="F5"){'
    'e.stopImmediatePropagation();e.preventDefault();'
    'window.parent.postMessage({type:"vnc-reload"},"*");'
    '}},true);</script>'
)
for f in glob.glob('/opt/noVNC/**/*.html', recursive=True):
    try:
        c = open(f).read()
        if 'x-del-intercept' in c:
            continue
        open(f, 'w').write(c.replace('</head>', INJECT + '</head>', 1))
    except Exception:
        pass
""").decode()
_NOVNC_PATCH_CMD = f"python3 -c \"exec(__import__('base64').b64decode('{_PATCH_PY}').decode())\""


async def _patch_novnc(container, sid_short: str = "?"):
    """컨테이너 noVNC HTML 파일에 Delete 키 인터셉트 스크립트 삽입."""
    try:
        exit_code, out = await asyncio.get_event_loop().run_in_executor(
            None, container.exec_run, ["sh", "-c", _NOVNC_PATCH_CMD]
        )
        if exit_code == 0:
            log.info(f"[{sid_short}] noVNC Delete 패치 적용")
        else:
            log.warning(f"[{sid_short}] noVNC Delete 패치 실패 (exit={exit_code})")
    except Exception as _e:
        log.warning(f"[{sid_short}] noVNC Delete 패치 실패: {_e}")


# ── 예열 풀 관리 ──

async def _create_warm_container():
    """미리 컨테이너 1개를 생성해 풀에 추가. WARM_BOOT_CONCURRENCY 제한.

    in-flight 카운터를 증감해 동시 `_replenish_pool` 호출 시
    이미 만들고 있는 컨테이너를 '풀에 곧 들어올' 것으로 계산.
    """
    global _warm_inflight
    if client is None:
        return
    _warm_inflight += 1
    try:
        # 동시 부팅 throttle — 풀 크기 25개여도 한 번에 N개씩 부팅 (CPU 보호)
        sem = _warm_boot_sem
        if sem is None:
            return await _create_warm_container_inner()
        async with sem:
            return await _create_warm_container_inner()
    finally:
        _warm_inflight -= 1


def _splash_loading_env_val() -> str:
    """admin_settings.splashes.loading → ORANGE3_SPLASH_LOADING env 값.
       '0'=숨김 / '1'=표시. launcher(orange3_launcher.py)가 이 값으로 Orange3
       native splash 표시 여부를 결정한다. (noVNC spawn 들이 이 값을 전달해야
       관리자의 '로딩 splash 노출' 설정이 실제로 적용된다 — 2026-05-30 버그 수정)"""
    try:
        return "1" if (_admin_load_settings().get("splashes", {}) or {}).get("loading", True) else "0"
    except Exception:
        return "1"


async def _create_warm_container_inner():
    """실제 컨테이너 생성 — 세마포 안에서 호출됨."""
    try:
        port = allocate_port()
    except RuntimeError as e:
        log.warning(f"[예열] 포트 부족으로 건너뜀: {e}")
        return
    warm_sid = str(uuid.uuid4())
    container_session_dir = os.path.join(CONTAINER_SESSIONS_PATH, warm_sid)
    os.makedirs(container_session_dir, exist_ok=True)
    host_session_dir = os.path.join(HOST_SESSIONS_PATH, warm_sid)
    widget_vols = build_widget_override_volumes()
    try:
        container = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: client.containers.run(
                ORANGE3_IMAGE,
                detach=True,
                ports={"5800/tcp": ("0.0.0.0", port)},
                volumes={
                    host_session_dir: {"bind": "/config", "mode": "rw"},
                    HOST_DATA_PATH:   {"bind": "/data",   "mode": "ro"},
                    **widget_vols,
                    **build_upload_ows_volume(),
                **build_shared_thumbs_volume(),
                    **build_launcher_volume(),
                },
                labels={"orange3.session": warm_sid, "orange3.managed": "true"},
                environment={"QT_STYLE_OVERRIDE": "Fusion", "ORANGE3_SPLASH_LOADING": _splash_loading_env_val()},
                remove=False,
                mem_limit=CONTAINER_MEM_LIMIT,
                memswap_limit=CONTAINER_MEM_LIMIT,
                cpu_quota=400000,
                cpu_period=100000,
                shm_size="536870912",
            )
        )
    except Exception as e:
        log.warning(f"[예열] 컨테이너 생성 실패 port={port}: {e}")
        # Hyper-V 등 외부 포트 충돌 시 해당 포트를 일시 차단 → 다음 워밍은 다른 포트.
        _msg = str(e).lower()
        if ("ports are not available" in _msg or "bind: only one usage" in _msg
                or "address already in use" in _msg):
            block_port(port)
        else:
            release_port(port)
        return
    with _lock:
        sessions[warm_sid] = {
            "container_id": container.id,
            "port": port,
            "last_seen": time.time(),
            "warm": True,
        }
    confirm_port(port)
    # noVNC HTML Delete 키 인터셉트 패치 (이미지 재빌드 없이 런타임 적용)
    asyncio.create_task(_patch_novnc(container, s8(warm_sid)))

    # ── Orange3가 .app_ready를 만들 때까지 대기 (최대 120s) ──
    # 이렇게 해야 풀에서 꺼낸 컨테이너는 즉시 사용 가능 — LOADING_PAGE 대기 없음.
    app_ready_path = os.path.join(container_session_dir, ".app_ready")
    deadline = time.time() + 120.0
    boot_started = time.time()
    while time.time() < deadline:
        if os.path.isfile(app_ready_path):
            break
        await asyncio.sleep(0.5)
    else:
        # 타임아웃 — 부팅 실패한 컨테이너는 풀에 넣지 말고 정리
        boot_sec = int(time.time() - boot_started)
        log.warning(f"[예열] {container.short_id} Orange3 부팅 타임아웃 ({boot_sec}s) — 풀 추가 안 함")
        try:
            container.stop(timeout=5)
            container.remove()
        except Exception as _ce:
            log.warning(f"[예열] 타임아웃 컨테이너 정리 실패: {_ce}")
        with _lock:
            sessions.pop(warm_sid, None)
        release_port(port)
        return
    boot_sec = round(time.time() - boot_started, 1)
    with _warm_lock:
        _warm_pool.append(warm_sid)
    log.info(f"[예열] {container.short_id} → 포트 {port} (풀 크기: {len(_warm_pool)}, 부팅 {boot_sec}s)")


async def _replenish_pool():
    """풀이 목표 크기보다 부족하면 비동기로 보충 — 병렬 + 세마포 throttle.

    in-flight 차감으로 cleanup_loop(60s)이 보충 도중 다시 호출해도 중복 생성 안 함.
    """
    # 좀비 정리 완료 전에는 보충 보류 — 정리 중인 좀비와 포트 충돌 방지.
    if not _zombies_cleared.is_set():
        return
    with _warm_lock:
        cur = len(_warm_pool)
    needed = _effective_pool_size() - cur - _warm_inflight
    if needed <= 0:
        return
    # 병렬 생성 — 세마포로 동시 부팅 수만 제한.
    # gather(return_exceptions=True): 한 컨테이너 실패가 나머지를 죽이지 않도록 격리.
    await asyncio.gather(
        *[_create_warm_container() for _ in range(needed)],
        return_exceptions=True,
    )


@app.on_event("startup")
async def startup_event():
    # cleanup_loop 스레드가 비동기 보충 함수를 호출할 수 있도록 메인 루프 핸들 저장
    global _main_loop, _warm_boot_sem
    _main_loop = asyncio.get_running_loop()
    # 세마포는 실행 중인 이벤트 루프에 바인딩되므로 startup에서 생성
    _warm_boot_sem = asyncio.Semaphore(WARM_BOOT_CONCURRENCY)
    # admin_settings.json 에 저장된 풀 크기 override 적용 (MAX 로 cap)
    try:
        _apply_admin_pool_overrides()
    except Exception as _pe:
        log.warning(f"[startup] admin pool override 적용 실패: {_pe}")
    log.info(f"[startup] WARM_POOL_SIZE={WARM_POOL_SIZE} (MAX={WARM_POOL_SIZE_MAX}) BOOT_CONCURRENCY={WARM_BOOT_CONCURRENCY}")
    # 호스트 바인드(위젯 오버라이드/QSS 런처) 유효성 검증 — GCP 이관 시 HOST_BASE 오설정 조기 감지
    try:
        _validate_host_mounts()
    except RuntimeError:
        raise  # STRICT 모드에서는 기동 중단
    except Exception as _ve:
        log.warning(f"[startup] 마운트 검증 중 예외(무시): {_ve}")
    # widget-catalog 언어별 캐시를 디스크에서 로드 — 언어 변경 시 사이드바 즉시 응답
    try:
        _nwc = _wcat_load_disk()
        if _nwc:
            log.info(f"[startup] widget-catalog 캐시 {_nwc}개 언어 디스크 로드됨")
    except Exception as _we:
        log.warning(f"[startup] widget-catalog 캐시 로드 실패: {_we}")

    # ── 좀비 컨테이너 정리 ────────────────────────────────────────────────
    # 세션매니저 재시작 시 `sessions` 딕셔너리가 빈 상태가 되어 이전 워밍 컨테이너의
    # 포트 점유 정보를 잃음 → 새 워밍 풀이 같은 포트 시도 → 충돌 → 풀 채워지지 않음.
    # 라벨 "orange3.managed=true"가 붙은 모든 컨테이너를 제거해 깨끗한 상태에서 시작.
    if client is not None:
        try:
            zombies = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.containers.list(
                    all=True, filters={"label": "orange3.managed=true"}
                ),
            )
            log.info(f"[startup] 좀비 워밍 컨테이너 {len(zombies)}개 정리 중...")
            for c in zombies:
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, lambda c=c: (c.stop(timeout=2), c.remove())
                    )
                except Exception as _ce:
                    log.warning(f"[startup] 좀비 정리 오류 ({c.short_id}): {_ce}")
            log.info("[startup] 좀비 정리 완료")
        except Exception as _e:
            log.warning(f"[startup] 좀비 목록 조회 실패: {_e}")

    # 좀비 정리가 끝났음(또는 client 없음/조회 실패)을 알림 → 워밍풀 보충 허용.
    # 이 신호 전까지 cleanup_loop·_replenish_pool 의 보충은 모두 보류된다.
    _zombies_cleared.set()

    # ── Xpra 고아 컨테이너 정리 (Phase 3C-1, 2026-05-23) ─────────────────────
    # 재시작 시 xpra_sessions(in-memory)는 비지만 이전 orange3.xpra 컨테이너가
    # 호스트 포트를 그대로 점유 → 새 spawn 시 충돌. noVNC 좀비 정리와 동일 패턴.
    if client is not None:
        try:
            xpra_orphans = client.containers.list(
                all=True, filters={"label": "orange3.xpra=true"})
            if xpra_orphans:
                log.info(f"[startup] Xpra 고아 컨테이너 {len(xpra_orphans)}개 정리 중...")
                for c in xpra_orphans:
                    try:
                        c.stop(timeout=2)
                        c.remove()
                    except Exception as _ce:
                        log.warning(f"[startup] Xpra 고아 정리 오류 ({c.short_id}): {_ce}")
                log.info("[startup] Xpra 고아 정리 완료")
        except Exception as _e:
            log.warning(f"[startup] Xpra 고아 조회 실패: {_e}")

    asyncio.create_task(_replenish_pool())
    if XPRA_WARM_POOL_SIZE > 0:
        log.info(f"[startup] XPRA_WARM_POOL_SIZE={XPRA_WARM_POOL_SIZE} — 초기 보충 예약")
        asyncio.create_task(_xpra_replenish_pool())

    # 좌하단 메타 패널의 Orange3 버전 캐시 워밍업 — 워밍풀이 충분히 채워지길
    # 기다린 뒤 _get_orange_version() 1회 호출 → 이후 wrapper 페이지가 즉시 노출.
    async def _warmup_orange_version_cache():
        for _ in range(60):  # 최대 ~60초 대기
            try:
                with _xpra_lock:
                    has_xpra = bool(_xpra_warm_pool)
                with _warm_lock:
                    has_main = bool(_warm_pool)
                if has_xpra or has_main:
                    v = await _get_orange_version()
                    log.info(f"[startup] orange version cache 워밍업: {v}")
                    return
            except Exception as _e:
                log.warning(f"[startup] version warmup loop err: {_e}")
            await asyncio.sleep(1.0)
        log.warning("[startup] version cache 워밍업 타임아웃 — 첫 사용자 호출에서 채워짐")
    asyncio.create_task(_warmup_orange_version_cache())


# ── HTML 템플릿 ──

LOADING_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>EBS Orange3</title>
  <style>
    body {{ background:#ffffff; color:#222; font-family:sans-serif;
           display:flex; justify-content:center; align-items:center;
           height:100vh; margin:0; }}
    .box {{ text-align:center; }}
    .spinner {{ width:52px; height:52px; border:6px solid #e0e0e0;
               border-top-color:#F47B20; border-radius:50%;
               animation:spin .9s linear infinite; margin:0 auto 24px; }}
    @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
    #msg {{ color:#888; font-size:14px; margin-top:8px; }}
  </style>
</head>
<body>
  <div class="box">
    <div class="spinner"></div>
    <h2>EBS Orange3</h2>
    <div id="msg"></div>
  </div>
  <script>
    const sid  = "{sid}";
    const lang = "{lang}";   /* URL ?lang= 파라미터 — reload 시 보존 */
    let elapsed = 0;
    const MAX_SEC = 150;
    let _timer = null;

    /* 로딩 페이지 라벨 — URL lang 또는 ko default */
    const _LP_LBL = {{
      ko: {{ start:'컨테이너 시작 중...', startN:'시작 중...',
             ready:'준비 완료 — 로딩 중...', expired:'세션 만료 — 새로 발급합니다...' }},
      en: {{ start:'Starting container...', startN:'Starting...',
             ready:'Ready — loading...', expired:'Session expired — redirecting...' }},
      sl: {{ start:'Zaganjanje vsebnika...', startN:'Zaganjanje...',
             ready:'Pripravljeno — nalaganje...', expired:'Seja je potekla — preusmerjanje...' }}
    }};
    const _LPL = _LP_LBL[lang] || _LP_LBL.en;
    document.getElementById('msg').textContent = _LPL.start;

    /* ── 이 탭의 sessionStorage에 SID 저장 (탭별 세션 분리) ── */
    try {{ sessionStorage.setItem('orange3_sid', sid); }} catch(_) {{}}

    /* ── 준비 완료 시 sid와 lang 파라미터를 유지하며 전환 ── */
    function gotoApp() {{
      window.location.href = '/?sid=' + sid + (lang ? '&lang=' + lang : '');
    }}

    /* ── SSE 방식: 폴링 없이 서버 push로 준비 신호 수신 ── */
    function connect() {{
      const es = new EventSource('/ready-sse?sid=' + sid);

      es.onmessage = function(e) {{
        try {{
          const d = JSON.parse(e.data);
          if (d.ready) {{
            es.close();
            clearTimeout(_timer);
            document.getElementById('msg').textContent = _LPL.ready;
            setTimeout(gotoApp, 100);
          }} else if (d.not_found || d.dead) {{
            es.close();
            clearTimeout(_timer);
            document.getElementById('msg').textContent = _LPL.expired;
            setTimeout(function() {{ window.location.href = '/'; }}, 2000);
          }} else {{
            elapsed = d.elapsed || elapsed;
            document.getElementById('msg').textContent =
              _LPL.startN + ' (' + Math.round(elapsed) + '/' + MAX_SEC + 's)';
          }}
        }} catch(_) {{}}
      }};

      es.onerror = function() {{
        es.close();
        /* SSE 연결 오류 시 2초 후 폴백 재시도 */
        setTimeout(connect, 2000);
      }};

      /* 최대 대기 타임아웃 */
      _timer = setTimeout(function() {{
        es.close();
        gotoApp();
      }}, MAX_SEC * 1000);
    }}

    connect();
  </script>
</body>
</html>"""


WRAPPER_PAGE = """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EBS Orange3</title>
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    /* 브라우저 스크롤바 완전 차단 — html·body 둘 다 overflow:hidden + 100vh 고정 */
    html, body {{ height:100vh; max-height:100vh; overflow:hidden; }}
    body {{ background:#ffffff; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; }}

    /* ── 헤더 바 ── */
    #header-bar {{
      position:fixed; top:0; left:0; right:0; height:52px;
      background:#fff; border-bottom:none;
      display:flex; align-items:center; padding:0 12px; gap:8px;
      z-index:9500; box-shadow:none;
    }}
    #logo {{
      display:flex; align-items:center; gap:7px;
      font-size:17px; font-weight:700; color:#222; white-space:nowrap;
    }}
    #logo em {{ color:#F47B20; font-style:normal; }}

    .hdr-sep {{ width:1px; height:20px; background:#ddd; margin:0 6px; flex-shrink:0; }}

    /* 문서 타이틀 드롭다운 */
    #menu-wrap {{ position:relative; }}
    #menu-wrap {{ display:flex; align-items:center; gap:8px; }}
    /* 헤더의 햄버거 버튼 + 문서 타이틀 숨김 — 사이드바 .hwd-menu 가 대체.
       #menu-wrap 자체와 #menu-dropdown 은 DOM 에 유지(사이드바 메뉴 재사용용). */
    #menu-btn, #doc-title {{ display:none !important; }}
    #menu-btn {{
      display:flex; align-items:center; gap:3px; cursor:pointer;
      padding:4px 18px; border-radius:6px; font-size:13px;
      background:#555; color:#fff; user-select:none;
      transition:background .15s; flex-shrink:0;
    }}
    #menu-btn:hover {{ background:#333; }}
    .doc-chevron {{ font-size:9px; color:rgba(255,255,255,0.8); margin-left:1px; }}
    #doc-title {{
      font-size:13px; color:#333; font-weight:500;
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      width:325px; background:transparent;
      cursor:pointer; padding:3px 6px; border-radius:4px;
      transition:background .15s;
    }}
    #doc-title {{ cursor:default; }}
    #menu-dropdown {{
      display:none; position:absolute; top:calc(100% + 6px); left:0;
      background:#fff; border:1px solid #e5e5ea; border-radius:10px;
      box-shadow:0 8px 24px rgba(0,0,0,0.13); min-width:160px;
      padding:4px 0; z-index:9200;
    }}
    #menu-dropdown.open {{ display:block; }}
    .mi {{
      padding:8px 16px; font-size:13px; color:#222; cursor:pointer;
      transition:background .12s;
    }}
    .mi:hover {{ background:#f5f5f7; }}
    .ms {{ height:1px; background:#e5e5ea; margin:4px 0; }}

    /* 헤더 가운데 안내 문구 (Phase 5, 2026-05-24) */
    #header-caption {{
      margin-left:14px;
      color:#888; font-size:12px; font-weight:500;
      font-family:-apple-system,"Malgun Gothic",sans-serif;
      letter-spacing:0.1px; white-space:nowrap;
      overflow:hidden; text-overflow:ellipsis;
      user-select:none; pointer-events:none;
    }}
    /* 헤더 우측 */
    #header-right {{
      margin-left:auto; display:flex; align-items:center; gap:6px;
    }}
    .h-btn {{
      padding:6px 14px; border-radius:8px; font-size:13px; cursor:pointer;
      border:1px solid #e5e5ea; background:#fff; color:#222;
      white-space:nowrap; transition:background .12s;
      display:inline-flex; align-items:center; gap:6px;
    }}
    .h-btn:hover {{ background:#f5f5f7; }}
    .h-btn svg {{ flex-shrink:0; }}
    .h-btn.primary {{
      background:#F47B20; color:#fff; border-color:#F47B20; font-weight:600;
    }}
    .h-btn.primary:hover {{ background:#d96b10; }}
    /* New Open 버튼 — 흰 배경에 텍스트만 오렌지 강조 (이미지 2 스타일) */
    .h-btn.accent {{ font-weight:600; color:#F47B20; }}
    .h-btn.accent:hover {{ background:#fff5eb; }}
    .h-btn.accent svg {{ stroke:#222; }}

    /* 언어/옵션 드롭다운 */
    #lang-wrap {{ position:relative; }}
    #lang-btn {{
      display:flex; align-items:center; gap:5px; cursor:pointer;
      padding:5px 10px; border-radius:8px; font-size:13px;
      color:#222; border:1px solid #e5e5ea; background:#fff;
      user-select:none; transition:background .15s;
    }}
    #lang-btn:hover {{ background:#f5f5f7; }}
    .lang-chevron {{ font-size:10px; color:#888; }}
    #lang-dropdown {{
      display:none; position:fixed; top:52px; right:12px;
      background:#fff; border:1px solid #e5e5ea; border-radius:10px;
      box-shadow:0 8px 24px rgba(0,0,0,0.13); min-width:148px;
      padding:4px 0; z-index:99999;
    }}
    #lang-dropdown.open {{ display:block; }}
    /* 언어 드롭다운 바깥(캔버스) 클릭 감지용 투명 백드롭. top 은 toggleLang 에서
       헤더 바로 아래로 동적 설정 → 헤더 버튼 영역은 덮지 않음. z-index 는 드롭다운
       (99999)보다 아래라 항목 선택은 그대로 가능. */
    #lang-backdrop {{
      display:none; position:fixed; top:52px; left:0; right:0; bottom:0;
      z-index:99990; background:transparent;
    }}
    #lang-backdrop.open {{ display:block; }}
    .li {{
      padding:8px 16px; font-size:13px; color:#222; cursor:pointer;
      transition:background .12s;
    }}
    .li:hover {{ background:#f5f5f7; }}
    .li.active {{ color:#F47B20; font-weight:600; }}

    /* ── VNC iframe ── */
    #vnc-frame {{
      position:fixed; top:83px; left:0; right:0; border:none;
      width:100vw; height:calc(100vh - 83px);
      border:none; display:block;
      will-change:transform; transform:translateZ(0);
    }}
    /* ── 위젯 패널 하단 footer (Phase 5, 2026-05-24) ──
       기존 canvas 좌하단 footer-info 를 위젯 패널 하단으로 이동.
       패널이 열린 동안만 노출, 닫히면 자연스럽게 사라짐. */
    #hwd-panel-footer {{
      flex-shrink:0; padding:10px 12px;
      border-top:1px solid #ececef; background:#fafafa;
      display:flex; align-items:center; justify-content:flex-start;
      user-select:none;
    }}
    #hwd-panel-footer img {{
      max-height:28px; width:auto; height:28px;
      flex:none; opacity:0.92;
    }}
    #hwd-panel-footer img:not([src]),
    #hwd-panel-footer img[src=""] {{ display:none; }}

    /* ── 워크플로우 탭 바 ── */
    /* ── 워크플로우 탭 바 ── */
    #wf-tabbar {{
      position:fixed; top:52px; left:0; right:0; height:31px;
      display:flex; align-items:flex-end; justify-content:flex-start; padding:0 11px 0 0; gap:0;
      z-index:9001; pointer-events:none;
      background:transparent;
      border-bottom:1px solid #e5e5ea;  /* 밝은 회색 경계 라인 (light gray, 2026-05-22) */
    }}
    /* 탭 스크롤 영역 — overflow 발생 시 양옆 화살표가 스크롤 (이미지 2 스타일).
       flex:0 1 auto → 컨텐츠 크기 기본, 공간 부족하면 축소(overflow 활성).
       + 버튼은 inner 바로 다음에 위치하므로 마지막 탭 옆에 자동 정렬됨.
       overflow 발생 시: inner 가 가용 공간만큼 축소되고 → [<][inner][>][+] 순으로
       + 가 자연스럽게 우측 화살표 뒤에 위치. */
    #wf-tabbar-inner {{
      display:flex; align-items:flex-end;
      flex:0 1 auto; min-width:0;
      overflow-x:hidden; overflow-y:hidden;
      scroll-behavior:smooth;
      pointer-events:auto;
    }}
    #wf-tabbar-inner::-webkit-scrollbar {{ display:none; }}
    .wf-tab-scroll {{
      display:none;  /* overflow 있을 때만 .visible 로 표시 */
      align-items:center; justify-content:center;
      width:24px; height:27px; flex-shrink:0;
      border:1px solid #e5e5ea; border-bottom:none;
      background:#f4f4f4; color:#555;
      cursor:pointer; pointer-events:auto;
      font-size:14px; line-height:1;
      transition:background .12s, color .12s;
      user-select:none;
    }}
    .wf-tab-scroll.visible {{ display:inline-flex; }}
    .wf-tab-scroll:hover {{ background:#e8e8e8; color:#222; }}
    .wf-tab-scroll.disabled {{ opacity:0.35; pointer-events:none; cursor:default; }}

    /* "···" 전체 탭 목록 팝업 버튼 — 우측 화살표 다음에 위치 (화살표와 함께 표시/숨김) */
    #wf-tab-overflow-btn {{
      font-size:16px; letter-spacing:1px;
    }}
    /* 전체 탭 목록 팝업 메뉴 */
    #wf-tab-overflow-menu {{
      display:none; position:fixed;
      background:#ffffff; border:1px solid #e5e5ea; border-radius:8px;
      box-shadow:0 8px 24px rgba(0,0,0,0.15);
      min-width:220px; max-width:340px;
      max-height:60vh; overflow-y:auto;
      z-index:9100;
      padding:4px 0;
      font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", "맑은 고딕", sans-serif;
    }}
    #wf-tab-overflow-menu.open {{ display:block; }}
    .wf-overflow-item {{
      display:flex; align-items:center; gap:8px;
      padding:7px 14px; font-size:13px; color:#222;
      cursor:pointer;
      transition:background .12s;
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
    }}
    .wf-overflow-item:hover {{ background:#f5f5f7; }}
    .wf-overflow-item.active {{ font-weight:600; color:#1a1a1c; }}
    .wf-overflow-item .wf-overflow-check {{
      width:14px; flex-shrink:0; color:#1a1a1c;
      display:inline-flex; align-items:center; justify-content:center;
    }}
    .wf-overflow-item .wf-overflow-label {{
      flex:1; overflow:hidden; text-overflow:ellipsis;
    }}
    .wf-tab {{
      display:inline-flex; align-items:center; gap:11px;
      height:27px; padding:0 14px 0 18px;  /* 29→27 (활성 탭 + 4px border = 31px, wf-tabbar 와 정확히 일치) */
      background:#e8e8e8; color:#666666; font-size:13px; font-weight:400;
      border-radius:0; cursor:pointer;
      pointer-events:auto; user-select:none;
      border:1px solid #e5e5ea; border-bottom:none;
      white-space:nowrap; overflow:visible;
      transition:background .15s; flex-shrink:0;
    }}
    .wf-tab:hover {{ background:#d8d8d8; }}
    .wf-tab.wf-active {{
      background:#ffffff; color:#222222; font-weight:400;
      border-color:#e5e5ea; border-bottom:2px solid #ffffff;
      border-top:2px solid #F47B20;
    }}
    .wf-tab-title {{
      overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1;
      text-align:left;
    }}
    .wf-tab-dirty {{ color:#F47B20; font-size:11px; flex-shrink:0; line-height:1; }}
    .wf-tab-dot {{
      display:inline-flex; align-items:center; justify-content:center;
      font-size:22px; font-weight:bold; color:#aaaaaa; pointer-events:none;
      width:22px; height:22px; flex-shrink:0; line-height:1;
    }}
    .wf-tab-close {{
      display:inline-flex; align-items:center; justify-content:center;
      font-size:14px; color:#555555; cursor:pointer; pointer-events:auto;
      width:22px; height:22px; border-radius:3px;
      flex-shrink:0; transition:color .1s, background .1s;
    }}
    .wf-tab-close:hover {{ color:#fff; background:rgba(0,0,0,0.25); }}
    .wf-tab.wf-active .wf-tab-close:hover {{ color:#333; background:rgba(0,0,0,0.1); }}
    .wf-tab-add {{
      display:inline-flex; align-items:center; justify-content:center;
      height:35px; width:36px; border-radius:0;
      color:#888898; font-size:22px; line-height:1; cursor:pointer; pointer-events:auto;
      background:transparent; flex-shrink:0; user-select:none;
      transition:background .15s;
    }}
    .wf-tab-add:hover {{ background:rgba(0,0,0,0.06); color:#333333; }}

    /* ── 토스트 ── */
    /* ── 교안 Workflows 갤러리 모달 ── */
    #lesson-modal {{
      display:none; position:fixed; inset:0; z-index:99000;
      background:rgba(0,0,0,0.55); backdrop-filter:blur(4px);
      align-items:center; justify-content:center;
    }}
    #lesson-modal.open {{ display:flex; }}
    #lesson-modal-box {{
      width:92%; max-width:1400px; height:88vh; max-height:880px;
      background:#fff; border-radius:14px; box-shadow:0 12px 48px rgba(0,0,0,0.4);
      display:flex; flex-direction:column; overflow:hidden;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    }}
    #lesson-header {{
      display:flex; align-items:center; gap:16px; padding:14px 20px;
      border-bottom:1px solid #ececef; flex-shrink:0;
    }}
    #lesson-title {{
      display:flex; align-items:center; gap:10px;
      font-size:17px; font-weight:600; color:#1a1a1c; flex-shrink:0;
      padding-right:18px;
    }}
    #lesson-search-wrap {{
      flex:1; max-width:520px; display:flex; align-items:center; gap:8px;
      background:#f4f4f6; border:1px solid #e5e5ea; border-radius:8px;
      padding:8px 14px; color:#888;
    }}
    #lesson-search-wrap:focus-within {{ border-color:#3b82f6; background:#fff; }}
    #lesson-search {{
      flex:1; border:none; outline:none; background:transparent;
      font-size:14px; color:#222;
    }}
    #lesson-close {{
      width:34px; height:34px; border:1px solid #e5e5ea; background:#f4f4f6;
      border-radius:8px; cursor:pointer; font-size:14px; color:#555;
      display:flex; align-items:center; justify-content:center;
      margin-left:auto;
    }}
    #lesson-close:hover {{ background:#ececef; color:#000; }}
    #lesson-body {{ flex:1; display:flex; min-height:0; }}
    #lesson-sidebar {{
      width:230px; flex-shrink:0; padding:14px 12px; overflow-y:auto;
      border-right:1px solid #ececef; background:#fafafa;
    }}
    #lesson-sidebar .lc-cat {{
      display:flex; align-items:center; gap:10px;
      padding:9px 12px; border-radius:8px; cursor:pointer;
      font-size:13.5px; color:#444; margin-bottom:2px;
      transition:background .12s;
    }}
    #lesson-sidebar .lc-cat:hover {{ background:#ececef; }}
    /* 2026-05-29 v3: 선택 상태 검정 → 밝은 회색으로 변경 (사용자 요청) */
    #lesson-sidebar .lc-cat.active {{
      background:#e5e7eb; color:#1a1a1c; font-weight:600;
    }}
    #lesson-sidebar .lc-cat svg {{ flex-shrink:0; }}
    /* 하위 카테고리 들여쓰기 (v6, 2026-05-27): Example Workflow > Basic > 8 sub */
    #lesson-sidebar .lc-cat.lc-cat-sub {{
      padding-left: 32px; font-size:13px; color:#666;
    }}
    #lesson-sidebar .lc-cat.lc-cat-sub.active {{
      background:#e5e7eb; color:#1a1a1c;
    }}
    /* 3-level 들여쓰기 — Basic 아래 8개 sub-sub 카테고리 */
    #lesson-sidebar .lc-cat.lc-cat-sub-sub {{
      padding-left: 52px; font-size:12.5px; color:#777;
    }}
    #lesson-sidebar .lc-cat.lc-cat-sub-sub.active {{
      background:#e5e7eb; color:#1a1a1c;
    }}
    #lesson-sidebar .lc-section {{
      font-size:11px; font-weight:600; color:#999;
      letter-spacing:0.7px; padding:18px 12px 6px; text-transform:uppercase;
    }}
    /* 접기 가능한 부모 카테고리 (2026-05-29) — Example Workflow, 교재 BOOK */
    #lesson-sidebar .lc-cat-parent {{ justify-content:flex-start; }}
    #lesson-sidebar .lc-cat-parent .lc-caret {{
      margin-left:auto;
      font-size:10px;
      color:#9ca3af;
      transition:transform .18s ease;
      transform:rotate(0deg);
    }}
    #lesson-sidebar .lc-cat-parent.collapsed .lc-caret {{
      transform:rotate(-90deg);
    }}
    #lesson-sidebar .lc-subgroup {{
      overflow:hidden;
      max-height:none;
      transition:max-height .2s ease, opacity .2s ease;
      opacity:1;
    }}
    #lesson-sidebar .lc-subgroup.collapsed {{
      max-height:0;
      opacity:0;
      pointer-events:none;
    }}
    /* 교재 BOOK sub 항목 — 책 제목이 길어 폰트 2px 축소 (lc-cat-sub 13px → 11px, 2026-05-29) */
    #lesson-sidebar .lc-cat-sub[data-cat^="교재:"] {{
      font-size:11px;
      line-height:1.4;
    }}
    #lesson-sidebar .lc-cat-sub[data-cat^="교재:"] span {{
      font-size:11px;
      line-height:1.4;
    }}
    #lesson-content {{
      flex:1; overflow-y:auto; padding:24px 32px 32px 32px;
    }}
    #lesson-heading {{
      font-size:24px; font-weight:700; color:#1a1a1c; margin:0 0 6px 0;
    }}
    /* 카테고리별 출처 표시 (Example Workflow 의 Orange3 원본 URL 등, 2026-05-27)
       :empty 셀렉터로 내용 없을 때 공간 차지 안 함 (2026-05-29 v3). */
    #lesson-source {{
      font-size:12px; color:#6b7280; line-height:1.55;
      margin:0 0 18px 0;
    }}
    #lesson-source:empty {{ margin:0; }}
    #lesson-source a {{
      color:#2563eb; text-decoration:none;
    }}
    #lesson-source a:hover {{ text-decoration:underline; }}
    /* 교재 BOOK 안내 박스 (2026-05-29) — 저작권/출판사 확인 안내.
       v3: 내용 너비만 차지 (오른쪽 빈 공간 제거) — 사용자 요청. */
    #lesson-source .lc-book-notice {{
      display:inline-flex; align-items:flex-start; gap:8px;
      background:#fffbeb;
      border:1px solid #fde68a;
      border-radius:6px;
      padding:9px 14px;
      color:#92400e;
      font-size:12.5px;
      line-height:1.5;
      max-width:100%;
    }}
    #lesson-source .lc-book-notice svg {{ color:#b45309; }}
    /* 헤더 영역 안내 문구 (Templates 로고 옆, ✕ 버튼 왼쪽) */
    #lesson-header-note {{
      flex:1;
      font-size:12.5px; color:#6b7280; line-height:1.45;
      margin:0; padding:0 16px;
      white-space:normal; word-break:keep-all;
    }}
    #lesson-grid {{
      display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr));
      gap:18px;
    }}
    /* ── 교재 BOOK: 책 정보 카드 (2026-05-29) ────────────────────────────
       이미지 + 책 메타데이터 + url/다운로드 버튼. 그리드 위쪽에 표시.
       2026-05-29 v2: 배경색 제거 (transparent) + 표지 placeholder 제거. */
    #lesson-book-info {{
      display:none;
      background:transparent;
      border:0;
      padding:0;
      margin:0 0 22px;
      gap:18px;
    }}
    #lesson-book-info.show {{ display:flex; }}
    #lesson-book-info .bi-cover {{
      flex-shrink:0;
      width:140px; height:190px;
      background:transparent;
      border-radius:8px;
      display:flex; align-items:center; justify-content:center;
      overflow:hidden;
    }}
    #lesson-book-info .bi-cover img {{
      max-width:100%; max-height:100%;
      object-fit:contain; display:block;
    }}
    /* 2026-05-29 v3: 4-line 구성 (제목 / 출판사 / 저자 / 액션) */
    #lesson-book-info .bi-detail {{
      flex:1; display:flex; flex-direction:column; gap:6px;
      min-width:0;
    }}
    #lesson-book-info .bi-title {{
      font-size:17px; font-weight:700; color:#1a1a1c;
      line-height:1.35;
      margin-bottom:2px;
    }}
    #lesson-book-info .bi-meta {{
      display:flex; flex-direction:column; gap:3px;
      font-size:13px; color:#4b5563; line-height:1.5;
    }}
    #lesson-book-info .bi-meta-row {{
      display:flex; gap:8px; align-items:baseline;
    }}
    #lesson-book-info .bi-meta-row b {{
      color:#1a1a1c; font-weight:600; min-width:42px; flex-shrink:0;
    }}
    #lesson-book-info .bi-meta-row span {{ color:#4b5563; }}
    /* URL 과 다운로드 버튼 줄 (4-line 중 마지막) */
    #lesson-book-info .bi-actions {{
      margin-top:6px; display:flex; gap:6px; align-items:center; flex-wrap:wrap;
    }}
    #lesson-book-info .bi-url {{
      flex:0 1 auto;
      max-width:540px;
      padding:8px 14px;
      background:#fff; border:1px solid #d1d5db; border-radius:6px;
      color:#1d4ed8; text-decoration:none; font-size:12.5px;
      overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
      display:inline-flex; align-items:center; gap:8px;
      transition:background .12s, border-color .12s;
    }}
    #lesson-book-info .bi-url:hover {{
      background:#eff6ff; border-color:#93c5fd;
    }}
    #lesson-book-info .bi-download {{
      flex:0 0 auto;
      padding:8px 16px;
      background:#fff; color:#374151;
      border:1px solid #d1d5db; border-radius:6px;
      font-size:13px; font-weight:500;
      cursor:pointer;
      transition:background .12s, border-color .12s;
      display:inline-flex; align-items:center; gap:6px;
    }}
    #lesson-book-info .bi-download:hover {{
      background:#f9fafb; border-color:#9ca3af;
    }}
    #lesson-book-info .bi-download:active {{
      background:#f3f4f6;
    }}
    #lesson-book-info .bi-download:disabled {{
      background:#fafafa; color:#9ca3af; cursor:not-allowed;
    }}
    .lc-card {{
      background:#fff; border:1px solid #ececef; border-radius:12px;
      overflow:hidden; cursor:pointer; transition:all .15s;
      display:flex; flex-direction:column;
    }}
    .lc-card:hover {{
      transform:translateY(-2px); box-shadow:0 8px 22px rgba(0,0,0,0.12);
      border-color:#d8d8de;
    }}
    .lc-thumb {{
      position:relative; aspect-ratio:1.15/1; padding:14px;
      display:flex; flex-direction:column; justify-content:flex-end;
      color:#fff; overflow:hidden;
    }}
    .lc-thumb-svg {{
      position:absolute; inset:0; width:100%; height:100%;
      object-fit:contain; padding:8%; pointer-events:none;
      background:#fff;
    }}
    .lc-thumb:has(.lc-thumb-svg) .lc-vendor {{ color:#1a1a1c; }}
    .lc-thumb:has(.lc-thumb-svg) .lc-badge {{
      background:rgba(0,0,0,0.7);
    }}
    .lc-vendor {{
      position:absolute; top:12px; left:12px;
      display:flex; align-items:center; gap:6px;
      background:rgba(255,255,255,0.92); color:#1a1a1c;
      padding:5px 10px; border-radius:14px; font-size:11.5px; font-weight:600;
      box-shadow:0 1px 4px rgba(0,0,0,0.18);
    }}
    .lc-badges {{
      position:absolute; bottom:12px; left:12px; right:12px;
      display:flex; gap:5px; flex-wrap:wrap;
    }}
    .lc-badge {{
      background:rgba(0,0,0,0.55); color:#fff; font-size:10.5px;
      padding:3px 9px; border-radius:5px; font-weight:500;
      backdrop-filter:blur(4px);
    }}
    .lc-card-title {{
      font-size:14px; font-weight:600; color:#1a1a1c;
      padding:13px 14px 4px; line-height:1.3;
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
    }}
    .lc-card-desc {{
      font-size:12.5px; color:#666; padding:0 14px 22px;
      line-height:1.45; min-height:2.9em;
      display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical;
      overflow:hidden;
    }}

    /* ── 임시 HTML 위젯 사이드바 (이미지 참조 — 컴팩트 + 충분한 여백) ──
       너비 43px, 흰 배경 + 작은 컬러 SVG 아이콘. 아이콘 간격 4px로 시각적 호흡 확보. */
    #html-widget-dock {{
      position:fixed; top:83px; left:0; bottom:0; width:43px;
      background:#ffffff; border-right:1px solid #e0e0e0;
      z-index:8500;
      /* overflow:visible — ::after 풍선 툴팁이 dock 우측 밖으로 확장되도록.
         (overflow-x:hidden 또는 overflow-y:auto는 한 축이라도 비-visible이면 다른 축도 클리핑) */
      overflow:visible;
      display:flex; flex-direction:column;
      /* 옆 패널 헤더 행과 1:1 정렬 (2026-05-24) — 패널 행 33px, gap 0
         상단 2px 여백 (2026-05-25) — 햄버거 메뉴 버튼 위 공간 */
      align-items:center; padding:2px 0 0 0; gap:0;
    }}
    .hwd-cat {{
      width:28px; height:33px; flex-shrink:0;
      display:flex; align-items:center; justify-content:center;
      border-radius:5px; cursor:pointer;
      transition:background .1s;
      position:relative;  /* 풍선 툴팁의 absolute 위치 기준 */
    }}
    .hwd-cat:hover {{ background:rgba(0,0,0,0.06); }}
    .hwd-cat:active {{ background:rgba(0,0,0,0.12); }}

    /* ── 풍선 툴팁 (이미지 2 "Templates" 스타일) ──
       data-tip 속성을 가진 모든 요소(hwd-cat, hwd-menu, hwd-widget)가 공유하는 단일
       풍선 요소. document.body에 append되므로 부모의 overflow:hidden/auto 영향을 받지
       않음 — 스크롤 영역 안의 위젯 항목에서도 정상 표시됨. */
    #hwd-tip {{
      position:fixed; display:none; pointer-events:none;
      /* 채팅 말풍선 스타일 (Phase 5, 2026-05-24) — 흰 배경 + 라운드 + 좌측 tail */
      background:#ffffff; color:#1a1a1c;
      border:1px solid #e5e7eb;
      padding:12px 18px; border-radius:22px;
      font-size:12.5px; font-weight:500; line-height:1.5;
      font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", "맑은 고딕", sans-serif;
      white-space:normal; max-width:320px;
      z-index:9999;
      box-shadow:0 4px 16px rgba(0,0,0,0.10), 0 1px 3px rgba(0,0,0,0.06);
      opacity:0; transition:opacity .12s ease-in;
    }}
    #hwd-tip.visible {{ opacity:1; }}
    /* 카테고리 우클릭 컨텍스트 메뉴 (Phase 5, 2026-05-24) — Open all / Close all */
    #hwd-cat-ctx-menu {{
      position:fixed; display:none; z-index:9999;
      min-width:120px; padding:4px 0;
      background:#ffffff; border:1px solid #d0d0d2;
      border-radius:4px;
      box-shadow:0 4px 12px rgba(0,0,0,0.15);
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Malgun Gothic",sans-serif;
      font-size:13px; color:#1a1a1c;
      user-select:none;
    }}
    #hwd-cat-ctx-menu .hwd-ctx-item {{
      padding:6px 16px; cursor:pointer;
    }}
    #hwd-cat-ctx-menu .hwd-ctx-item:hover {{
      background:#f0f0f2;
    }}
    /* tail — 좌측 끝, 위젯 방향(왼쪽) 으로 뾰족하게 (border 와 fill 이중 트라이앵글) */
    #hwd-tip::before,
    #hwd-tip::after {{
      content:""; position:absolute; left:-9px; top:16px;
      width:0; height:0;
      border-top:8px solid transparent;
      border-bottom:8px solid transparent;
      border-right:9px solid #e5e7eb;  /* border 색 */
    }}
    #hwd-tip::after {{
      left:-8px; border-right-color:#ffffff;  /* 내부 흰색 (border 위에 덮음) */
    }}
    /* 툴팁이 위젯 좌측에 표시될 때 (right edge 초과 시) — tail 방향 반전 */
    #hwd-tip.hwd-tip-left::before,
    #hwd-tip.hwd-tip-left::after {{
      left:auto; right:-9px;
      border-right:none;
      border-left:9px solid #e5e7eb;
    }}
    #hwd-tip.hwd-tip-left::after {{
      right:-8px; border-left-color:#ffffff;
    }}
    /* 풍부 툴팁 내부 (Phase 5, 2026-05-24) — Orange3 native 형식 모방 */
    .hwd-tip-title {{ font-size:13px; margin-bottom:6px; color:#1a1a1c; }}
    .hwd-tip-title b {{ font-weight:700; }}
    .hwd-tip-pkg {{ color:#888; font-weight:400; font-size:12px; }}
    .hwd-tip-desc {{ font-size:12.5px; color:#374151; line-height:1.5;
                    margin-bottom:8px; }}
    .hwd-tip-section {{ font-size:12px; color:#1a1a1c; margin-top:6px;
                       font-weight:600; }}
    .hwd-tip-section ul {{ margin:3px 0 0 14px; padding:0;
                          list-style:disc; font-weight:400; color:#374151; }}
    .hwd-tip-section li {{ font-size:12px; line-height:1.55; }}
    .hwd-tip-type {{ color:#9ca3af; font-size:11px; }}
    .hwd-cat-icon {{
      width:22px; height:22px; border-radius:3px;
      display:flex; align-items:center; justify-content:center;
      user-select:none;
    }}
    .hwd-cat-icon svg {{ display:block; }}
    /* 사이드바 최상단 메뉴 버튼 — 회색 4-row bulleted list (이미지 2 참조)
       클릭 시 헤더의 메뉴 dropdown 토글 (New / Open / Save / Save a Copy / Close) */
    .hwd-menu {{
      /* 사이드바 카테고리 아이콘과 동일한 33px row 로 통일 (2026-05-24) */
      width:28px; height:33px; flex-shrink:0;
      display:flex; align-items:center; justify-content:center;
      border-radius:5px; cursor:pointer;
      background:#e8e8eb;
      transition:background .1s;
    }}
    .hwd-menu:hover {{ background:#d8d8de; }}
    .hwd-menu:active {{ background:#c8c8ce; }}
    .hwd-menu-icon {{ display:block; flex-shrink:0; }}

    /* 메뉴 버튼과 카테고리 아이콘 사이 구분 바 */
    .hwd-divider {{
      width:24px; height:1px;
      flex-shrink:0;
      background:rgba(0,0,0,0.18);
      margin:2px 0;
    }}
    /* 사이드바 마지막 카테고리 다음 구분선 — 위쪽 여백 살짝 더, 폭 더 길게 (2026-05-24) */
    .hwd-cat-sep-end {{
      margin-top:6px;
      width:28px;
    }}
    /* 햄버거 메뉴 ↔ 카테고리 사이 구분선 (2026-05-25):
       phase divider 와 정확히 같은 두께·색·폭. margin-top 만 +2 더 줘서
       햄버거 아래 여백 살짝 강화. */
    .hwd-menu-sep {{
      margin-top:4px;       /* 햄버거 아래 추가 2px (기본 2 + 추가 2) */
      margin-bottom:2px;
      /* width 와 background 는 .hwd-divider 기본값(24px / rgba 0.18) 그대로 사용 */
    }}

    /* ── 단계 2B: 카테고리 선택 시 표시되는 위젯 목록 패널 ── */
    .hwd-cat.active {{ background:rgba(0,0,0,0.10); }}
    #hwd-panel {{
      position:fixed; top:83px; left:43px; bottom:0; width:300px;
      background:#ffffff; border-right:1px solid #e0e0e0;
      box-shadow:2px 0 8px rgba(0,0,0,0.08);
      z-index:8499;
      display:none; flex-direction:column;
      font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", "맑은 고딕", sans-serif;
    }}
    #hwd-panel.open {{ display:flex; }}
    /* 패널 상단 바 — 위젯 검색 + 닫기 버튼 (이미지 1 native dock 참조) */
    #hwd-panel-topbar {{
      display:flex; align-items:center; gap:6px;
      padding:6px 8px; flex-shrink:0;
      background:#fafafa; border-bottom:1px solid #ececef;
    }}
    /* 검색 입력 래퍼 — 좌측 돋보기 아이콘 + 우측 초기화(X) 버튼을 input 안에 오버레이 */
    #hwd-panel-search-wrap {{
      flex:1; min-width:0; position:relative;
      display:flex; align-items:center;
    }}
    #hwd-panel-search-icon {{
      position:absolute; left:9px; pointer-events:none;
      display:flex; align-items:center; color:#999;
    }}
    #hwd-panel-search {{
      flex:1; min-width:0;
      border:1px solid #d8d8de; border-radius:6px;
      padding:5px 26px 5px 28px; font-size:13px; color:#333;
      outline:none; background:#fff;
      font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", "맑은 고딕", sans-serif;
    }}
    #hwd-panel-search:focus {{ border-color:#F47B20; }}
    #hwd-panel-search::placeholder {{ color:#aaa; }}
    /* 검색어 초기화 버튼 — 회색 원형, 입력값 있을 때만 표시 */
    #hwd-panel-search-clear {{
      position:absolute; right:6px;
      width:16px; height:16px; padding:0;
      border:none; border-radius:50%; cursor:pointer;
      background:#c4c4ca; color:#fff;
      display:none; align-items:center; justify-content:center;
      transition:background .12s;
    }}
    #hwd-panel-search-clear.show {{ display:flex; }}
    #hwd-panel-search-clear:hover {{ background:#9a9aa1; }}
    #hwd-panel-close {{
      width:28px; height:28px; flex-shrink:0;
      border:none; background:transparent; cursor:pointer;
      color:#888; border-radius:5px;
      display:flex; align-items:center; justify-content:center;
      transition:background .12s, color .12s;
    }}
    #hwd-panel-close:hover {{ background:rgba(0,0,0,0.08); color:#222; }}
    /* 검색 결과 없음 안내 메시지 */
    #hwd-panel-noresult {{
      display:none;
      padding:9px 14px; font-size:12.5px; color:#9a7b63;
      background:#fdf3ea; border-bottom:1px solid #f0e0d2;
    }}
    #hwd-panel-noresult.show {{ display:block; }}
    #hwd-panel-header {{
      padding:6px 14px; font-weight:700; color:#1a1a1c;
      font-size:13.5px; border-bottom:1px solid #ececef;
      display:flex; align-items:center; gap:10px;
      background:#fafafa; flex-shrink:0;
      transition:background-color .15s;
    }}
    /* 카테고리 색 배경 — JS에서 background-color 인라인 스타일로 설정 */
    .hwd-panel-color-dot {{
      width:10px; height:10px; border-radius:50%; flex-shrink:0;
      border:1px solid rgba(0,0,0,0.10);
    }}
    /* 단계 3E: 헤더 좌측에 카테고리 SVG 아이콘 (이미지 2 native dock 스타일) */
    .hwd-panel-header-icon {{
      width:20px; height:20px; flex-shrink:0;
      display:block; object-fit:contain;
    }}
    .hwd-panel-title {{
      flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
    }}
    /* 보기 전환 버튼 (list ↔ grid) */
    .hwd-view-toggle-btn {{
      background:transparent; border:none; cursor:pointer;
      padding:8px 10px; border-radius:4px; margin:0 4px;
      display:flex; align-items:center; justify-content:center;
      color:#444; flex-shrink:0;
      transition:background .1s, color .1s;
      min-width:32px; min-height:32px;
    }}
    .hwd-view-toggle-btn:hover {{ background:rgba(0,0,0,0.10); color:#000; }}
    #hwd-panel-body {{
      flex:1; overflow-y:auto; padding:4px 0;
    }}
    /* ── 단계 3D: grid 보기 모드 (아이콘+텍스트 격자) ── */
    /* grid-auto-rows 로 모든 행 동일 높이 → 메뉴마다 간격 차이 제거.
       row-gap 0, column-gap 2px 로 세로 공백 최소화. */
    #hwd-panel-body.view-grid {{
      display:grid; grid-template-columns:repeat(4, 1fr);
      grid-auto-rows:62px;
      row-gap:0; column-gap:2px;
      padding:4px 4px;
      align-content:start;  /* 위젯 적어도 위쪽부터 채움 */
    }}
    #hwd-panel-body.view-grid .hwd-widget {{
      flex-direction:column; align-items:center; justify-content:flex-start;
      text-align:center;
      padding:5px 3px 3px; gap:2px;
      height:100%; box-sizing:border-box;
      border-radius:4px;
    }}
    #hwd-panel-body.view-grid .hwd-widget img,
    #hwd-panel-body.view-grid .hwd-widget .hwd-widget-iconbox {{
      width:28px; height:28px;
    }}
    #hwd-panel-body.view-grid .hwd-widget-name {{
      font-size:10.5px; line-height:1.15;
      white-space:normal; overflow:hidden;
      display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical;
      flex:none; width:100%;
      word-break:keep-all; overflow-wrap:break-word;
    }}
    #hwd-panel-body::-webkit-scrollbar {{ width:6px; }}
    #hwd-panel-body::-webkit-scrollbar-thumb {{ background:rgba(0,0,0,0.18); border-radius:3px; }}

    /* ── 모든 카테고리 누적 표시 모드 (Orange3 native dock 스타일, 이미지 2 참조) ──
       클릭한 카테고리뿐 아니라 모든 카테고리가 섹션으로 쌓여서 표시됨. 사이드바 클릭 시 해당 섹션으로 스크롤. */
    .hwd-cat-section {{ }}
    .hwd-cat-section-header {{
      display:flex; align-items:stretch; gap:0;
      font-size:13.5px; font-weight:400; color:#1a1a1c;
      position:sticky; top:0; z-index:2;
      background:#ffffff;  /* 헤더 전체는 흰색 — 아이콘만 카테고리 색 */
      cursor:pointer;       /* 클릭으로 접기/펼치기 */
      border-bottom:1px solid rgba(0,0,0,0.05);
      user-select:none;
      /* row 높이 고정 (2026-05-24) — 사이드바 .hwd-cat 와 1:1 정렬 기준점 */
      height:33px; box-sizing:border-box;
    }}
    /* 아이콘 박스 — 카테고리 색 배경(--cat-color), fixed-width */
    .hwd-section-icon-box {{
      display:flex; align-items:center; justify-content:center;
      width:42px; flex-shrink:0;
      background:var(--cat-color, #e8e8eb);
    }}
    .hwd-section-icon-box img {{
      width:22px; height:22px; object-fit:contain;
    }}
    /* 타이틀 — 펼쳐진 상태일 때만 카테고리 색, 접힌 상태일 때는 흰색.
       padding 축소(8→4) — 사이드바(.hwd-cat 28px + gap 4px = 32px)와 줄
       높이 정렬. */
    .hwd-cat-section-title {{
      flex:1; padding:4px 12px;
      overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
      display:flex; align-items:center; gap:6px;
      background:var(--cat-color, #e8e8eb);
      transition:background .12s ease-out;
    }}
    /* 위젯 개수 (N) — 햄버거 아이콘 바로 왼쪽(우측 끝) 표시, 회색 + small.
       margin-left:auto 로 title 안에서 우측으로 push (이름은 좌측 정렬 유지). */
    .hwd-cat-section-count {{
      color:#7a7a7a; font-size:10px; font-weight:500;
      flex-shrink:0; margin-left:auto;
    }}
    /* 접힌 섹션 — title 배경 제거, grid 숨김 */
    .hwd-cat-section.is-collapsed .hwd-cat-section-title {{ background:transparent; }}
    .hwd-cat-section.is-collapsed .hwd-cat-section-grid {{ display:none; }}
    /* hover hint for clickable header */
    .hwd-cat-section.is-collapsed .hwd-cat-section-header:hover .hwd-cat-section-title {{
      background:rgba(0,0,0,0.04);
    }}
    /* 비활성화(접힘) 섹션의 햄버거 버튼은 시각적으로 흐리게 표시.
       (실제 동작은 JS 핸들러에서 처리 — 접힌 섹션 햄버거 클릭 시 그 섹션을 활성화) */
    .hwd-cat-section.is-collapsed .hwd-section-view-toggle {{
      opacity:0.35;
    }}
    .hwd-cat-section.is-collapsed .hwd-section-view-toggle:hover {{
      opacity:0.7;
    }}

    /* 리스트 모드도 그리드 모드와 동일하게 아코디언 동작 — 접힌 섹션은 그대로 닫힌 상태 유지.
       (이전: 모든 섹션의 title 이 카테고리 색이 되었지만, 사용자 요청으로 펼친 섹션만 색 표시) */
    .hwd-cat-section-grid {{
      display:grid; grid-template-columns:repeat(4, 1fr);
      grid-auto-rows:62px;
      row-gap:0; column-gap:2px;
      padding:4px 4px 10px;
      align-content:start;
    }}
    .hwd-cat-section-grid .hwd-widget {{
      flex-direction:column; align-items:center; justify-content:flex-start;
      text-align:center;
      padding:5px 3px 3px; gap:2px;
      height:100%; box-sizing:border-box;
      border-radius:4px;
    }}
    .hwd-cat-section-grid .hwd-widget img,
    .hwd-cat-section-grid .hwd-widget .hwd-widget-iconbox {{
      width:28px; height:28px;
    }}
    .hwd-cat-section-grid .hwd-widget-name {{
      font-size:10.5px; line-height:1.15;
      white-space:normal; overflow:hidden;
      display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical;
      flex:none; width:100%;
      word-break:keep-all; overflow-wrap:break-word;
    }}
    /* 클릭된 활성 섹션 미세 하이라이트 (사용자 컨텍스트 인식) */
    .hwd-cat-section.is-active .hwd-cat-section-header {{
      box-shadow:inset 3px 0 0 #F47B20;
    }}

    /* ── 리스트 보기 모드 — 위젯 카드를 세로 행으로 표시 (이미지 1 햄버거 토글) ──
       #hwd-panel-body.view-list 클래스가 켜지면 펼친 섹션의 grid 가 list 로 전환됨.
       :not(.is-collapsed) 로 한정 — 접힌 섹션은 그대로 display:none 유지 (아코디언).
       선호는 localStorage 'hwd-view-mode' 에 저장 (기본값 grid). */
    #hwd-panel-body.view-list .hwd-cat-section:not(.is-collapsed) .hwd-cat-section-grid {{
      display:flex; flex-direction:column;
      padding:2px 0 6px;
      grid-auto-rows:auto; row-gap:0; column-gap:0;
    }}
    #hwd-panel-body.view-list .hwd-cat-section:not(.is-collapsed) .hwd-cat-section-grid .hwd-widget {{
      flex-direction:row; align-items:center; justify-content:flex-start;
      text-align:left; gap:10px;
      padding:7px 12px; height:auto;
      border-radius:0;
    }}
    #hwd-panel-body.view-list .hwd-cat-section:not(.is-collapsed) .hwd-cat-section-grid .hwd-widget img,
    #hwd-panel-body.view-list .hwd-cat-section:not(.is-collapsed) .hwd-cat-section-grid .hwd-widget .hwd-widget-iconbox {{
      width:22px; height:22px; flex-shrink:0;
    }}
    #hwd-panel-body.view-list .hwd-cat-section:not(.is-collapsed) .hwd-cat-section-grid .hwd-widget-name {{
      font-size:13px; line-height:1.3; flex:1;
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      display:block; -webkit-line-clamp:1; width:auto;
    }}
    .hwd-widget {{
      display:flex; align-items:center; gap:10px;
      padding:7px 12px; cursor:pointer; user-select:none;
      font-size:13px; color:#333;
      transition:background .08s;
    }}
    .hwd-widget:hover {{ background:#f3f4f6; }}
    .hwd-widget img, .hwd-widget .hwd-widget-iconbox {{
      width:22px; height:22px; flex-shrink:0; border-radius:3px;
    }}
    .hwd-widget-name {{
      flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
    }}
    /* admin 에서 비활성화된 위젯 (2026-05-24) — 회색 톤 + 클릭/드래그 차단 */
    .hwd-widget.is-disabled {{
      cursor:not-allowed;
      opacity:0.45;
    }}
    .hwd-widget.is-disabled:hover {{ background:transparent; }}
    .hwd-widget.is-disabled img,
    .hwd-widget.is-disabled .hwd-widget-iconbox {{
      filter:grayscale(100%);
    }}
    .hwd-widget.is-disabled .hwd-widget-name {{
      color:#9ca3af; font-style:italic;
    }}

    /* ── 단계 3C: 위젯 드래그-드롭 zone ── */
    /* 평소엔 pointer-events:none + 투명 → 캔버스 클릭 통과
       드래그 시작 시 .active 클래스 부여 → pointer-events:auto + iframe 위에 떠서 drop 캡처 */
    #hwd-drop-zone {{
      position:fixed; top:83px; left:43px; right:0; bottom:0;
      pointer-events:none; z-index:8600;
      background:transparent;
    }}
    #hwd-drop-zone.active {{ pointer-events:auto; }}
    #hwd-drop-zone.over {{
      outline:2px dashed rgba(244,123,32,0.5);
      outline-offset:-6px;
      background:rgba(244,123,32,0.04);
    }}
    .hwd-widget {{ /* 드래그 시 잡을 수 있도록 cursor 보강 */
      -webkit-user-drag:element;
    }}
    .hwd-widget:active {{ opacity:0.6; }}

    /* ── 리사이즈 중 왼쪽 위젯 독·상단 시각 안정화 마스크 ──
       Orange3의 왼쪽 위젯 독(카테고리 아이콘 사이드바, 컴팩트 모드 ~60px)이 viewport 스케일링과
       함께 움직여 사용자에게 시각적 혼란을 주는 문제. 리사이즈 진행 중에만 해당 영역을 위젯 독
       배경과 동일한 색으로 덮어 "메뉴 위치 변동"이 보이지 않게 함. 너비를 위젯 독에 정확히
       맞춰(60px) 마스크 vs 진짜 위젯 독의 시각 차이 최소화. */
    #resize-mask-left {{
      position:fixed;
      top:83px; left:0; bottom:0; width:43px;  /* HTML 사이드바 너비와 일치 */
      background:#ffffff;
      border-right:1px solid #e0e0e0;
      z-index:8200;
      opacity:0; pointer-events:none;
      transition:opacity 0.08s ease-in;
    }}
    #resize-mask-left.active {{ opacity:1; }}
    /* 상단 그라데이션 마스크 — HTML 사이드바(43px)부터 우측 끝까지 */
    #resize-mask-top {{
      position:fixed;
      top:83px; left:43px; right:0; height:30px;
      background:linear-gradient(to bottom, #f7f8fa 0%, rgba(247,248,250,0) 100%);
      z-index:8200;
      opacity:0; pointer-events:none;
      transition:opacity 0.08s ease-in;
    }}
    #resize-mask-top.active {{ opacity:1; }}

    /* ── VNC 로딩 커튼 (3단계 패턴) ── */
    #vnc-cover {{
      position:fixed; inset:0;
      background:#fafafa; z-index:99999; pointer-events:all;
      transition:opacity 0.55s cubic-bezier(0.4,0,0.2,1);
      display:flex; flex-direction:column;
    }}
    /* 로딩 커튼 — 헤더·탭바·캔버스 3개 영역을 단일 색(#fafafa)으로 통일.
       기존엔 영역별 배경색·경계선이 달라 로딩 화면에 3단 구분선이 보였음 (2026-05-22). */
    .sk-header {{
      height:52px; flex-shrink:0;
      background:#fafafa;
    }}
    .sk-tabbar {{
      height:31px; flex-shrink:0; padding:4px 14px 0 14px;
      background:#fafafa;
      display:flex; align-items:flex-end; gap:4px;
    }}
    .sk-tab, .sk-tab-inactive {{
      height:26px; border-radius:7px 7px 0 0;
      background:linear-gradient(90deg, #f0f0f0 25%, #e4e4e4 50%, #f0f0f0 75%);
      background-size:200% 100%;
      animation:sk-shimmer 1.4s linear infinite;
    }}
    .sk-tab          {{ width:160px; }}
    .sk-tab-inactive {{ width:120px; opacity:0.55; }}
    @keyframes sk-shimmer {{
      0%   {{ background-position:200% 0; }}
      100% {{ background-position:-200% 0; }}
    }}
    .sk-canvas {{
      flex:1; display:flex; flex-direction:column;
      align-items:center; justify-content:center;
      background:#fafafa; gap:18px;
    }}
    .sk-spinner {{
      width:54px; height:54px; border-radius:50%;
      border:5px solid #f7e0c8; border-top-color:#F47B20;
      animation:sk-spin 0.85s linear infinite;
    }}
    @keyframes sk-spin {{ to {{ transform:rotate(360deg); }} }}
    .sk-label {{
      font-size:14px; color:#888; user-select:none;
      letter-spacing:0.3px;
    }}
    /* ── Splash 이미지 + 내부 텍스트 오버레이 (Phase 5, 2026-05-24) ──
       마스코트 이미지 단독 — 페이지 정중앙 자동 정렬.
       Orange 버전/addon 목록은 이미지 좌측(보라 구름 영역) 위에 absolute. */
    .sk-splash-row {{
      position:relative; display:inline-block;
    }}
    .sk-splash-wrap {{
      position:relative; display:block;
    }}
    .sk-splash-img {{
      width:560px; max-width:80vw; height:auto;
      display:block;
      user-select:none; pointer-events:none;
    }}
    /* 이미지 로드 실패 시 wrap 통째 숨김 → fallback 으로 기존 spinner 노출 */
    .sk-splash-img:not([src]),
    .sk-splash-img[src=""] {{ display:none; }}
    /* ── 이미지 위 absolute 로딩 정보 텍스트 (Phase 5, 2026-05-24) ──
       Orange 버전 + addon 목록. splash-wrap 안에 absolute — 이미지 좌측
       (보라 구름 영역) 위에 오버레이. 보라 배경 대비 흰색 + 그림자.
       이미지 2배 확대(560px) + nowrap 으로 라인 중간 줄바꿈 차단. */
    .sk-load-info {{
      position:absolute; top:50%; left:calc(6% - 2px);
      transform:translateY(-50%);
      color:#ffffff; font-size:11px; font-weight:600;
      line-height:1.4; user-select:none; pointer-events:none;
      font-family:-apple-system,"Malgun Gothic",sans-serif;
      text-shadow:0 1px 3px rgba(0,0,0,0.35);
      white-space:nowrap;
    }}
    .sk-load-info > * {{ white-space:nowrap; }}
    .sk-load-info .sk-load-app {{
      font-size:12px; color:#ffffff; font-weight:700;
      letter-spacing:0.2px;
    }}
    .sk-load-info .sk-load-ver {{
      font-size:10px; color:rgba(255,255,255,0.92);
      margin-top:1px; font-weight:500;
    }}

    /* ── 캔버스 우상단 툴바 (T·펜·일시정지·새탭) ── */
    #canvas-toolbar {{
      position:fixed; top:91px; right:12px; z-index:8400;
      display:flex; align-items:center; gap:1px;
      background:#ffffff; border:1px solid rgba(0,0,0,0.13);
      border-radius:12px; padding:5px 8px;
      box-shadow:0 2px 12px rgba(0,0,0,0.15);
      font-size:16px; color:#555; user-select:none;
    }}
    #canvas-toolbar .ct-btn {{
      display:flex; align-items:center; justify-content:center;
      padding:6px 10px; border-radius:8px; border:none;
      background:transparent; color:#555; cursor:pointer;
      font-size:13px; transition:background .12s; white-space:nowrap; line-height:1;
      /* 헤더 .h-btn (이미지 1) 폰트 매칭: 13px text + 6px padding ≈ 30px */
    }}
    #canvas-toolbar .ct-btn:hover {{ background:rgba(0,0,0,0.07); }}
    #canvas-toolbar .ct-btn.sb-active {{ background:rgba(244,123,32,0.15); color:#F47B20; }}
    #canvas-toolbar .ct-sep {{ width:1px; height:20px; background:rgba(0,0,0,0.12); margin:0 3px; flex-shrink:0; }}

    /* ── 펜 버튼 롱프레스 색상 드롭다운 (아래쪽) ── */
    #ct-color-drop {{
      display:none; position:absolute; top:calc(100% + 6px); left:50%;
      transform:translateX(-50%);
      background:#ffffff; border:1px solid rgba(0,0,0,0.13);
      border-radius:10px; overflow:hidden;
      box-shadow:0 4px 18px rgba(0,0,0,0.15); z-index:9700;
      padding:8px 0;
    }}
    #ct-color-drop.open {{ display:flex; flex-direction:column; align-items:center; gap:6px; }}
    .ct-color-item {{
      width:22px; height:22px; border-radius:50%; cursor:pointer;
      box-sizing:border-box; border:2px solid transparent;
      transition:transform .1s;
    }}
    .ct-color-item:hover {{ transform:scale(1.15); }}
    .ct-color-item.sel {{
      border-color:#888;
      box-shadow:0 0 0 2px #fff inset;
    }}

    /* ── 저장 확인 모달 (이미지 2 스타일) ── */
    #save-confirm-overlay {{
      display:none; position:fixed; inset:0;
      background:rgba(0,0,0,0.45); backdrop-filter:blur(2px);
      z-index:10001; justify-content:center; align-items:center;
      font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", "맑은 고딕", sans-serif;
    }}
    #save-confirm-overlay.open {{ display:flex; }}
    #save-confirm-modal {{
      background:#ffffff; border-radius:12px;
      width:460px; max-width:92vw;
      box-shadow:0 24px 60px rgba(0,0,0,0.35);
      overflow:hidden;
    }}
    .sc-header {{
      display:flex; align-items:center; justify-content:space-between;
      padding:18px 22px 4px;
    }}
    .sc-title-text {{ font-size:16px; font-weight:700; color:#1f1f23; letter-spacing:-0.2px; }}
    .sc-close-btn {{
      width:28px; height:28px; border:none; background:transparent;
      cursor:pointer; border-radius:6px; color:#9ca3af;
      font-size:18px; line-height:1;
      display:flex; align-items:center; justify-content:center;
      transition:background .1s, color .1s;
    }}
    .sc-close-btn:hover {{ background:#f3f4f6; color:#1f1f23; }}
    .sc-body {{
      padding:6px 22px 4px;
      font-size:14px; color:#1f1f23; line-height:1.55;
    }}
    .sc-body .sc-wf-quote {{ color:#1f1f23; font-weight:500; }}
    .sc-body .sc-warn {{
      font-size:12.5px; color:#9ca3af; margin-top:6px;
    }}
    .sc-footer {{
      display:flex; justify-content:flex-end; gap:6px;
      padding:18px 22px 20px;
    }}
    .sc-btn {{
      padding:7px 16px; border-radius:6px;
      font-size:13px; font-weight:500;
      cursor:pointer; border:1px solid #d1d5db;
      background:#ffffff; color:#1f1f23;
      font-family:inherit;
      transition:background .1s, border-color .1s;
    }}
    .sc-btn:hover {{ background:#f3f4f6; }}
    .sc-btn-primary {{ font-weight:700; }}

    /* ── Workflow Info 모달 (Datasets 모달 스타일) ── */
    #wf-info-overlay {{
      display:none; position:fixed; inset:0;
      background:rgba(0,0,0,0.45); backdrop-filter:blur(2px);
      z-index:10000; justify-content:center; align-items:center;
      font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", "맑은 고딕", sans-serif;
    }}
    #wf-info-overlay.open {{ display:flex; }}
    #wf-info-modal {{
      background:#ffffff; border-radius:12px;
      width:500px; max-width:92vw; max-height:88vh;
      display:flex; flex-direction:column;
      box-shadow:0 24px 60px rgba(0,0,0,0.35);
      overflow:hidden;
    }}
    .wf-header {{
      display:flex; align-items:center; justify-content:space-between;
      padding:14px 18px; border-bottom:1px solid #e5e7eb;
      background:#ffffff;
    }}
    .wf-title-text {{ font-size:16px; font-weight:700; color:#1f1f23; }}
    .wf-close-btn {{
      width:30px; height:30px; border:none; background:transparent;
      cursor:pointer; border-radius:6px; color:#6b7280;
      font-size:18px; line-height:1;
      display:flex; align-items:center; justify-content:center;
      transition:background .1s;
    }}
    .wf-close-btn:hover {{ background:#f3f4f6; color:#1f1f23; }}
    .wf-body {{
      padding:18px; flex:1; overflow-y:auto;
      display:flex; flex-direction:column; gap:16px;
      background:#ffffff;
    }}
    .wf-field-label {{
      font-size:13px; font-weight:600; color:#374151;
      margin-bottom:6px; display:block;
    }}
    .wf-input {{
      width:100%; padding:9px 11px;
      border:1px solid #d1d5db; border-radius:6px;
      font-size:13.5px; outline:none; color:#1f1f23;
      font-family:inherit; background:#ffffff;
      transition:border-color .1s, box-shadow .1s;
    }}
    .wf-input:focus {{
      border-color:#2563eb;
      box-shadow:0 0 0 3px rgba(37,99,235,0.12);
    }}
    .wf-textarea {{
      width:100%; padding:9px 11px;
      border:1px solid #d1d5db; border-radius:6px;
      font-size:13.5px; outline:none; color:#1f1f23;
      font-family:inherit; background:#ffffff;
      resize:vertical; min-height:130px;
      transition:border-color .1s, box-shadow .1s;
    }}
    .wf-textarea:focus {{
      border-color:#2563eb;
      box-shadow:0 0 0 3px rgba(37,99,235,0.12);
    }}
    .wf-check-row {{
      display:flex; align-items:center; gap:8px;
      font-size:12.5px; color:#4b5563; cursor:pointer;
      user-select:none;
    }}
    .wf-check-row input[type="checkbox"] {{
      width:14px; height:14px; cursor:pointer; accent-color:#2563eb;
    }}
    .wf-footer {{
      display:flex; justify-content:flex-end; align-items:center;
      padding:12px 18px; border-top:1px solid #e5e7eb;
      background:#fafafa;
    }}
    .wf-footer-info {{ font-size:11px; color:#9ca3af; }}
    .wf-btn-group {{ display:flex; gap:8px; }}
    .wf-btn {{
      padding:7px 18px; border-radius:6px;
      font-size:12.5px; font-weight:600; cursor:pointer;
      border:1px solid transparent;
      font-family:inherit;
      transition:background .1s, border-color .1s;
    }}
    .wf-btn-cancel {{ background:#ffffff; border-color:#d1d5db; color:#4b5563; }}
    .wf-btn-cancel:hover {{ background:#f3f4f6; }}
    .wf-btn-ok {{ background:#2563eb; color:#ffffff; }}
    .wf-btn-ok:hover {{ background:#1d4ed8; }}

    /* ── T 버튼 롱프레스 폰트 크기 드롭다운 (아래쪽) ── */
    #canvas-toolbar .ct-grp {{ position:relative; }}
    #ct-font-drop {{
      display:none; position:absolute; top:calc(100% + 6px); left:0;
      background:#ffffff; border:1px solid rgba(0,0,0,0.13);
      border-radius:10px; overflow:hidden; min-width:84px;
      box-shadow:0 4px 18px rgba(0,0,0,0.15); z-index:9700;
      padding:4px 0;
    }}
    #ct-font-drop.open {{ display:block; }}
    .ct-font-item {{
      display:flex; align-items:center; gap:8px;
      padding:4px 16px 4px 10px; color:#333; cursor:pointer;
      transition:background .1s; line-height:1.3; user-select:none;
      font-family:Georgia, "Times New Roman", serif;
    }}
    .ct-font-item:hover {{ background:rgba(244,123,32,0.10); }}
    .ct-font-item.sel {{ color:#F47B20; }}
    .ct-font-dot {{
      width:6px; height:6px; border-radius:50%;
      background:currentColor; opacity:0; flex-shrink:0;
    }}
    .ct-font-item.sel .ct-font-dot {{ opacity:1; }}

    /* ── 좌하단 상태바 ── */
    #sb-wrap {{
      position:fixed; bottom:12px; right:11px; z-index:8400;
      display:flex; align-items:center; gap:1px;
      background:#ffffff; border:1px solid rgba(0,0,0,0.13);
      border-radius:12px; padding:5px 8px;
      box-shadow:0 2px 12px rgba(0,0,0,0.15);
      font-size:16px; color:#555; user-select:none;
    }}
    .sb-btn {{
      display:flex; align-items:center; justify-content:center; gap:5px;
      padding:6px 10px; border-radius:8px; border:none;
      background:transparent; color:#555; cursor:pointer;
      font-size:16px; transition:background .12s; white-space:nowrap; line-height:1;
    }}
    .sb-btn:hover {{ background:rgba(0,0,0,0.07); }}
    .sb-btn.sb-active {{ background:rgba(244,123,32,0.15); color:#F47B20; }}
    .sb-sep {{ width:1px; height:24px; background:rgba(0,0,0,0.12); margin:0 3px; flex-shrink:0; }}
    .sb-grp {{ position:relative; }}
    .sb-drop {{
      display:none; position:absolute; bottom:calc(100% + 7px); right:0;
      background:#ffffff; border:1px solid rgba(0,0,0,0.13);
      border-radius:10px; overflow:hidden; min-width:200px;
      box-shadow:0 4px 18px rgba(0,0,0,0.15); z-index:9600;
    }}
    .sb-drop.sb-open {{ display:block; }}
    .sb-di {{
      display:flex; align-items:center; justify-content:space-between;
      padding:9px 14px; font-size:15px; color:#333; cursor:pointer; gap:14px;
      transition:background .1s;
    }}
    .sb-di:hover {{ background:rgba(0,0,0,0.05); }}
    .sb-di .ico {{ display:flex; align-items:center; gap:8px; }}
    .sb-key {{ color:#999; font-size:13px; }}
    .sb-zoom-row {{
      display:flex; align-items:center; gap:8px;
      padding:7px 14px; border-top:1px solid rgba(0,0,0,0.08);
    }}
    .sb-zoom-row input {{
      width:60px; background:#f5f5f5;
      border:1px solid rgba(0,0,0,0.15); border-radius:5px;
      color:#333; font-size:15px; padding:4px 7px; outline:none; text-align:right;
    }}
    /* 한글 입력 도우미 (2026-05-22) — 캔버스 IME 보조 입력창 */
    #sb-ime-panel {{
      display:none; flex-direction:column; position:fixed; bottom:55px; right:11px;
      width:300px; background:#ffffff; border:1px solid #ddd;
      border-radius:8px; overflow:hidden; z-index:8350;
      box-shadow:0 4px 18px rgba(0,0,0,0.18);
    }}
    #sb-ime-header {{
      display:flex; align-items:center; justify-content:space-between;
      height:30px; padding:0 8px 0 12px; flex-shrink:0;
      background:#F47B20; color:#fff; font-size:12.5px; font-weight:600;
    }}
    #sb-ime-close {{
      width:20px; height:20px; border-radius:4px; cursor:pointer;
      display:flex; align-items:center; justify-content:center; line-height:1;
    }}
    #sb-ime-close:hover {{ background:rgba(255,255,255,0.25); }}
    #sb-ime-body {{ padding:10px 12px; display:flex; flex-direction:column; gap:8px; }}
    #sb-ime-hint {{ font-size:11px; color:#888; line-height:1.5; }}
    #sb-ime-input {{
      width:100%; padding:7px 9px; font-size:14px;
      border:1px solid #ccc; border-radius:6px; outline:none; font-family:inherit;
    }}
    #sb-ime-input:focus {{ border-color:#F47B20; box-shadow:0 0 0 3px rgba(244,123,32,0.12); }}
    /* 미니맵 */
    #sb-minimap {{
      display:flex; flex-direction:column; position:fixed; bottom:55px; right:11px;
      width:280px;
      background:#f5f5f5; border:1px solid #ddd;
      border-radius:8px; overflow:hidden; z-index:8300;
      box-shadow:0 4px 18px rgba(0,0,0,0.18);
    }}
    #sb-minimap-header {{
      display:flex; align-items:center; justify-content:space-between;
      height:28px; padding:0 8px 0 10px; flex-shrink:0;
      background:#ebebeb;
      border-bottom:1px solid #ddd;
    }}
    #sb-minimap-label {{
      font-size:12px; color:#555; user-select:none;
      display:flex; align-items:center; gap:5px;
    }}
    #sb-minimap-close {{
      width:20px; height:20px; border-radius:4px;
      display:flex; align-items:center; justify-content:center;
      font-size:13px; color:#777; cursor:pointer;
      background:transparent; transition:background .12s, color .12s;
      line-height:1; user-select:none;
    }}
    #sb-minimap-close:hover {{ background:rgba(0,0,0,0.10); color:#333; }}
    #sb-minimap-body {{
      position:relative; width:280px; height:158px; overflow:hidden; flex-shrink:0;
      background:#ffffff;
    }}
    #sb-minimap-body img {{
      width:280px; height:158px; display:block; object-fit:cover;
    }}
    #sb-minimap-disc {{
      display:none; position:absolute; top:0; left:0; right:0; bottom:0; z-index:10;
      align-items:center; justify-content:center;
      background:rgba(245,245,245,0.90);
      color:#777; font-size:11px; text-align:center; line-height:1.6;
    }}
    #sb-minimap-overlay {{
      position:absolute; top:0; left:0; right:0; bottom:0;
      z-index:2; cursor:grab;
    }}
    #sb-minimap-overlay.dragging {{
      cursor:grabbing;
    }}
    #sb-vp-rect {{
      position:absolute; pointer-events:none; box-sizing:border-box;
      border:2px solid rgba(80,195,255,0.95);
      background:rgba(80,195,255,0.18);
      box-shadow:0 0 0 1px rgba(0,100,200,0.45);
    }}
    /* 패닝 오버레이 */
    #pan-overlay {{
      display:none; position:fixed; top:83px; left:0; right:0; bottom:0;
      z-index:151; cursor:grab;
    }}
    #pan-overlay.panning {{ cursor:grabbing; }}
    /* ── 탭 닫기 확인 모달 ── */
    #close-modal {{
      display:none; position:fixed; inset:0; z-index:99997;
      background:rgba(0,0,0,0.35);
      align-items:center; justify-content:center;
    }}
    #close-modal.open {{ display:flex; }}
    #close-modal-box {{
      background:#fff; border-radius:12px; padding:28px 32px;
      min-width:400px; max-width:560px;
      box-shadow:0 8px 40px rgba(0,0,0,0.18);
    }}
    #close-modal-header {{
      display:flex; justify-content:space-between; align-items:center;
      margin-bottom:14px;
    }}
    #close-modal-title {{
      font-size:18px; font-weight:700; color:#111;
    }}
    #close-modal-x {{
      font-size:20px; color:#888; cursor:pointer; line-height:1;
      width:28px; height:28px; display:flex; align-items:center; justify-content:center;
      border-radius:6px; transition:background .12s;
    }}
    #close-modal-x:hover {{ background:#f0f0f0; color:#333; }}
    #close-modal-body {{
      font-size:14px; color:#444; margin-bottom:10px; line-height:1.5;
    }}
    #close-modal-files {{
      font-size:14px; color:#444; margin:8px 0 6px 4px;
    }}
    #close-modal-hint {{
      font-size:12px; color:#888; margin-bottom:24px;
      display:flex; align-items:center; gap:5px;
    }}
    #close-modal-btns {{
      display:flex; justify-content:flex-end; gap:8px;
    }}
    .cm-btn {{
      padding:8px 18px; border-radius:8px; font-size:14px; cursor:pointer;
      border:1px solid #e0e0e0; background:#f5f5f5; color:#333;
      display:flex; align-items:center; gap:6px;
      transition:background .12s; white-space:nowrap;
    }}
    .cm-btn:hover {{ background:#e4e4e4; }}
    .cm-btn.cm-save {{ background:#fff; border-color:#d0d0d0; }}
    .cm-btn.cm-save:hover {{ background:#f8f8f8; }}
    #toast {{
      display:none; position:fixed; bottom:24px; left:50%;
      transform:translateX(-50%); z-index:9999;
      background:#2d2d44; color:#fff; font-size:13px;
      padding:10px 20px; border-radius:8px;
      box-shadow:0 4px 16px rgba(0,0,0,0.5);
      border-left:4px solid #F47B20; white-space:nowrap;
    }}
  </style>
</head>
<body>

  <!-- ── 헤더 바 ── -->
  <div id="header-bar">

    <!-- 로고 -->
    <div id="logo">
      <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAkACQAAD/4hAISUNDX1BST0ZJTEUAAQEAAA/4YXBwbAIQAABtbnRyUkdCIFhZWiAH5gADAAoABgARABBhY3NwQVBQTAAAAABBUFBMAAAAAAAAAAAAAAAAAAAAAAAA9tYAAQAAAADTLWFwcGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJkZXNjAAABXAAAAGJkc2NtAAABwAAABJxjcHJ0AAAGXAAAACN3dHB0AAAGgAAAABRyWFlaAAAGlAAAABRnWFlaAAAGqAAAABRiWFlaAAAGvAAAABRyVFJDAAAG0AAACAxhYXJnAAAO3AAAACB2Y2d0AAAO/AAAADBuZGluAAAPLAAAAD5jaGFkAAAPbAAAACxtbW9kAAAPmAAAACh2Y2dwAAAPwAAAADhiVFJDAAAG0AAACAxnVFJDAAAG0AAACAxhYWJnAAAO3AAAACBhYWdnAAAO3AAAACBkZXNjAAAAAAAAAAhEaXNwbGF5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbWx1YwAAAAAAAAAmAAAADGhySFIAAAAUAAAB2GtvS1IAAAAMAAAB7G5iTk8AAAASAAAB+GlkAAAAAAASAAACCmh1SFUAAAAUAAACHGNzQ1oAAAAWAAACMGRhREsAAAAcAAACRm5sTkwAAAAWAAACYmZpRkkAAAAQAAACeGl0SVQAAAAYAAACiGVzRVMAAAAWAAACoHJvUk8AAAASAAACtmZyQ0EAAAAWAAACyGFyAAAAAAAUAAAC3nVrVUEAAAAcAAAC8mhlSUwAAAAWAAADDnpoVFcAAAAKAAADJHZpVk4AAAAOAAADLnNrU0sAAAAWAAADPHpoQ04AAAAKAAADJHJ1UlUAAAAkAAADUmVuR0IAAAAUAAADdmZyRlIAAAAWAAADim1zAAAAAAASAAADoGhpSU4AAAASAAADsnRoVEgAAAAMAAADxGNhRVMAAAAYAAAD0GVuQVUAAAAUAAADdmVzWEwAAAASAAACtmRlREUAAAAQAAAD6GVuVVMAAAASAAAD+HB0QlIAAAAYAAAECnBsUEwAAAASAAAEImVsR1IAAAAiAAAENHN2U0UAAAAQAAAEVnRyVFIAAAAUAAAEZnB0UFQAAAAWAAAEemphSlAAAAAMAAAEkABMAEMARAAgAHUAIABiAG8AagBpzuy37AAgAEwAQwBEAEYAYQByAGcAZQAtAEwAQwBEAEwAQwBEACAAVwBhAHIAbgBhAFMAegDtAG4AZQBzACAATABDAEQAQgBhAHIAZQB2AG4A/QAgAEwAQwBEAEwAQwBEAC0AZgBhAHIAdgBlAHMAawDmAHIAbQBLAGwAZQB1AHIAZQBuAC0ATABDAEQAVgDkAHIAaQAtAEwAQwBEAEwAQwBEACAAYQAgAGMAbwBsAG8AcgBpAEwAQwBEACAAYQAgAGMAbwBsAG8AcgBMAEMARAAgAGMAbwBsAG8AcgBBAEMATAAgAGMAbwB1AGwAZQB1AHIgDwBMAEMARAAgBkUGRAZIBkYGKQQaBD4EOwRMBD4EQAQ+BDIEOAQ5ACAATABDAEQgDwBMAEMARAAgBeYF0QXiBdUF4AXZX2mCcgBMAEMARABMAEMARAAgAE0A4AB1AEYAYQByAGUAYgBuAP0AIABMAEMARAQmBDIENQRCBD0EPgQ5ACAEFgQaAC0ENAQ4BEEEPwQ7BDUEOQBDAG8AbABvAHUAcgAgAEwAQwBEAEwAQwBEACAAYwBvAHUAbABlAHUAcgBXAGEAcgBuAGEAIABMAEMARAkwCQIJFwlACSgAIABMAEMARABMAEMARAAgDioONQBMAEMARAAgAGUAbgAgAGMAbwBsAG8AcgBGAGEAcgBiAC0ATABDAEQAQwBvAGwAbwByACAATABDAEQATABDAEQAIABDAG8AbABvAHIAaQBkAG8ASwBvAGwAbwByACAATABDAEQDiAOzA8cDwQPJA7wDtwAgA78DuAPMA70DtwAgAEwAQwBEAEYA5AByAGcALQBMAEMARABSAGUAbgBrAGwAaQAgAEwAQwBEAEwAQwBEACAAYQAgAEMAbwByAGUAczCrMOkw/ABMAEMARHRleHQAAAAAQ29weXJpZ2h0IEFwcGxlIEluYy4sIDIwMjIAAFhZWiAAAAAAAADwzwABAAAAARkRWFlaIAAAAAAAAIGdAAA8sv///7lYWVogAAAAAAAATYcAALQkAAAKzlhZWiAAAAAAAAAnsgAADyoAAMimY3VydgAAAAAAAAQAAAAABQAKAA8AFAAZAB4AIwAoAC0AMgA2ADsAQABFAEoATwBUAFkAXgBjAGgAbQByAHcAfACBAIYAiwCQAJUAmgCfAKMAqACtALIAtwC8AMEAxgDLANAA1QDbAOAA5QDrAPAA9gD7AQEBBwENARMBGQEfASUBKwEyATgBPgFFAUwBUgFZAWABZwFuAXUBfAGDAYsBkgGaAaEBqQGxAbkBwQHJAdEB2QHhAekB8gH6AgMCDAIUAh0CJgIvAjgCQQJLAlQCXQJnAnECegKEAo4CmAKiAqwCtgLBAssC1QLgAusC9QMAAwsDFgMhAy0DOANDA08DWgNmA3IDfgOKA5YDogOuA7oDxwPTA+AD7AP5BAYEEwQgBC0EOwRIBFUEYwRxBH4EjASaBKgEtgTEBNME4QTwBP4FDQUcBSsFOgVJBVgFZwV3BYYFlgWmBbUFxQXVBeUF9gYGBhYGJwY3BkgGWQZqBnsGjAadBq8GwAbRBuMG9QcHBxkHKwc9B08HYQd0B4YHmQesB78H0gflB/gICwgfCDIIRghaCG4IggiWCKoIvgjSCOcI+wkQCSUJOglPCWQJeQmPCaQJugnPCeUJ+woRCicKPQpUCmoKgQqYCq4KxQrcCvMLCwsiCzkLUQtpC4ALmAuwC8gL4Qv5DBIMKgxDDFwMdQyODKcMwAzZDPMNDQ0mDUANWg10DY4NqQ3DDd4N+A4TDi4OSQ5kDn8Omw62DtIO7g8JDyUPQQ9eD3oPlg+zD88P7BAJECYQQxBhEH4QmxC5ENcQ9RETETERTxFtEYwRqhHJEegSBxImEkUSZBKEEqMSwxLjEwMTIxNDE2MTgxOkE8UT5RQGFCcUSRRqFIsUrRTOFPAVEhU0FVYVeBWbFb0V4BYDFiYWSRZsFo8WshbWFvoXHRdBF2UXiReuF9IX9xgbGEAYZRiKGK8Y1Rj6GSAZRRlrGZEZtxndGgQaKhpRGncanhrFGuwbFBs7G2MbihuyG9ocAhwqHFIcexyjHMwc9R0eHUcdcB2ZHcMd7B4WHkAeah6UHr4e6R8THz4faR+UH78f6iAVIEEgbCCYIMQg8CEcIUghdSGhIc4h+yInIlUigiKvIt0jCiM4I2YjlCPCI/AkHyRNJHwkqyTaJQklOCVoJZclxyX3JicmVyaHJrcm6CcYJ0kneierJ9woDSg/KHEooijUKQYpOClrKZ0p0CoCKjUqaCqbKs8rAis2K2krnSvRLAUsOSxuLKIs1y0MLUEtdi2rLeEuFi5MLoIuty7uLyQvWi+RL8cv/jA1MGwwpDDbMRIxSjGCMbox8jIqMmMymzLUMw0zRjN/M7gz8TQrNGU0njTYNRM1TTWHNcI1/TY3NnI2rjbpNyQ3YDecN9c4FDhQOIw4yDkFOUI5fzm8Ofk6Njp0OrI67zstO2s7qjvoPCc8ZTykPOM9Ij1hPaE94D4gPmA+oD7gPyE/YT+iP+JAI0BkQKZA50EpQWpBrEHuQjBCckK1QvdDOkN9Q8BEA0RHRIpEzkUSRVVFmkXeRiJGZ0arRvBHNUd7R8BIBUhLSJFI10kdSWNJqUnwSjdKfUrESwxLU0uaS+JMKkxyTLpNAk1KTZNN3E4lTm5Ot08AT0lPk0/dUCdQcVC7UQZRUFGbUeZSMVJ8UsdTE1NfU6pT9lRCVI9U21UoVXVVwlYPVlxWqVb3V0RXklfgWC9YfVjLWRpZaVm4WgdaVlqmWvVbRVuVW+VcNVyGXNZdJ114XcleGl5sXr1fD19hX7NgBWBXYKpg/GFPYaJh9WJJYpxi8GNDY5dj62RAZJRk6WU9ZZJl52Y9ZpJm6Gc9Z5Nn6Wg/aJZo7GlDaZpp8WpIap9q92tPa6dr/2xXbK9tCG1gbbluEm5rbsRvHm94b9FwK3CGcOBxOnGVcfByS3KmcwFzXXO4dBR0cHTMdSh1hXXhdj52m3b4d1Z3s3gReG54zHkqeYl553pGeqV7BHtje8J8IXyBfOF9QX2hfgF+Yn7CfyN/hH/lgEeAqIEKgWuBzYIwgpKC9INXg7qEHYSAhOOFR4Wrhg6GcobXhzuHn4gEiGmIzokziZmJ/opkisqLMIuWi/yMY4zKjTGNmI3/jmaOzo82j56QBpBukNaRP5GokhGSepLjk02TtpQglIqU9JVflcmWNJaflwqXdZfgmEyYuJkkmZCZ/JpomtWbQpuvnByciZz3nWSd0p5Anq6fHZ+Ln/qgaaDYoUehtqImopajBqN2o+akVqTHpTilqaYapoum/adup+CoUqjEqTepqaocqo+rAqt1q+msXKzQrUStuK4trqGvFq+LsACwdbDqsWCx1rJLssKzOLOutCW0nLUTtYq2AbZ5tvC3aLfguFm40blKucK6O7q1uy67p7whvJu9Fb2Pvgq+hL7/v3q/9cBwwOzBZ8Hjwl/C28NYw9TEUcTOxUvFyMZGxsPHQce/yD3IvMk6ybnKOMq3yzbLtsw1zLXNNc21zjbOts83z7jQOdC60TzRvtI/0sHTRNPG1EnUy9VO1dHWVdbY11zX4Nhk2OjZbNnx2nba+9uA3AXcit0Q3ZbeHN6i3ynfr+A24L3hROHM4lPi2+Nj4+vkc+T85YTmDeaW5x/nqegy6LzpRunQ6lvq5etw6/vshu0R7ZzuKO6070DvzPBY8OXxcvH/8ozzGfOn9DT0wvVQ9d72bfb794r4Gfio+Tj5x/pX+uf7d/wH/Jj9Kf26/kv+3P9t//9wYXJhAAAAAAADAAAAAmZmAADypwAADVkAABPQAAAKW3ZjZ3QAAAAAAAAAAQABAAAAAAAAAAEAAAABAAAAAAAAAAEAAAABAAAAAAAAAAEAAG5kaW4AAAAAAAAANgAArgAAAFIAAABDwAAAsMAAACZAAAAOAAAAT0AAAFRAAAIzMwACMzMAAjMzAAAAAAAAAABzZjMyAAAAAAABDqsAAAch///ybwAACW8AAPxH///7UP///ZwAAAPUAAC+6G1tb2QAAAAAAAAGEAAAoDAAAAAA0h+zAAAAAAAAAAAAAAAAAAAAAAB2Y2dwAAAAAAADAAAAAmZmAAMAAAACZmYAAwAAAAJmZgAAAAIzMzQAAAAAAjMzNAAAAAACMzM0AP/bAEMAAwICAwICAwMDAwQDAwQFCAUFBAQFCgcHBggMCgwMCwoLCw0OEhANDhEOCwsQFhARExQVFRUMDxcYFhQYEhQVFP/bAEMBAwQEBQQFCQUFCRQNCw0UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFP/CABEIAMgAyAMBEQACEQEDEQH/xAAdAAABBAMBAQAAAAAAAAAAAAAABQYHCAEDBAIJ/8QAGwEBAAIDAQEAAAAAAAAAAAAAAAIDAQQFBgf/2gAMAwEAAhADEAAAAbUgAAAAAHFXqdk9rOcgAAAAAAAAAAAAAeMRinkeB75bD96Xruuewn1aaldvAAAAAAAAAAAAc+K4R5nh+uMNlu5vjXxRpmfqe73ZkAAAAAAAAAAABXKjzLfi2pivjzVai/1XZmQAAAAAAAAAAJ2rsoHJ6aHzt3Tr3hvsrNrVc3R0lnpaHZsUgAAAAAAHNjLfrs0Yki8DtoPn+1pqsznCdt63LfSpVTV6bd06+3Z11btcvf1ubtzhw2V9OcAAAGjCBKr4TrtSc4BQhJ4cnqL3L6Ecej4KVs6/TVZzW1rmtfKHC67Z6WixOnocMsexYjmarK56u192QB4Ki03MGMrB1ZlDGNhHjNf7MoeT68735F8/3euGdVlUd+h4Ucei4S3FYWvMiYx5IyzmAZ5fk4Wzvo9gQjCdZK7Ll05ek4ZA14yjFOZzWOF3JS8t6jOMe0Ir9X5hr9ziXKok6NmkhLGGBnQnTuyVlbqJqnAKR12PWiyzmYegNOVSLI2LsjHWrfXdOwHz/wCgbYS8ZjXX6J89sHAxbqrU219uvb0YB5K0xsZt8Lp20h8867LP69sySrAIknin9kewsprXVuujPfg/fK2rspexrV6+gfP7Ma9lYNmnsLX1ymCGQCIYW1j2K/oHbSHz6hOxurfN86g14lXGeK72wGLY6t9VtiuwngvoSlr3p9tFdPoPzy1utbU/aoGbB1TsnDOzMQhaFtc9mm/1lYU/jlM1dufeH6ZF1Ojy13YNE6kLb0kTs+Zi6WLBeH99sg8Fe/deAkzGXDxvTrmpvb4WZOqyla2+fBPb80o7WnbycQYuFHYTljzvsHtyPQbWMHLGxqdLkRH6jw0qeY9dIPF7hjGY4j7tcSJfVeQlvzHuXhzOz1yryamWb1uBE/o/H3hnW98gCutGxWmUHjodV0c3s5xJt9DkszpcR9cT0cted9T6xnMcEcecYiT0vl2D3/OvPm9pzc7r5zFs9LjM/f5VmozsHfrgANfS6Fb/ADHtI+7fm2n1eL14OyMn7ye84vO+o3xnnAiI4zHGmUED0/mGB2OEz5x5B28vryJxPRWQ9N49ybugAByxlX3wn0vxXbCvrvG82xXZrOpKtmul1Xtfn9NJ1dzVXPbOCrtabn6HMVrqIuhsVhjtbqLpz8d67onXPHvvmvTLAAGCGvMexb3E9A0etxou9DxOyNsv515ss0l+VeDBkyIEbITr3YfxsccqpN8323xxeq5O5w5e9b44AAAbOruw14r6FuxiKPTeZQNyrdifnMVyem68197HAy1cWocNvOJaMwXdK2X/AB/ocyS573wbj3NIAAA8kR+f9U1PP+nzPXiz0nn0Hbq4Z0q7bU8X7WdaKbmlIavdXct6tkr+R7vRTJzeo89KvpfMegAAADlxmFPK+2S+V2tuaWP2+Lo6nVWZw7s1KMqcYzqSbNex44/OfPnetiqan3uPMvr/ABvVnAAAAABwxlEHnPXoHE9BvxjZZRw9CvVtwxZjZU36cuvl2eNa3TnK96Hgy56jyXdKIAAAAAAaRg83rsDz3quXR6G2L1HGcYI4xhrOno6D+9L5Z+9Pk7gAAAAAAAAOQa2pvtfndVL1NzVXZtnWqbem6OjynVuaHUAAAAAAAAAAAAeTBk9AAAAAAAf/xAAqEAABBAIBBAIDAAEFAAAAAAADAQIEBQAGEQcQEhMUFSAwQBYXISMxQf/aAAgBAQABBQL9SzQNIi8p/M53i1xvN0acSMsSWyWNzkYiWEdSfxyE5AKRyiGRMhXDgSpFk+S5ZfggX+0P8d4x9TaPWaZow2AmKaYPCWaqyGz1RP4TThBw13hLFSO+cRcSY/GznpjiCPgrXnBSmE/aaSKO0m0Vg8/yysVJOwJJx8hz88s8+MJbRA4mwwMBaxT4jsR2DOrcZdjjIu2ViYPaKwmBkikN/IxxxhbB1J4dLuZUx/vVc96twVgYeQNlc3J2zAjDl20maqL5L8Y/HPisK8lQFr9qjShWW3vepbExV9yuxDq3IlxJiP1/qOvkEzJAu73oNm57i+7k11dJtpVN04iRmx6iNFaauCdttoFbOS5o5dDI8vJtNrwThAEcdqOwoRSG3etACD2eLaWil30io6fV0FAVoQNkVEaU246dQ5KWNbJqJOnbe+kktcj29up1+sKBDjEnytb14NHBROO7m+WTqgNrEvKctDZazP8AUfOcRc2uzV5qSqLd2NVVgq4jB+KduOc2KgDdwZUYkKT0zvVmwO292K2Gy9L6tDSkThOxisALYeo1jYStKkukax1GiisqoBlCYT/MePd4MlnWRI6dQxV9PM32wtrS2tgUdYA7JIeypynUysQMrRrD4GzdrN/ssemQ/Gi79TbFYWuYOZICKtb7+marlS7yr8tHeNf/AOyGqDplhZkg4+l9kszXu/UgSPoq1/hY9rwCxbrphKa+q7ebc6tmUpFTjP8AvLhPpNDcv+1cP1QssB+2Gma8n3OiqnConOdJTqGT5t79S5SDqaIDpd326pVSwdg0W8+qsDbER+EsiEz5bs+U7CKI6LT1JJG/bF9g6sjfMsGJ4txycttY3w7DQNi+tL9RUtkj9QE+U7PlOwdkQeB2IjM3q8+0ndLar5t/23LXk2Kl/wCSIemuGyGNKjs5zyRMebLO0ZDGYykdq9WsYXfaKpZIREVjqq3bLGwuI5FznHFRMuLhsYaIWZI0/Xm65Td+pOpsMiOfHJC2V4kHscZyP2KK1JeyuehTuK6i19xHtb4p3c3yS+15zHjK4ToeyPEg9ijOR+xxmpM2V5EV75BemupjjM/DZA+6qn0oZzZWsyA5w/I8ORLfF0+wPkDTVg41UZnP4c47h+TdJdYZL0qwjLIhyIj+H5F1qQfK2iDCTXw+ms/CUP2gcNRE8Mt4fw7CMZ8cuqbFDtR+DeJNYGThtaHj9eKmfRHxmvlXA62PI1WGPniiJtezRKockz5JaqJ8ywaxGoIalJGH6w/jsUX40/NkrvlRG4NysdR78eGldewbRucZ4pnHaxvYVW28348tCOV7nZrNd6AcZQRffN/K9r/mxGrjV4W7qfrzt7Kb1LF3C2hYDqbZDz/VOVh+ptkTJW4Ws3Pb7ezspalbA6Jxi5SQfiRfyVOU2KsWMZF5x7ByBWdOStI53ijWPO4VKcmN15c/x1Mdrq4WkkMxWPjuReUrKglkQIRxhc+KUNcskqJwn5yANkDtKx9YVF5zlHMsdW9rwASPjOMbxgYrjNHF9mGjgYw8ZshK/V/W9OGM54ytr32RY4Gxx/plRWSR2dIWA5pEdiLxjlYZFrguz60qZ8GRiV5MbBC3GuaJOeccRG5W0xZ7osVkYf6yCaRLPWmFWREkQlaVFzntz25xSomR4siatZrbRKMTRp+4kZhcl61HPhtVe3HUExufSzsbQTHYHVXuyJrUcGCjMF/J4pngmeKfs//EADARAAEDAgQGAAYCAgMAAAAAAAEAAgMEEQUQITESEyAyQVEUIjBAUmEVgSNxQlCR/9oACAEDAQE/AfpGqha7gLtUCDqPtybC6cS4lxUFTJTn5SqeobUM4mpzg0XchWwF/AHfaPF2EItVlBI6mdxhSyyTm7ymixTTcA/aT0/DIQmUzvxRo5Trwo0rx4Qh1TRYAfZR075FHh/tNomBfDtC5DUadqfRMd4T6P0nQub9UAnZcp6ELiVTUbN7psQarKydPE3dy+Lh9ps0btnKyITowVNTBcly5T0QRv8AQDAN1xesw4jZQV7maP1Cmr42N+TUqSokl7ihrsuVJ+JW26jqHx7FR1kbx82hUtYXaNReTnf2iwHbqHy53V+ijw+N7BI83TY2sFmhWTo2v0cFVULGtMjDbourq+Thfob7Q1RPSXWywyfhfyj5ysrLE57u5Q8IZE9AOThn4Q0HW3ZRv5bw4eE03F8joLqV/MeXLZE9XhHboO3W3Km1hb/rKpNoXH9ZHMdDek7Z8J9Itd6zGUDeCNrcpm8Ubm5HMNd6XCfWY2PQFCA88BUeFsG4TaRjdlyGrktTqVjt1JhUbtQFUxiB5YCqSLnTNagM6yLkzOaqaMTODCVHhUbdSE2lY3Zclq5LU6kY7dSYWx2wUwDDwAo9ANtVh+Itc3lSq2VkGquxFsDSyPuTnFxuVhlLymcbtz0YlS81nG3cJpLTcKgxFs7eCTuRarZWWIYg1jTFEib69MELp3cDd0Q6M2OhVPic0GnhMxph7mp2NRjtap8Wml0GiJLiqDDjfmS/+IC3Ruq7DzfmRIEtKp8Vmh0OoTcaYe5qdjTP+LVUYnNPp4QDnmw3U8ToXcLt+nD38FSwqoooqgfMFNhMjNWG65bvS5b/AEhEfKoTSx926aQRp1OsBqq00snbujEfC5bvS5bvShwuR+rzZU9FHB2hV7uKpfbpaeE8QUUgkYHjyjqFPHy5SFa6kYW5RzSRdpTMUmbvqm4t7av5Vv4p2Lemp+JzHbRSTSSdxyjYXK1lTx8yUBDRSSCNhefCceI3PVhE/HFyz4yr4bjjCCCfTg6tTo3N36mxudsmU4GrsiqGLgbxnyrrFp+CHljz10dR8NMH+E0hwuE5vELKaHlO/SGRNk4NPhctq5QXLamho8IG+RUEPNd+kNAibalVdR8RKX+PoYTWafDv/rKWISBPiMZ1RNkGukNmhNopDvovgR5cvgmfkvgR4cnUUg21Ra6M2cEDdRxGQqOMRiwyxOrsOQz+/ogkG4WH14qRwP7spIg8aqSkPF+k1rWNsxFFF/Ci+ya55OyLWvFnKOlPEfSZGGDKurRTDgb3Ikk3P0muLTdqosUbL/jm0OVroxfirPC/2Fov6Qa4oRe1tlWYk2L5IdSnOLjc/VpcSlp/lOoVPXQVHadfoT1sFP3HVVWJS1HyjQfYxV1RD2uTMaeO9iGNQ+WlfzFP+0cZh8NKfjTz2MUtdUTdzv8Ao//EAC4RAAEDAgUEAAUFAQEAAAAAAAEAAgMEEQUQEiExEyAyQRQiMEBSFUNRYXGBUP/aAAgBAgEBPwH6XUaDa/3J3THuZwmPDxdXsuqy9r/aHhFqsmXZunEu5Qb9qWqzQvlVgtH2clTHHyVJiX4p1e9y+KeV8Q9CqeEytcFHX35TJmP+rey6jUZW2VXWyDa1k6Zz+VfJlNM/hq+BqPxTqeZnLcgUyUtVPVOK6rV1GoG/0C4nhWzLAeVUYax+8exUOGyvd8+wUNLFB4BE25XWi/IIb8KWmjm8gpaCRjvl3CgoGs3fuUGgZ2QcRz3HdE2VyVYqxVyEDfKtxGRjzHGLJz3PN3G+TJHMN2lUWISPcI5BfImyuSrFWKuQgbppt2OR2XPZZNblilPqZ1R67MKp9LOqfaJsuU1u3Zwhum9j/wCO0BBX+ZSMD2Fp9pwsbZAXNlEwRsDQnblNaB3NQ7PfY3N3llUi0zv9ypheZv8AuTfLN3Z77T5Z3CaRnycpzqkccoDpkDsuDm4hXGY3d2zXA1BOrXHhGdxXUK6hQnc3hMrnja6pyZBqKqZOlEXI50kvVhBVQSxuoJ9e87XRnc7ldQrqFNncEytcOVDdw1FDsIuqujIOtnZdUtIZTqdwmgNFliFR1HaG8Dsw6p6TtDuCiLiyqqMxHUzhX7KSjLjregLdssgiGpyBDxcKaijk3TsNd6KGGv8AZUVBGzcoANVZWi2iNHs4VFXi3TlVgVLQRybhHDXeim4a72VDRRx7q4YLlQyCUam9tY3VA5Q1T4TsosQY7yCuFqC1hVQqH+PCcCDv3Na4nZUbahg+bhB61BXCkr2N2ap6p8vKom6YG9pFxZSM0OLSgqaTqxA5C2T4mSeQTsPiPGyOG/w5fprvyQwz+XJmHRDndMhZH4jI2QVRJ0oi5arqNpkcGj2gNIt3YlFpfrHvKgm0O0H3mHWQcD3agi6+eI1Gp3THrLC4dcvUPrvqYetGWpw0mxypajrNseeyy3W63VuyrqRAzblF2o3TQXGwVJB8PEGe/oYhTfut/wC5MeY3amqCobMP7y4V1dXV1fOoqWwDflSyuldqcgLrDKT95/8Az6JF9iqyjMJ1N4yBLTcKCvHEiDg7cdxIbuVUYg0bRp8jnm5QF1QUPVOp3CAtsPpEBwsVVUBZ88fGbJHx+JTMQePIXTcRj9hfqEKOIxjgJ+JOPiFJO+TyOQaSqPDS755eEAGiw+rPQxzbjYqajlh5Gyt3aSVBQSzcDZU9BHBudz9jJSwy+TU/CmHxcjhUnohfpUv9IYS/2QmYUweTlHSQxeLf/D//xAA7EAABAwEEBgYIBgIDAAAAAAABAAIDEQQSITEQIjJBUXETICNSYZEFMEJigaGxwRQzNEByklOCFSTx/9oACAEBAAY/AvVFhkAcFhj+3J4IuO/Fapw7qvNz3jgquNB4oMElSf2kg906M1WLWA2qqr3V8FeByTH94A/tJoaarjfZyWpZ5iPBhVBY7R/QrXs87ebCnDeoGHNrAPl+yzqVq4K8cTxWazWa7WGOTfrNWKzp62ssjYx7xosbU08gsLRU8KKkbxTgFnp152D4r9QPJak7D8ep2sjQPErG0fIrC1NHMKsUjZB7pr13SSvEcbcS5ydF6OFB/lOZ5Ivklc48SVtEraIWD0Gy6wQ6LtZHDAcOa7WU07owCoNY+C/Ty/0Kxq0+OC1JSW912IR6XsZGjFvHki2DUb81V0hW0StohB8crmniCmxekcW/5RmOabJE8PjdiHN39QucbrRiSUYYHFtjYdUd7xKEFmjMkh8hzQfbSbXL3cmBUhs0MQ91gVJII5Bwc0FEwt/BTcY8vJdHaW6p2JW7LlQps9of01fYbkrsUbYxwaKaLssbZBwcKp9os8nQ3c2OyV1vxK6OzMwG3K7Zag6dv42bjJs+SpFZ44xwawBUms0Uo95gKLrGTY5eGbCjBaYzG8ZcDyQhncXWJ51h3PEIOaatOII0x+j4nUktGL/4KOCIXpJDdATYmCshxkk7x6stmtLL8bvl4qWyS43cWP7zeKNncdV+XPqCzNOqzF3NRWWLC9tO7o4plmszLsbfn49V0LxR+ccndKkgmF2SM3SFJYJXVks+LK72abYa1bG7om/BT21w/LFxnM9R8sjgxjBec47gntsMpsdlB1bm07xJVknmtJtEjgXPkefHJQ+k4SH9Gdsb2FMkGbTVNdx0OdwUkhzcaq1elJsL1dbg1uajjitJ9H2N0gbqZ3a5kp9rncTFGBlmUyaJ1+N4vNcN46kFtaPzBcfzGSsZrRsh6J3x02p3GV31RPelP26hiaaOtLxH8MzodFHPIyJ20xriAU4SY0hfT4HDRAfcGi0H3Do7PCsAJ+LsdDY5J5JI27LXPJARgcausz7n+uY6le7KD9VZDwmZ9dNvhcKFsz/qpYq6zJK+enaHmvR0LBeADnm7iscNAgODuhbF8Tn99ETeDQNEzOLSNBs2buifD8d32VDmsMV6QheC1rmteL3h/wCraHnpZHXF76+SsELc3Ts+ukWoDs7W2v8AsMD9kQ7YeKFUa+7/ABWJceZ0ZBUlgjkHvNTJPw4je1wdq4BQ2RlLkes6m8qGPdW8eSA0EKaPdW8OSlsr9iXFtdzlJL+GEj3uLtbEKkUEcY91q3aMCRyKo517+SDW7DBROtZHZ2Rla+8cB99MkAwnZrxO4ORa4GOWM0LTuKDSaPHUwRANZEXuRnkHaSfIdTpox2jPmEHBBrzST6rHqEA1edyDGAyTSGgaN5Udnzmdryu4u6n/ACNmF2fJ/vrfHI1XZReHELauraqiIhTxVXG8U2e0tpTFrD91TqUTp7M3xcwfZVGBV2UXgs6LaqiIm3fErfJI5H0jaBetOTPc6suFaYrWbj3hmiY3B7eBzWyrsUJe7gte7CPMrpBEZnd45q7S6eB612l4+C6QxGE94Zo3Lsw8irk0JY7gtlAyOEbfDErVbj3jmohlv6r2neE9hzaaaJWeyTebyTZIzde3IoRStbFaxuPtclktdgdzWoXM5FasvmF+Y3yWtL5Ba5c/mtVgby0OiiDZbWd3d5p0kjrz3ZlRM9mtTyWATWD2jRNbwHW6T2ZProE7B2kOf8dALTQjeE2K2jp4++NoKsE7XHu79OWms87Wnu706KxDoI++dooucak7zoM7xrSZctF/2WddwG2MQqHAheCvsH/Xfs+HhpqDQ+C7O1uI4Say7SGGXzC/RRf2K7OGGLzK7S1uA4M1VUmp8dN5w7Bm0ePgsFQZoV2jievRG0MGqdrQ6GZt6NyrtwHZfoo1pcsaNWMvyX5p8lhL8lhR6o9pbz0dyEbT02KJt1jdHTvGoNlU9QWuFUSMYT8tBY9oew5tKv2R1Wb4zmOSuXLlN2mraU8SnVextMMSndveduDQrly/Xci+1OozdGMzzQYxoYwZAaMcIR80GtFPVFrhWqL4gXxcN40YKkrA/muzkdH4HFasrHfJex/Za0jAtd5fywVI2BmkOkBbFw3lBrRT1lCi+Ls3+C7RlW94eo7Nmr3ig+XtH+KoPX4hVuUPFuC7OU/ELNpWTfNZtC7SU/AKtyp4uxWA/aZLJZes/8QAKRABAAIBAwIFBQEBAQAAAAAAAQARITFBYVGBEHGRobEgMMHR8EDh8f/aAAgBAQABPyH7WJHCMC5A6n+e79AsR5a7S589aMsfQxuqLQluqgpFUUY9f8inaoHpAHMEtBMKxVtMT8dsJdUHMhhaeqn+S4LMQ1fTy0mbS3/QhCu3daGKIav603Syq3j6oP2/xLy+MTUKQfAHAjJHcfA9yRIvBAitzSVYHizn7vNrThuvNJg6hyJctuWkQz4NBa0G8ZRQ2LfEtV7iJU70wl5Y448NPDPKSpB4b6DRuvNI/E5taf1iGTaUBGoTxX6DaKTOqFi/LPOCNRzGRd7xf8lm8TNEgmew72mrPQNs12Hr/wAoqvgBaFe84j2somSHQnLNXePshzL2oj2GecDmdKTEBXYr9BvDyZaWD6AnhdADrKdjtC/9VM+pHodVsTWlNC9hq95xygn4jx/hEf7Hz9PpUOW/7Do8R9kPSb8lHo+e7OCCrwDvoO4wMi12/J1I/wDqCdqaA8v4iWSy6R4/e4GJ4DgEn4ial4mfYbdpktEtnqtyV7FJm39WQ/hTQE8dZEMcg27vwxZ5ourDzEKGf19IAx4iIWEdcro6JGr6Q1tIXdC4xcPA9JcG8ZYjunA6wKwuu73XVhRdfBAzDfBoM/r6y/bvKmMM0WU27PyePoN4GPzctF1I9x9PmYrxVgXQA1YqGxpF/CiX/wDJKNsniEaBDyb716zQVcARoL8Dc0FxiMmKHTRble74mxK0wqcioXQDK7WiurC8j6Amj42BKxYzHcenxF9Z/GJ714olqn3wd9W+g+j+y+k8j18PfMaJEXWBW6K/CYGI9l/B4OZhPgg3FLyUDg/Lw9k9LCOkZO+L6v8Ap9Fw6legjC6o9vjXidXfU6BQ8A/T4aRLUYWg3BQVA+GI6CujAVQWuhBFae8qGV1YzevtHh/GQRU+UA6sI4X+UIwUGkiOgriNEWBRaSB9Fgz4dGquA/sgC2Z2ovseKFqt9tA9LTVlWlryezLIQ6H8z3Ldj0SchGnCAxoZqKiN5NJiitt4X9HzGobPYp5AeND0lPuUx1abNAfs+JlQAsireDSPyjAThED2Il6/koxjofzNH1YDZy+sZ6WDZpnpbxq0yFsbeTpEf5cYhqTTZpGEaynWOoZtQYtPaM5asrJ5qewfQSv56O4RUaRhaRxb/MyvEaAynWA62wMmECAJXnFNCMasNbn4NPoNBvCNBtfPMemYyOEgSneZM+a6MxC/iVJ7ulnS6ErqP2KCMeJDdSzpfJcxeVPUhCgb6zKL5jjfQlGawqmYwGVgF2UnIN655+mk6D2sv3DwCIlrOjFWL9pvTSlRUqn+MRoENix5EzZFsUwDv9FDePXE0BbEFh2MvMlUR/1mb+EtTLN/eXZjNSWrl5VDJMj3fSOnkJqhh9oh1LiV9dwIiVFhB3BnS5QBQFcQt7Ml++5B7xGP/wCsiMG9fmSj2hPoTMKSioEVcHTlCDEWkahsdmmMBNUwIA7QD6UsqLWN/smszCaA33ekMaI6xKSMBPB7x1gndxtHtBuIdpxoA2JdRaOaFt9oyNcPtHSNJdalrBFpTfbf9+BjRu94FFfVVjceYxZ2qR2moFrCMfOltdfV4CJYz0VTMR5HnvDA5ql+fBIROapfmYbyuvaCS99VW+LA0l9RBihQYAmwLWAJVRvHP1my0Z0Q3NnrANwSBKR25JrY3D8PR8JsKOCFDT5bY4+CcUQB9yQVrcNMsoOEz0sxacp7HVgBBUHXliLGE8xwd+YZDQ+wZwJVMAlVh+LCNkDOOg2MpL45/qN5kdupFPhCkVVbVoTRBdpL1JhYtmwWzCGubg5bSkI6HQSpthtCjL8SGUAVR9oVYFI7zcMD+twiI7VSs/6jJ3l0oeQj7grgPeD/AGVWZFfpglAR1DL3ilawjWbZZaImhAUBt9yhsyrGbOHzIsHDlJucA7y5brLlDeb3Bg4uEmGIzYweRKG/fOaYggeaIu0TpdLevXkzV/btNT9cxMsnSqICHmCDYf8AIpsnCgGz7n//2gAMAwEAAgADAAAAEJJJJJCpJJJJJJJJJJOQBpJJJJJJJJJV1mpJJJJJJJJA8EtJJJJJJJIKvqZ+JJJJJJHL6TEKRfJJJOYI4qbW64WnJB7UX8wMQzWW5IkS3vENx8UyUZI62CG32QPG75Io27+O6yf629JIm/o5jej5u2RJS0n5RXG5qyFpH6ckB0XPO8XvIH97GnBQoFaYJI/tjPLonNK/ZJE342TXCfDFXJJCsQW+22JfsJJIF0mL/wCV59CSSSAZHVZmMhqSSSQcavoonVsSSSSTCFuzOmrSSSSSSdWokkeSSSSSSQQErTASSSSSSSSQSQSSSSSf/8QAKREBAAIBAgQFBQEBAAAAAAAAAQARITFBEFFhcSCRwdHhMIGhsfBAUP/aAAgBAwEBPxD6T0YP7XSA2Wf57tbE1mFuWTFuOjNLDucomajrA1xcb15/5OtQ/qIMvOdDbnMx3TY7EUE2nWwP8jEGHSLyJ+zELLymqvyYgBJ0sD/FoRRLMzl0IbaPJi9pqQftK8xrZ9XAC4JtKY4m1FgdBwoC2N0U2f1ZgylHgm5JkphiLUQ2mAHjBWiZjOWMYEtlsftRY9cg5yNuXf2j7pcjBAuhcxX+BiLoVE9rk6Ri4H9iNOE/MSyy2CkulZTOYxEafCadYF5ZYSkBB4OSZA3Y0+/OUJB0KjBFBOpMbJs6faXRRA3ZdSkBC06yne/gEC0ol8RrgBEsjo+Mjv8AMrgYQVxk9/iG8sWWsNOGnCcSpviYB4hccsFUiaiQwDG/BjLaIvurNEVhl8BiaxmvBgPA8dJHeNW8n6lRCub9MNZpfGyGLjwZF4awXReUFqvKImvA0S70nQQP1w6+CfiaMFnAL0jtF5RHVeU04YtFx4BJaL1hY3d/aaSDsEA3nWgNAe5AcHtj8aS2F6R6TF29iUFcEsqLsi2dmUdr/qhuS9c/jSE0A7BAoy0sPcIUtXb2jq1TrFtxGoypCS0mj6Pox3mkpgmbzGwv9PmImtY7H6ZseBqn1jcgjUIceubZ+ZvkUSmD1YqFrq+h7xUqX4GWyU61tEIoQjO+RzBP1PxBPU+ISvTp76zJMsoD009T7QBR4EBTLw+56ntMAwkEG7mfmHep8Qx+1+IA3rkMQGFqCtsL0vbwkpoteZU3Fc95fiHXDKYo1hOqoiUrnc+XL+zLI7JfhTF0Rh1c5jz5/wBmA1XDZgWKQQ6ZYXuc3WCzQNeWPCp6g35TSEA+cohOVd2feAFMyRpLYpbnZhFV7j2gV+tnX+ZAr978QWq9h7xW3e/DLOkoKJy71exADBNJQL5RV1lvz8Vw2f1fm+FEGT9cIHDNhGaC8SOE3kYgYOC8LP6fPAAaz/B81407Cez/AFwQljCRRlrVwEMRWFuCFHYIY4ky6NfaAqIIUoI3bB2PfX6ANnJq9PaEdiSraJUl+DBLZ/OkB9j5nWeRFfY+YJbIswJQuUY04BFhM2XV6e/0SSUksJR/PU9ThRhAEvVntBAUdJaWhKmJWhbhjSRidkUF6sdpVAjGq2/x1fQiJLX6QdqTRhAvJdn2fxwQKYI2qY6wuLzJ2MOimhFQNXcAwOBi3Ndj3Yne11fqnnZ3U7PpBQp5HD8/biyjjVwxLeQy/H3gD2c1e7/hxr1ycn5mMJ7Ne8bpPJ9Z0fIe8PqPI9ZeBHdv2mJeuRg/H/D/AP/EACoRAQACAQIEBQUBAQEAAAAAAAEAESExQRBRcdEgYZGx4TBAocHwgVDx/9oACAECAQE/EPpNpygjk+3Wi5ZKxG1jlKkiBawQHL7QWiUS8synamSyGS/tDuGsY2cpB9GAhg+yA1GGWRvEd1DnTeJqzAwk3D9VGSxPeCSZlhYIxaloKtECt69PeH/oIDbV6+0FMSmPYZjkUghbBd4GQ+NQyzCTXVzKCUMDoXA39R/dIzMbfn07wCsvNy+sA2q6zJX5jvEG1cG3OZrDxmb8usCP0EHoJQShlTJMZIjk8Kv5QIdJLJRDWQICmYInd1emxL8l5ty5ZkPk1MpTua/7Kttgw6SWSqGogRZrbwLFRAgLtgVxQx22VWGAR5wenxK4gh5wOnzKkLUph14VcRdkVLjsri5VitgKPAJrABiLXc0FgkV1tKjkN5oHAETQQWODHgSyOlI6eJHPgi3jg4QgnN7yoYXk95t4EU+DSQzx0mC41bzPyQzpwu1mhPN1feVPJ5PeGSXl4aaznyDaPHAgZ4ussgupilXSa6r/ALx/MKujMut1zBJVOe1UdWZKyoYbgb2FPUiIrqB0p0maV9Xhk9HU/wBmCV9YKFUHFLgCmNjsdSDsy5ZGDw17/iUhBuP2MqJEhWn6HnAuRoF+34hSWS5exCo0GhAFECvAV0LCWUsYq0pg+3HP6Y7qvnAMYIBP1e0StyokSCqyMCdH9PeIeZGEKfKH7cW/riti2KqUEW6V16eGimxfpMm45bSlKny0hJDeJaQx1ch/ZiQNPCokZUqBtgbRyP8AYg74gm/AvQt/EVzxy2iDdUv1z4TZ6OI22GokcTmno9SMehlEEoGO3bo+Z88TynpPjiL3bq+IVQEqPQcB7lodWKWZqFIIYHQx4q3S9xwtXx7vmPBMPGCETAhCFY41dfiDGTQ974w33U6xUDJBRshWmOvn58QuFJhvL55fNG2rErgRELPTvGRQwFrA6gev0M6f837yqhxKSY3ganaBcKErLS0tKRBiVLPlsP7aOktYyolLRp/Ht9EAhYxgdv8AHl24GHpIg03nt/sIsshCBcCIQxSiCud57f5GT2sRURKuj+fLvAIFB9JwdjL4b5NzuRE4OWxMKX4RGsfmeY+k1wfxL4I/MbtmKsZolQFcm72IYOg+rc9YN+pLRs5jJ8RRwuXFlMIGLo5nBKrrL+j7HKBfMwzIMdS+03S9e0831fEbovXtMsz0K7zNBfNy/n/h/wD/xAApEAEAAgECBQMEAwEAAAAAAAABABEhMUFRYXGBkRChsSDB0fAw4fFA/9oACAEBAAE/EP4mCNZoDwvSHGnIlj3/AOctVN7C/aWPFTircOvbZN9rbqQhqAn/AAc5rpOIDuw3SmRS6GFf8nuJ+Kic5aMQCDdYDNoSQ3Q63TGr5YGuWEfEqYdEzFSsY8gfv/xpZTkhqNiimrXUvslOxbfj3iogZC5bukxdWFh3hSLiWJZwFS3LKnEB+P8AhUBVoN4OBDdx5jiENkywgP09DgLkl58ksXbzNaq6x5BYWDYil2JMbuuGDqV2X3giWZP5EBsXUPdiJGf6YQRYMWXkVA0L0y3ruxctTLOrcURZSmgms16zPdOYmrwfEFtujKezUMgKyKsY465hBWpUDepL7GsJo97A7hUtQ/01gE7F1Cuz9bFghTt1ZYsy7fOXB5tvSJrm/Jhbj/kOyzNeZEhls0u0DhwCrgcn8xvvql5tfYz0imbcJQ4U16tswJfq54i4N7LcVqG6rwNMSSDl6XCnTtHm5KeYW/RzCzc4TBz2dDzD0LW0i+8GOxKzuEaGPD+0S7jCuuDV544PMB6wbiwrm4n0Psu6hlqdgBiUjjbFZVz2bHNZmSmGN03AcX5lEtiR+AK6qrlDwl/ZS0M9VIx7JFH/ACPNzqaO5ByqctI4PkWT3me7TrqVPgHvLsycTB1g8B2J7EXjFznYHuYhLDZfk2tHAGTpLZKXQ1X4ifMzIU33HgLX3lbKhU4AMV3JjqcCDwRom/6SM75hVuC7etY4TiF2O30vwb0wwR0LK1Vw8hnUjs8itRYjuJ6pgO0JSvhdC3m/DCJKzyNV2BmymkaZzqHINjmspQA9VgmeM1YDZyq9QJGOBGILFXOik2RIt+lvcAZDqfEIQlG8ZOEWMMYHofMtbtZbJN0NDdQ3hnEDTnTuOVg2i1ys1q9GALGHC1yG2R1toNznUZ6uWwdTk4R4JF2FthGurS6Ft6mdjDeBXrrf3lFeSLC5LmEJMBt6rrNGgFR4AQgGkQNoVaLqUVe+s16S5vUaVAzwuGbhSzEV8C46ozFA+zHYsITmejg0trtQyyEv7qkUDGVaaw628YUEticrXti4QPeDeZIPALOS77LF8bxYFh2fUmC7lD+AUOZOa07ZkzYXQWTz9vXVJb1Vh1+LCfH0PvWK1SI9EB9FrUMuOtKD3JZEFOdeHKSiKs2WvbBqOnax75R82K7k5rR3kL04bMUai0mHCDZDVaCD0FJ0+h380iPmKc0CnOPXvoG0rCiOSI94LNSvhQ+ZGSLS1o4s9zQH3iJvSAGUumoPhjZR94acoA1XYhZLSX9XKWCZwEwjJOoCDxjiamdVEoLwqma++RurF/JH+NI2RpJysQbfaNaTKzUFrNDE9lQP3iBY2cT0adK3jKXzKtRAVdBjoI+pizXaM7gdxl97eust/oYWUIUqjflbFF/VDWI25fqDmRcI1Pkxh4wFJgAthqnGkzYRCoVB+mVDBWeCLb5wd5jSqGnpbmbI/wC/8FVSujZ2gNClaAfsdRKFD04pCtAXBTiHxbQ+DJRoTkRbV7S7frhrLobihfhTL70eelr3PYE3I5AA9h4h6jE1woNJ4KrqO0G3ctoRDtB/FE9f3jAl0YLoIQoksHzw2BIU3f8APKLQWctrn5i0CFPPzjq9oQa9H8FSWfmDU/uOQOcNIjCquWKPx5N5W9+AWLENkbVyEIeyppA83LbKAlgXcKRYPAAdL39UERyMWSSKsy3AaA3GHaPQoFpEwewfiQI8+JGCvCsxu+Fof3GLboMquwR0CAbR2LjwPMPug9VWIXdiTKI0bVvzuJ4lof0mEeCRrFI4B8y+PwlT7R0luK3NHst7sQ8MMyhDBuVs643kdhg3sKKPoB+wwdB+BjwVT4rd+jAh6gUg23F8S+pU6ogNzIDXHKTcdAWrth7zIRp+Ig7ZirjgoDqMHwGX6oMiAVwC0OgQ9SWVvaHvmbGUAq9sPeYCPkJXHCwZQb2Ss2ymoO2we8OkGfePboVNZyx1L9z6Ryt70RH5glOeDiSI4BzIDHbVUOUro2doUtO0P3OUJXoRVXE16akrfvYQSSShFTo6kUxfD2K3zEWQ2Pwsx1+l1mkE3Pzs7CP4QfMJ31VY26urHZLeJGYxKrdeQ06asekneHgcDlFGwHqwyt9aDvAhQcCAFZWs6tQH6AdAr7fSCLRKiimFnYwPkp8woXEqOKTLfcz0X0AW+cINETRldedJtMNPa9Y4Yl9zryQBYicpqwepP8CaMXaIFqBzgzCvsdOWWvd0szo0970iIOPEOqrqzEyjtioyOnlnoE0MvADlsuw9rYBDQK+ohLs46ecneXUIa8hpGCgRKSxHUY/c8fJqPS24nRhg0gbOpQOiSsO8AAdM33lFS1LHhHtMNZ+P9UuKWjI8g9pYMeExOuD7zLw5RO7E1g1hdwyMGsHrvwIbIYAoA0CFyDzUldCCJd1PXxg7fWDNhTE7rFfodLvDIbm6sMy2TZNRnCQGx+5ydoaN52ixTdLvPCWIrao7H5gK8dz+6D7npig97f1MVAm1x2fzM1n0ovpxhVpXTYmH6nLeVmmDVbpuu7EKSqzgTXv0m0Jmgo/gUAJBYjqM45Xfb4ODLCXMIJmB0YgGK0xXmzRyc82L3F0vZzvLMJVVNKqPUTQFfSCzat1HicSVZU1QXm8Iq0EM04lZHnFArW0uYo9hnpNExBB0iglAThjb9vg4sMQIBQBsfxO0wDYODLGYUCw5cHvMSc8JfAuJKkGUeBajsx9HZBD+H3gdl8yfDBvj/rB1L5j8EqBXUhfl941d8PlGpjpS8WIrFy6ehUQfY94C7QNA4H8jALe9TWrSzPP+hmN7jTa+Lud4PgzQQwRo10ZzXmczfVjqhD2ziOTzTa+Ju9o++AM7/TLCQSt6/mSynSEVx3qL9zd1njWJuzjHyVEAcaLY+0PcG8OAW6pce0bN1GPluE87dnyaQCXDRqBRRg/4kHXM1JO0/wA+aGHaAGmP4//Z" width="33" height="33" style="border-radius:6px;display:block;">
      <span><em>Orange</em> <em>3</em></span>
    </div>

    <!-- 로고와 타이틀 구분선 -->
    <div class="hdr-sep"></div>

    <!-- 문서 타이틀 드롭다운 -->
    <div id="menu-wrap">
      <div id="menu-btn" onclick="toggleMenu()">
        <svg width="18" height="11" viewBox="0 0 22 14" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect y="0"  width="22" height="2" rx="1" fill="currentColor"/>
          <rect y="6"  width="22" height="2" rx="1" fill="currentColor"/>
          <rect y="12" width="22" height="2" rx="1" fill="currentColor"/>
        </svg>
        <span class="doc-chevron">▼</span>
      </div>
      <span id="doc-title">제목없음</span>
      <div id="menu-dropdown">
        <div class="mi" onclick="closeMenu();wfAddTab()">새 문서</div>
        <div class="mi" id="mi-open" onclick="openOwsDialog()">불러오기</div>
        <div class="ms"></div>
        <div class="mi" onclick="saveWorkflow()">저장</div>
        <div class="mi" onclick="saveWorkflow()">다른 이름으로 저장 ...</div>
        <div class="ms"></div>
        <div class="mi" onclick="closeMenu();ctShowInfo()">Workflow Info</div>
        <div class="ms"></div>
        <div class="mi" onclick="closeMenu();wfCloseActive()">닫기</div>
      </div>
    </div>

    <!-- 헤더 가운데 안내 문구 -->
    <div id="header-caption">오렌지3(Orange3) 기반의 웹 머신러닝·데이터 분석 실습 환경</div>

    <!-- 우측 버튼 -->
    <div id="header-right">
      <!-- Open: .ows 워크플로우 파일 열기 (사이드바 메뉴의 "Open"과 동일 동작) -->
      <div class="h-btn" id="btn-new-open" onclick="openOwsDialog()" title="워크플로우 파일 열기">
        <!-- 새로고침/리로드 아이콘 — 두 화살표가 원을 이루는 형태 (이미지 2 참조) -->
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12a9 9 0 0 1-15 6.7L3 16M3 12a9 9 0 0 1 15-6.7L21 8"/>
          <path d="M3 22v-6h6M21 2v6h-6"/>
        </svg>
        Open
      </div>
      <div class="h-btn" id="btn-datasets" onclick="openAnalysisDatasets()" title="분석 데이터셋 카탈로그">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <ellipse cx="12" cy="5" rx="9" ry="3"/>
          <path d="M3 5v6c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/>
          <path d="M3 11v6c0 1.66 4.03 3 9 3s9-1.34 9-3v-6"/>
        </svg>
        Analysis-Datasets
      </div>
      <div class="h-btn" id="btn-share"   onclick="openLessonTemplates()"><svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="9" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="2" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="9" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/></svg>Templates</div>

      <!-- 언어/옵션 드롭다운 -->
      <div id="lang-wrap">
        <div id="lang-btn" onclick="toggleLang()">
          <span class="lang-globe">🌐</span>
          <span id="lang-label">옵션</span>
          <span class="lang-chevron">▼</span>
        </div>
      </div>
    </div>
  </div>

  <!-- ── 워크플로우 탭 바 오버레이 ── -->
  <div id="wf-tabbar"></div>

  <!-- ── VNC iframe ── -->
  <iframe id="vnc-frame" src="{novnc_url}" allowfullscreen></iframe>
  <!-- (Phase 5, 2026-05-24) footer 로고는 canvas 영역에서 제거되어 위젯 패널
       하단(#hwd-panel-footer)으로 이동. dismiss 스크립트도 해당 위치로 이동. -->
  <div id="footer-info-placeholder" style="display:none"></div>
  <!-- (Phase 5, 2026-05-24) footer 로고가 위젯 패널 하단으로 이동 — 캔버스
       첫 클릭 dismiss 스크립트는 더 이상 필요 없음. -->


  <!-- ── HTML 위젯 사이드바 (단계 2A: /widget-catalog 응답으로 카테고리 동적 렌더링) ── -->
  <div id="html-widget-dock">
    <!-- 최상단 메뉴 버튼: 회색 4-row bulleted list → 헤더의 메뉴 dropdown 토글 -->
    <div class="hwd-menu" data-tip="메뉴" onclick="event.stopPropagation(); _hwdToggleSidebarMenu(this);">
      <svg class="hwd-menu-icon" width="22" height="22" viewBox="0 0 24 24" fill="none">
        <circle cx="3.5" cy="4.5"  r="1.5" fill="#555"/>
        <line x1="8" y1="4.5"  x2="22" y2="4.5"  stroke="#555" stroke-width="2" stroke-linecap="round"/>
        <circle cx="3.5" cy="10"   r="1.5" fill="#555"/>
        <line x1="8" y1="10"   x2="22" y2="10"   stroke="#555" stroke-width="2" stroke-linecap="round"/>
        <circle cx="3.5" cy="15.5" r="1.5" fill="#555"/>
        <line x1="8" y1="15.5" x2="22" y2="15.5" stroke="#555" stroke-width="2" stroke-linecap="round"/>
        <circle cx="3.5" cy="21"   r="1.5" fill="#555"/>
        <line x1="8" y1="21"   x2="22" y2="21"   stroke="#555" stroke-width="2" stroke-linecap="round"/>
      </svg>
    </div>
    <!-- 메뉴 버튼과 카테고리 아이콘 사이 구분 바 (2026-05-25: 위 2px 여백 + 더 또렷한 라인) -->
    <div class="hwd-divider hwd-menu-sep" aria-hidden="true"></div>
    <!-- 카테고리 항목들은 페이지 로드 시 _loadWidgetCatalog()가 .hwd-cat 으로 채워 넣음 -->
  </div>

  <!-- ── 단계 2B: 카테고리 클릭 시 표시되는 위젯 목록 패널 ── -->
  <div id="hwd-panel" aria-hidden="true">
    <!-- 상단 바: 위젯 검색 입력 + 패널 닫기 버튼 (이미지 1 native dock 참조) -->
    <div id="hwd-panel-topbar">
      <div id="hwd-panel-search-wrap">
        <span id="hwd-panel-search-icon" aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6">
            <circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5 L14 14" stroke-linecap="round"/>
          </svg>
        </span>
        <input id="hwd-panel-search" type="text" placeholder="위젯 검색..." autocomplete="off"/>
        <button id="hwd-panel-search-clear" title="검색어 지우기" aria-label="검색어 지우기">
          <svg width="9" height="9" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round">
            <path d="M4 4 L12 12 M12 4 L4 12"/>
          </svg>
        </button>
      </div>
      <button id="hwd-panel-close" title="패널 닫기" aria-label="패널 닫기">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <path d="M4 4 L12 12 M12 4 L4 12"/>
        </svg>
      </button>
    </div>
    <div id="hwd-panel-header"></div>
    <!-- 검색 결과 없을 때 안내 메시지 (영어) -->
    <div id="hwd-panel-noresult" aria-hidden="true">No matching widgets. Click a category name to clear the search.</div>
    <div id="hwd-panel-body"></div>
    <!-- 패널 하단 footer 로고 (Phase 5, 2026-05-24) — EBS / 교육부 -->
    <div id="hwd-panel-footer">
      <img src="/footer-logo" alt="" onerror="this.parentNode.style.display='none'"/>
    </div>
  </div>

  <!-- ── 단계 3C: 위젯 드래그-드롭 zone (활성 시에만 캔버스 위에 떠서 drop 이벤트 캡처) ── -->
  <div id="hwd-drop-zone" aria-hidden="true"></div>

  <!-- ── 리사이즈 중 왼쪽/상단 마스크 (메뉴바 이동 시각적 혼란 차단) ── -->
  <div id="resize-mask-left"></div>
  <div id="resize-mask-top"></div>

  <!-- ── VNC 로딩 커튼 (3단계 패턴: 헤더·탭바·iframe 전체를 덮어 resize 잔상 차단) ── -->
  <div id="vnc-cover">
    <div class="sk-header"></div>
    <div class="sk-tabbar"></div>
    <div class="sk-canvas">
      <div class="sk-splash-wrap">
        <img class="sk-splash-img" id="sk-splash-img" src="/splash-image"
             onerror="this.parentNode.style.display='none';
                      var s=document.getElementById('sk-fallback-spinner');
                      if(s)s.style.display='block';" alt=""/>
        <div class="sk-load-info" id="sk-load-info">
          <div class="sk-load-app">Orange</div>
          <div class="sk-load-ver" data-i18n="loading"></div>
        </div>
      </div>
      <div class="sk-spinner" id="sk-fallback-spinner" style="display:none"></div>
      <div class="sk-label" data-i18n="ready"></div>
    </div>
    <script>
      /* 로딩 커튼 정적 라벨 — DOM 생성 직후 INIT_LANG 으로 채움.
         applyLangUI 가 호출되기 전에도 텍스트가 보이도록 즉시 실행. */
      (function(){{
        var _COVER_STATIC = {{
          ko: {{ loading: '로딩 중...', ready: 'Orange3 준비 중...' }},
          en: {{ loading: 'Loading...',  ready: 'Orange3 is preparing...' }},
          sl: {{ loading: 'Nalaganje...', ready: 'Orange3 se pripravlja...' }}
        }};
        var _L = _COVER_STATIC['{init_lang}'] || _COVER_STATIC.en;
        document.querySelectorAll('#vnc-cover [data-i18n]').forEach(function(el){{
          var k = el.getAttribute('data-i18n');
          if (_L[k]) el.textContent = _L[k];
        }});
      }})();
    </script>
    <script>
      // /api/orange-info → 버전·addon 목록 fetch (Phase 5, 2026-05-24)
      // cover 안의 좌하단 #sk-load-info 채움. 라인을 한 줄씩 순차 append —
      // 로딩 진행감 표현. fade-in + 220ms 간격. cover 가 사라지면 자동 중단.
      (function(){{
        try {{
          fetch('/api/orange-info', {{cache:'no-store'}})
            .then(function(r){{ return r.json(); }})
            .then(function(d){{
              var el = document.getElementById('sk-load-info');
              if (!el || !d) return;
              var esc = function(s){{
                return String(s).replace(/[&<>"']/g, function(c){{
                  return ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}})[c];
                }});
              }};
              // 3줄 구조: 1줄(버전 고정) + 2줄("Add-ons" 고정) + 3줄(addon in-place 갱신).
              // 화면엔 항상 정확히 3줄만 표시, 마지막 줄만 textContent 교체.
              var addons = (d.addons || []).filter(function(a){{
                return (a.name || '').toLowerCase() !== 'orange3';
              }});
              // 로딩 커튼 라벨 — 언어별 분기 (2026-05-26)
              var _COVER_LBL = {{
                ko: {{ addons: '애드온',  loading: '로딩 중...' }},
                en: {{ addons: 'Add-ons', loading: 'Loading...' }},
                sl: {{ addons: 'Dodatki', loading: 'Nalaganje...' }}
              }};
              var _CL = _COVER_LBL['{init_lang}'] || _COVER_LBL.en;
              el.innerHTML = '';
              var verLine = document.createElement('div');
              verLine.className = 'sk-load-app';
              verLine.textContent = 'Orange' + (d.version ? ' ' + d.version : '');
              el.appendChild(verLine);
              var headerLine = document.createElement('div');
              headerLine.className = 'sk-load-ver';
              headerLine.style.marginTop = '6px';
              headerLine.textContent = addons.length ? _CL.addons : _CL.loading;
              el.appendChild(headerLine);
              if (!addons.length) return;
              var rollLine = document.createElement('div');
              rollLine.className = 'sk-load-ver';
              rollLine.style.transition = 'opacity 180ms ease';
              rollLine.textContent = '· ' + addons[0].name + ' ' + addons[0].version;
              el.appendChild(rollLine);
              // 두 번째부터 in-place 교체. 각 갱신 사이 220ms.
              // addon 리스트 끝까지 가면 첫 addon 부터 다시 순환 — vnc-cover 가
              // 닫힐 때까지 마지막 줄이 계속 갱신되어 멈춰 보이지 않음.
              var i = 1;
              var INTERVAL = 220;
              function step() {{
                if (!document.getElementById('vnc-cover')) return;
                if (i >= addons.length) i = 0;  // 순환
                var a = addons[i++];
                rollLine.style.opacity = '0';
                setTimeout(function(){{
                  rollLine.textContent = '· ' + a.name + ' ' + a.version;
                  rollLine.style.opacity = '1';
                  setTimeout(step, INTERVAL);
                }}, 90);
              }}
              setTimeout(step, INTERVAL);
            }})
            .catch(function(){{}});
        }} catch(_){{}}
      }})();
    </script>
  </div>

  <!-- ── 저장 확인 모달 (메뉴 저장/사본 만들기 클릭 시) ── -->
  <div id="save-confirm-overlay" onclick="if(event.target.id==='save-confirm-overlay')closeSaveConfirm()">
    <div id="save-confirm-modal">
      <div class="sc-header">
        <div class="sc-title-text">변경 내용을 저장하시겠습니까?</div>
        <button class="sc-close-btn" onclick="closeSaveConfirm()" title="닫기">✕</button>
      </div>
      <div class="sc-body">
        <div><span class="sc-wf-quote">"<span id="sc-wf-name">untitled</span>"</span>의 변경 내용을 저장하시겠습니까?</div>
        <div class="sc-warn">저장하지 않으면 변경 내용이 손실됩니다.</div>
      </div>
      <div class="sc-footer">
        <button class="sc-btn" onclick="closeSaveConfirm()">취소</button>
        <button class="sc-btn" onclick="closeSaveConfirm()">저장 안 함</button>
        <!-- 주의: 저장 버튼은 closeSaveConfirm() 후 _doSaveWorkflow()를 동기 호출.
             showSaveFilePicker는 사용자 제스처 컨텍스트 필요 — await 사이 끼면 활성화 만료. -->
        <button class="sc-btn sc-btn-primary"
                onclick="closeSaveConfirm(); _doSaveWorkflow();">저장</button>
      </div>
    </div>
  </div>

  <!-- ── Workflow Info 모달 (Datasets 스타일, ⓘ 버튼이 호출) ── -->
  <div id="wf-info-overlay" onclick="if(event.target.id==='wf-info-overlay')ctCloseInfoModal()">
    <div id="wf-info-modal">
      <div class="wf-header">
        <div class="wf-title-text">Workflow Info</div>
        <button class="wf-close-btn" onclick="ctCloseInfoModal()" title="닫기">✕</button>
      </div>
      <div class="wf-body">
        <div>
          <label class="wf-field-label">Title</label>
          <input type="text" class="wf-input" id="wf-title-input" placeholder="untitled" autocomplete="off" />
        </div>
        <div>
          <label class="wf-field-label">Description</label>
          <textarea class="wf-textarea" id="wf-desc-input" placeholder="워크플로우 설명을 입력하세요..."></textarea>
        </div>
      </div>
      <div class="wf-footer">
        <div class="wf-btn-group">
          <button class="wf-btn wf-btn-cancel" onclick="ctCloseInfoModal()">취소</button>
          <button class="wf-btn wf-btn-ok" onclick="ctSaveInfoModal()">확인</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 숨김 파일 입력 -->
  <input type="file" id="pc-file-input" style="display:none" multiple>
  <input type="file" id="ows-file-input" style="display:none" accept=".ows">
  <input type="file" id="model-file-input" style="display:none" accept=".pkcls">
  <input type="file" id="image-folder-input" style="display:none" multiple webkitdirectory>
  <input type="file" id="corpus-file-input" style="display:none" accept=".tab,.csv,.tsv,.txt">
  <input type="file" id="documents-folder-input" style="display:none" multiple webkitdirectory>
  <input type="file" id="distance-file-input" style="display:none" accept=".dst,.xlsx">
  <input type="file" id="network-file-input" style="display:none" accept=".net,.pajek">
  <input type="file" id="sent-pos-file-input" style="display:none" accept=".txt">
  <input type="file" id="sent-neg-file-input" style="display:none" accept=".txt">
  <input type="file" id="stopwords-file-input" style="display:none" accept=".txt">
  <input type="file" id="lexicon-file-input" style="display:none" accept=".txt">
  <input type="file" id="sc-cell-anno-file-input" style="display:none" accept=".meta">
  <input type="file" id="sc-gene-anno-file-input" style="display:none" accept=".meta">
  <input type="file" id="spec-multifile-input" style="display:none" multiple
         accept=".tab,.tsv,.csv,.dat,.dpt,.xy,.hdr,.h5,.hdf5,.txt,.dmt,.seq,.basket,.bsk,.spc,.SPC,.gsf,.xyz,.mat,.xls,.xlsx,.nxs,.nea,.map,.ptir,.sp,.fsm,.pkl,.pickle,.wdf,.WDF,.spa,.SPA,.srs,.xim,.gz,.bz2,.xz">
  <input type="file" id="spec-tilefile-input" style="display:none" accept=".dmt">


  <!-- 토스트 -->
  <div id="toast"></div>

  <!-- ── OPEN 모달 — .ows 파일 열기 (Templates 모달과 동일한 미니멀 스타일) ── -->
  <div id="open-modal" onclick="if(event.target===this)closeOpenOwsModal()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);backdrop-filter:blur(4px);z-index:99000;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
    <div style="width:92%;max-width:780px;height:560px;background:#fff;border-radius:14px;box-shadow:0 12px 48px rgba(0,0,0,0.4);display:flex;flex-direction:column;overflow:hidden;">
      <!-- 헤더 (Templates 모달과 동일 구조) -->
      <div style="display:flex;align-items:center;gap:16px;padding:14px 20px;border-bottom:1px solid #ececef;flex-shrink:0;">
        <div style="display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600;color:#1a1a1c;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
          </svg>
          Open
        </div>
        <div style="flex:1;font-size:12.5px;color:#6b7280;line-height:1.45;padding:0 16px;">왼쪽 탭에서 소스를 선택하고, .ows 워크플로우 파일을 불러옵니다.</div>
        <div onclick="closeOpenOwsModal()" style="width:34px;height:34px;border:1px solid #e5e5ea;background:#f4f4f6;border-radius:8px;cursor:pointer;font-size:14px;color:#555;display:flex;align-items:center;justify-content:center;">✕</div>
      </div>
      <!-- 본문 -->
      <div style="flex:1;display:flex;min-height:0;">
        <!-- 좌측 사이드바 (Templates 모달과 동일 톤) -->
        <div style="width:200px;flex-shrink:0;padding:14px 12px;overflow-y:auto;border-right:1px solid #ececef;background:#fafafa;">
          <div id="opentab-examples" class="om-cat" onclick="_openOwsSwitchTab('examples')"
               style="display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;cursor:pointer;font-size:13.5px;color:#444;margin-bottom:2px;transition:background .12s;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-7l-2-2H5a2 2 0 0 0-2 2z"/></svg>
            Example Workflow
          </div>
          <div id="opentab-gdrive" class="om-cat" onclick="_openOwsSwitchTab('gdrive')"
               style="display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;cursor:pointer;font-size:13.5px;color:#444;margin-bottom:2px;transition:background .12s;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M2 12h20"/></svg>
            Google Drive
          </div>
          <div id="opentab-local" class="om-cat" onclick="_openOwsSwitchTab('local')"
               style="display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;cursor:pointer;font-size:13.5px;color:#fff;margin-bottom:2px;background:#1a1a1c;font-weight:500;transition:background .12s;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/></svg>
            Local File
          </div>
        </div>
        <!-- 우측 본문 -->
        <div style="flex:1;padding:24px 32px;display:flex;flex-direction:column;min-height:0;">
          <!-- Local File 패널 -->
          <div id="openpanel-local" class="openpanel" style="flex:1;display:flex;flex-direction:column;min-height:0;">
            <div style="font-size:20px;font-weight:700;color:#1a1a1c;margin-bottom:14px;">Local File</div>
            <div id="open-drop-zone" style="flex:1;border:2px dashed #d0d0d4;border-radius:12px;display:flex;align-items:center;justify-content:center;color:#666;cursor:pointer;text-align:center;padding:20px;user-select:none;transition:border-color .15s,background .15s;font-size:14px;">
              .ows 파일을 드래그 하거나 <span style="color:#2563eb;text-decoration:underline;margin:0 4px;">여기를 클릭</span>해 선택하세요.
            </div>
          </div>
          <!-- Example Workflow 패널 -->
          <div id="openpanel-examples" class="openpanel" style="flex:1;display:none;flex-direction:column;min-height:0;">
            <div style="font-size:20px;font-weight:700;color:#1a1a1c;margin-bottom:6px;">Example Workflow</div>
            <div style="font-size:12.5px;color:#6b7280;margin-bottom:14px;">Orange3 내장 예제 워크플로우 목록</div>
            <div style="flex:1;min-height:0;overflow:auto;">
              <div id="open-examples-list" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;">
                <div style="grid-column:1/-1;padding:30px;color:#888;text-align:center;">로딩 중...</div>
              </div>
            </div>
          </div>
          <!-- Google Drive 패널 — 이미지1 스타일 (로고 + works with + Google Drive + LOGIN 버튼) -->
          <div id="openpanel-gdrive" class="openpanel" style="flex:1;display:none;flex-direction:column;align-items:center;justify-content:center;min-height:0;color:#444;gap:18px;">
            <div style="display:flex;align-items:center;gap:18px;">
              <!-- Google Drive 공식 삼각 로고 (노랑/초록/파랑 3색) — 인라인 SVG -->
              <svg width="92" height="80" viewBox="0 0 87.3 78" xmlns="http://www.w3.org/2000/svg" aria-label="Google Drive">
                <path d="m6.6 66.85 3.85 6.65c.8 1.4 1.95 2.5 3.3 3.3l13.75-23.8h-27.5c0 1.55.4 3.1 1.2 4.5z" fill="#0066da"/>
                <path d="m43.65 25-13.75-23.8c-1.35.8-2.5 1.9-3.3 3.3l-25.4 44a9.06 9.06 0 0 0 -1.2 4.5h27.5z" fill="#00ac47"/>
                <path d="m73.55 76.8c1.35-.8 2.5-1.9 3.3-3.3l1.6-2.75 7.65-13.25c.8-1.4 1.2-2.95 1.2-4.5h-27.502l5.852 11.5z" fill="#ea4335"/>
                <path d="m43.65 25 13.75-23.8c-1.35-.8-2.9-1.2-4.5-1.2h-18.5c-1.6 0-3.15.45-4.5 1.2z" fill="#00832d"/>
                <path d="m59.8 53h-32.3l-13.75 23.8c1.35.8 2.9 1.2 4.5 1.2h50.8c1.6 0 3.15-.45 4.5-1.2z" fill="#2684fc"/>
                <path d="m73.4 26.5-12.7-22c-.8-1.4-1.95-2.5-3.3-3.3l-13.75 23.8 16.15 28h27.45c0-1.55-.4-3.1-1.2-4.5z" fill="#ffba00"/>
              </svg>
              <div style="display:flex;flex-direction:column;align-items:flex-start;">
                <div style="font-size:13px;color:#777;letter-spacing:0.5px;">works with</div>
                <div style="font-size:30px;font-weight:400;color:#444;line-height:1.05;">
                  <span style="color:#4285F4;">G</span><span style="color:#EA4335;">o</span><span style="color:#FBBC05;">o</span><span style="color:#4285F4;">g</span><span style="color:#34A853;">l</span><span style="color:#EA4335;">e</span>
                  <span style="color:#5f6368;font-weight:300;">Drive</span>
                </div>
              </div>
            </div>
            <button id="open-gdrive-login-btn" onclick="_openGDriveLogin()"
                    style="background:#88c8c8;color:#fff;border:none;padding:11px 28px;border-radius:6px;font-weight:600;letter-spacing:1.5px;font-size:13px;cursor:pointer;transition:background .15s;">
              LOGIN TO GOOGLE
            </button>
            <div id="open-gdrive-status" style="margin-top:4px;color:#999;font-size:11.5px;height:14px;"></div>
            <div id="open-gdrive-note"
                 style="margin-top:6px;padding:10px 16px;border:1px dashed #d1d5db;border-radius:6px;background:#f9fafb;color:#6b7280;font-size:12px;line-height:1.55;text-align:center;max-width:440px;">
              도메인 확정 및 정식 서비스 오픈 후 구글 드라이브 연결 설정을 제공 예정입니다.
            </div>
          </div>
          <div style="margin-top:14px;display:flex;justify-content:flex-end;">
            <button onclick="closeOpenOwsModal()" style="background:#f4f4f6;color:#444;border:1px solid #e5e5ea;padding:8px 18px;border-radius:8px;font-weight:500;cursor:pointer;font-size:13px;">취소</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <style>
    #open-modal .om-cat:hover {{ background:#ececef !important; }}
    #open-modal .om-cat.om-active {{ background:#1a1a1c !important; color:#fff !important; font-weight:500; }}
    #open-modal #open-drop-zone:hover {{ border-color:#2563eb; background:#f8faff; }}
    #open-modal .open-ex-card {{ border:1px solid #ececef; border-radius:10px; padding:14px; cursor:pointer; background:#fff; transition:border-color .12s, box-shadow .12s; }}
    #open-modal .open-ex-card:hover {{ border-color:#2563eb; box-shadow:0 2px 8px rgba(37,99,235,0.12); }}
    #open-gdrive-login-btn:hover {{ background:#5db5b5 !important; }}
    #open-gdrive-login-btn:active {{ background:#4ca0a0 !important; }}
  </style>

  <!-- ── 교안 Workflows 갤러리 모달 ── -->
  <div id="lesson-modal">
    <div id="lesson-modal-box">
      <div id="lesson-header">
        <div id="lesson-title">
          <svg width="20" height="20" viewBox="0 0 16 16" fill="none">
            <rect x="2" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/>
            <rect x="9" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/>
            <rect x="2" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/>
            <rect x="9" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/>
          </svg>
          <span>Templates</span>
        </div>
        <p id="lesson-header-note">카테고리 목록을 선택하고, 카드를 클릭하면 오렌지3 워크플로우를 바로 실행하실수 있습니다.</p>
        <button id="lesson-close" onclick="closeLessonModal()">✕</button>
      </div>
      <div id="lesson-body">
        <div id="lesson-sidebar">
          <div class="lc-cat active" data-cat="All Templates">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 4h3M2 8h3M2 12h3M7 4h7M7 8h7M7 12h7" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
            <span>All Templates</span>
          </div>
          <div class="lc-cat" data-cat="초등 Workflow">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 13l5-9 5 9H3z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" fill="none"/><circle cx="8" cy="10" r="0.8" fill="currentColor"/></svg>
            <span>초등 Workflow</span>
          </div>
          <div class="lc-cat" data-cat="중등 Workflow">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="3" y="3" width="10" height="10" rx="1.5" stroke="currentColor" stroke-width="1.3"/><path d="M6 7h4M6 10h4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
            <span>중등 Workflow</span>
          </div>
          <div class="lc-cat" data-cat="공통 Workflow">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="6" cy="8" r="3" stroke="currentColor" stroke-width="1.3"/><circle cx="10" cy="8" r="3" stroke="currentColor" stroke-width="1.3"/></svg>
            <span>공통 Workflow</span>
          </div>
          <div class="lc-cat" data-cat="Getting Started">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.3"/><path d="M5 8h6M8 5v6" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
            <span>Getting Started</span>
          </div>
          <!-- Example Workflow 그룹 (v7, 2026-05-27): 2-level hierarchy 재구성
               Example Workflow (부모) — 통합 보기: Basic + 8개 카테고리 카드 전체
                 ↳ Basic — Orange3 내장 examples (이전 부모 자리)
                 ↳ Bioinformatics / Classification / Clustering / Fairness /
                   Hierarchical Clustering / Scatter Plot / Survival Analysis / Text Mining
               (2026-05-29) 부모 두 번 클릭 시 sub 그룹 접기 토글 — data-parent 그룹화. -->
          <div class="lc-cat lc-cat-parent collapsed" data-cat="Example Workflow" data-collapse-target="lc-example-subs">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.4"/><rect x="9" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.4"/><line x1="6" y1="6" x2="10" y2="10" stroke="currentColor" stroke-width="1.4"/></svg>
            <span>Example Workflow</span>
            <span class="lc-caret" aria-hidden="true">▾</span>
          </div>
          <div id="lc-example-subs" class="lc-subgroup collapsed">
          <div class="lc-cat lc-cat-sub" data-cat="베이직">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 4h12v9H2z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M6 4V2.5C6 2.2 6.2 2 6.5 2h3c.3 0 .5.2.5.5V4" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><line x1="4" y1="7" x2="12" y2="7" stroke="currentColor" stroke-width="1.1"/><line x1="4" y1="9.5" x2="10" y2="9.5" stroke="currentColor" stroke-width="1.1"/></svg>
            <span>Basic</span>
          </div>
          <div class="lc-cat lc-cat-sub" data-cat="Bioinformatics">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="5" cy="5" r="1.4" fill="currentColor"/><circle cx="11" cy="5" r="1.4" fill="currentColor"/><circle cx="8" cy="11" r="1.4" fill="currentColor"/><path d="M5 5L11 5M5 5L8 11M11 5L8 11" stroke="currentColor" stroke-width="1.2"/></svg>
            <span>Bioinformatics</span>
          </div>
          <div class="lc-cat lc-cat-sub" data-cat="Classification">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 12L8 4L13 12" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><line x1="5.5" y1="9" x2="10.5" y2="9" stroke="currentColor" stroke-width="1.2"/></svg>
            <span>Classification</span>
          </div>
          <div class="lc-cat lc-cat-sub" data-cat="Clustering">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="5" cy="5" r="2" stroke="currentColor" stroke-width="1.3"/><circle cx="11" cy="5" r="2" stroke="currentColor" stroke-width="1.3"/><circle cx="8" cy="11" r="2" stroke="currentColor" stroke-width="1.3"/></svg>
            <span>Clustering</span>
          </div>
          <div class="lc-cat lc-cat-sub" data-cat="Fairness">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2V14M2 6h12M3 6l-1 3h4l-1-3M13 6l-1 3h4l-1-3" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/></svg>
            <span>Fairness</span>
          </div>
          <div class="lc-cat lc-cat-sub" data-cat="Hierarchical Clustering">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2v3M5 5v3M11 5v3M3.5 8v3M6.5 8v3M9.5 8v3M12.5 8v3M5 5h6M3.5 8h3M9.5 8h3" stroke="currentColor" stroke-width="1.2"/></svg>
            <span>Hierarchical Clustering</span>
          </div>
          <div class="lc-cat lc-cat-sub" data-cat="Scatter Plot">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="4" cy="11" r="1" fill="currentColor"/><circle cx="7" cy="7" r="1" fill="currentColor"/><circle cx="10" cy="9" r="1" fill="currentColor"/><circle cx="12" cy="4" r="1" fill="currentColor"/><circle cx="6" cy="13" r="1" fill="currentColor"/><path d="M2 14h12M2 2v12" stroke="currentColor" stroke-width="1.1"/></svg>
            <span>Scatter Plot</span>
          </div>
          <div class="lc-cat lc-cat-sub" data-cat="Survival Analysis">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 13L5 7L8 9L11 4L14 6" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M2 14h12" stroke="currentColor" stroke-width="1.1"/></svg>
            <span>Survival Analysis</span>
          </div>
          <div class="lc-cat lc-cat-sub" data-cat="Text Mining">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="3" y="3" width="10" height="10" rx="1" stroke="currentColor" stroke-width="1.3"/><line x1="5" y1="6" x2="11" y2="6" stroke="currentColor" stroke-width="1.2"/><line x1="5" y1="9" x2="11" y2="9" stroke="currentColor" stroke-width="1.2"/><line x1="5" y1="12" x2="9" y2="12" stroke="currentColor" stroke-width="1.2"/></svg>
            <span>Text Mining</span>
          </div>
          </div><!-- /#lc-example-subs -->
          <!-- 교재 BOOK 그룹 (2026-05-29) — _upload_ows_/orange3_book/ 폴더 기반
               부모 두 번 클릭 시 sub 그룹 접기 토글 (Example Workflow 와 동일 패턴) -->
          <div class="lc-cat lc-cat-parent collapsed" data-cat="교재 BOOK" data-collapse-target="lc-book-subs-host">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 2.5C3 2.2 3.2 2 3.5 2H12c.3 0 .5.2.5.5v11c0 .3-.2.5-.5.5H4.5C3.7 14 3 13.3 3 12.5v-10z" stroke="currentColor" stroke-width="1.3"/><path d="M3 12.5c0-.8.7-1.5 1.5-1.5h8" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/><line x1="5.5" y1="5" x2="10" y2="5" stroke="currentColor" stroke-width="1.1"/><line x1="5.5" y1="7.5" x2="10" y2="7.5" stroke="currentColor" stroke-width="1.1"/></svg>
            <span>교재 BOOK</span>
            <span class="lc-caret" aria-hidden="true">▾</span>
          </div>
          <div id="lc-book-subs-host" class="lc-subgroup collapsed"><!-- 책 목록 sub 항목 동적 삽입 --></div>
        </div>
        <div id="lesson-content">
          <h2 id="lesson-heading">All Templates</h2>
          <div id="lesson-source"></div>
          <!-- 교재 BOOK 정보 카드 — 책 선택 시에만 표시 -->
          <div id="lesson-book-info">
            <div class="bi-cover" id="lesson-book-cover"></div>
            <div class="bi-detail">
              <div class="bi-title" id="lesson-book-title"></div>
              <div class="bi-meta" id="lesson-book-meta"></div>
              <div class="bi-actions">
                <a class="bi-url" id="lesson-book-url" href="#" target="_blank" rel="noopener noreferrer">
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M6 4H4a2 2 0 00-2 2v6a2 2 0 002 2h6a2 2 0 002-2v-2M10 2h4v4M7 9l7-7" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  <span id="lesson-book-url-text">출판사 페이지</span>
                </a>
                <button class="bi-download" id="lesson-book-download" onclick="downloadBookZip()">다운로드</button>
              </div>
            </div>
          </div>
          <div id="lesson-grid"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── 탭 닫기 확인 모달 ── -->
  <div id="close-modal">
    <div id="close-modal-box">
      <div id="close-modal-header">
        <span id="close-modal-title">변경 내용을 저장하시겠습니까?</span>
        <span id="close-modal-x" onclick="modalCancel()">✕</span>
      </div>
      <div id="close-modal-body">
        "<span id="close-modal-wf-name"></span>"의 변경 내용을 저장하시겠습니까?
      </div>
      <div id="close-modal-hint">저장하지 않으면 변경 내용이 손실됩니다.</div>
      <div id="close-modal-btns">
        <button class="cm-btn" onclick="modalCancel()">취소</button>
        <button class="cm-btn" onclick="modalNo()">저장 안 함</button>
        <button class="cm-btn cm-save" onclick="modalSave()">저장</button>
      </div>
    </div>
  </div>

  <!-- ── 캔버스 우상단 툴바 ── -->
  <div id="canvas-toolbar">
    <div class="ct-grp">
      <button class="ct-btn" id="sb-text-btn" title="텍스트 (T) — 길게 누르면 폰트 크기 선택">
        <!-- 하단 sb-btn 톤(stroke 1.4 아웃라인)과 통일 (2026-05-26) -->
        <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M3 4H13" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
          <path d="M8 4V13" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
        </svg>
      </button>
      <!-- 폰트 크기 드롭다운: T 길게 누르면 아래로 펼쳐짐 -->
      <div id="ct-font-drop">
        <div class="ct-font-item" data-size="12" style="font-size:12px" onclick="ctPickFontSize(12)">
          <span class="ct-font-dot"></span>12px
        </div>
        <div class="ct-font-item" data-size="14" style="font-size:14px" onclick="ctPickFontSize(14)">
          <span class="ct-font-dot"></span>14px
        </div>
        <div class="ct-font-item sel" data-size="16" style="font-size:16px" onclick="ctPickFontSize(16)">
          <span class="ct-font-dot"></span>16px
        </div>
        <div class="ct-font-item" data-size="18" style="font-size:18px" onclick="ctPickFontSize(18)">
          <span class="ct-font-dot"></span>18px
        </div>
        <div class="ct-font-item" data-size="20" style="font-size:20px" onclick="ctPickFontSize(20)">
          <span class="ct-font-dot"></span>20px
        </div>
        <div class="ct-font-item" data-size="22" style="font-size:22px" onclick="ctPickFontSize(22)">
          <span class="ct-font-dot"></span>22px
        </div>
        <div class="ct-font-item" data-size="24" style="font-size:24px" onclick="ctPickFontSize(24)">
          <span class="ct-font-dot"></span>24px
        </div>
      </div>
    </div>
    <div class="ct-grp">
      <button class="ct-btn" id="sb-pen-btn" title="화살표 주석 — 길게 누르면 색상 선택">
        <!-- 하단 sb-btn 톤(stroke 1.4 아웃라인)과 통일 (2026-05-26) -->
        <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M1.5 14
                   C 4.5 12.5 8 9 10.5 4.5
                   L 8 6
                   L 11.5 0.5
                   L 15.5 5.5
                   L 13.25 3.25
                   C 11 8.5 7.5 13 1.5 14 Z"
                stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
        </svg>
      </button>
      <!-- 화살표 색상 드롭다운: 펜 길게 누르면 아래로 펼쳐짐 (Orange3 내장 5색) -->
      <div id="ct-color-drop">
        <div class="ct-color-item"      data-color="000"    style="background:#000000" onclick="ctPickPenColor('000')"></div>
        <div class="ct-color-item sel"  data-color="C1272D" style="background:#C1272D" onclick="ctPickPenColor('C1272D')"></div>
        <div class="ct-color-item"      data-color="662D91" style="background:#662D91" onclick="ctPickPenColor('662D91')"></div>
        <div class="ct-color-item"      data-color="1F9CDF" style="background:#1F9CDF" onclick="ctPickPenColor('1F9CDF')"></div>
        <div class="ct-color-item"      data-color="39B54A" style="background:#39B54A" onclick="ctPickPenColor('39B54A')"></div>
      </div>
    </div>
    <button class="ct-btn" id="sb-pause-btn" title="신호 전파 중단/재개 (Shift+F)" onclick="sbShortcut('pause')">
      <!-- 하단 sb-btn 톤(stroke 1.4 아웃라인)과 통일 (2026-05-26) -->
      <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="4" y="3" width="3" height="10" rx="1" stroke="currentColor" stroke-width="1.4"/>
        <rect x="9" y="3" width="3" height="10" rx="1" stroke="currentColor" stroke-width="1.4"/>
      </svg>
    </button>
    <button class="ct-btn" title="새 탭 (새 워크플로우)" onclick="wfAddTab()">
      <!-- 하단 sb-btn 톤(stroke 1.4)과 통일 (2026-05-26): 1.8 → 1.4 -->
      <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M4 2H9.5L13 5.5V14H4V2Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
        <path d="M9.5 2V5.5H13" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="8" y1="8" x2="8" y2="12" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
        <line x1="6" y1="10" x2="10" y2="10" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
      </svg>
    </button>
    <button class="ct-btn" id="sb-info-btn" title="도움말 / 도구 안내" onclick="ctShowInfo()">
      <!-- 하단 sb-btn 톤(stroke 1.4 아웃라인)과 통일 (2026-05-26) -->
      <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="8" cy="8" r="6.2" stroke="currentColor" stroke-width="1.4"/>
        <circle cx="8" cy="5" r="0.85" fill="currentColor"/>
        <line x1="8" y1="7.4" x2="8" y2="11.6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
      </svg>
    </button>
  </div>

  <!-- ── 좌하단 상태바 ── -->
  <div id="sb-wrap">
    <div class="sb-grp">
      <button class="sb-btn" id="sb-tool-btn" onclick="sbToggleDrop('tool')" title="도구 선택">
        <svg id="sb-tool-ico" width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M3.5 3 L12.5 9 L8.5 10 L7.2 13.5 Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
        </svg>
        <svg width="9" height="6" viewBox="0 0 7 5" fill="none"><path d="M1 1L3.5 4L6 1" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
      </button>
      <div class="sb-drop" id="sb-drop-tool">
        <div class="sb-di" onclick="sbTool('select')">
          <span class="ico"><svg width="18" height="18" viewBox="0 0 16 16" fill="none"><path d="M3.5 3 L12.5 9 L8.5 10 L7.2 13.5 Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/></svg> Select</span>
          <span class="sb-key">V</span>
        </div>
        <div class="sb-di" onclick="sbTool('hand')">
          <span class="ico"><svg width="18" height="18" viewBox="0 0 16 16" fill="none"><path d="M6 11V5C6 4.5 6.5 4 7 4S8 4.5 8 5V8M8 5V4C8 3.5 8.5 3 9 3S10 3.5 10 4V8M10 4.5V4C10 3.5 10.5 3 11 3S12 3.5 12 4V9M12 6V5.5C12 5 12.5 4.5 13 4.5S14 5 14 5.5V11C14 12.5 12 14 10 14H8C6.5 14 5.5 13 4.5 11.5L3 9.5C2.5 8.5 3.5 7.5 4.5 8L6 9" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/></svg> Hand</span>
          <span class="sb-key">H</span>
        </div>
      </div>
    </div>
    <div class="sb-sep"></div>
    <button class="sb-btn" id="sb-fixview-btn" title="FIX VIEW — 미니맵 위젯 자동 추적 켜기/끄기" onclick="sbFixView()">
      <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M4 1H1V4M12 1H15V4M4 15H1V12M12 15H15V12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        <circle cx="8" cy="8" r="1.5" fill="currentColor"/>
      </svg>
    </button>
    <div class="sb-sep"></div>
    <button class="sb-btn" title="전체 보기 (Ctrl+0)" onclick="sbFit()">
      <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="1" y="3" width="14" height="10" rx="1.5" stroke="currentColor" stroke-width="1.3"/>
        <rect x="3" y="5" width="4" height="3" rx="0.5" fill="currentColor" opacity="0.5"/>
        <rect x="9" y="8" width="4" height="3" rx="0.5" fill="currentColor" opacity="0.5"/>
      </svg>
    </button>
    <div class="sb-sep"></div>
    <button class="sb-btn" id="sb-zoom-out-btn" title="축소 (Ctrl −)" onclick="sbZoom('out')">
      <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="6.5" cy="6.5" r="4.5" stroke="currentColor" stroke-width="1.4"/>
        <line x1="9.8" y1="9.8" x2="14" y2="14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
        <line x1="4" y1="6.5" x2="9" y2="6.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
      </svg>
    </button>
    <div class="sb-grp">
      <button class="sb-btn" id="sb-zoom-btn" onclick="sbToggleDrop('zoom')" title="줌">
        <span id="sb-zoom-pct">100%</span>
        <svg width="9" height="6" viewBox="0 0 7 5" fill="none"><path d="M1 1L3.5 4L6 1" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
      </button>
      <div class="sb-drop" id="sb-drop-zoom">
        <div class="sb-di" onclick="sbZoom('in')"><span class="ico">확대</span><span class="sb-key">Ctrl ＋</span></div>
        <div class="sb-di" onclick="sbZoom('out')"><span class="ico">축소</span><span class="sb-key">Ctrl －</span></div>
        <div class="sb-di" onclick="sbZoom('fit')"><span class="ico">전체 보기</span><span class="sb-key">Ctrl 0</span></div>
        <div class="sb-zoom-row">
          <input id="sb-zoom-input" type="number" min="10" max="400" value="100"
                 onchange="sbZoomSet(this.value)"
                 onkeydown="if(event.key==='Enter'){{sbZoomSet(this.value);event.preventDefault();}}">
          <span style="color:#888;font-size:11px">%</span>
        </div>
      </div>
    </div>
    <button class="sb-btn" id="sb-zoom-in-btn" title="확대 (Ctrl ＋)" onclick="sbZoom('in')">
      <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="6.5" cy="6.5" r="4.5" stroke="currentColor" stroke-width="1.4"/>
        <line x1="9.8" y1="9.8" x2="14" y2="14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
        <line x1="4" y1="6.5" x2="9" y2="6.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
        <line x1="6.5" y1="4" x2="6.5" y2="9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
      </svg>
    </button>
    <div class="sb-sep"></div>
    <button class="sb-btn" id="sb-map-btn" title="미니맵 켜기/끄기" onclick="sbToggleMap()">
      <svg width="18" height="18" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M1 3.5L5.5 2L10.5 3.5L15 2V12.5L10.5 14L5.5 12.5L1 14V3.5Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/>
        <line x1="5.5" y1="2"   x2="5.5"  y2="12.5" stroke="currentColor" stroke-width="1.1"/>
        <line x1="10.5" y1="3.5" x2="10.5" y2="14"   stroke="currentColor" stroke-width="1.1"/>
      </svg>
    </button>
  </div>

  <!-- ── 미니맵 패널 (Tier A3: 진단보고서 U3 — 기본 접힘 상태) ── -->
  <div id="sb-minimap" style="display:none;">
    <div id="sb-minimap-header">
      <span id="sb-minimap-label">
        <svg width="13" height="13" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect x="1" y="1" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.4"/>
          <rect x="9" y="1" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.4"/>
          <rect x="1" y="9" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.4"/>
          <rect x="9" y="9" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.4"/>
        </svg>
        <span id="sb-minimap-label-text">미니맵</span>
      </span>
      <div id="sb-minimap-close" onclick="sbToggleMap()" title="미니맵 닫기">✕</div>
    </div>
    <div id="sb-minimap-body">
      <img id="sb-minimap-img" src="" alt="" style="display:none;">
      <div id="sb-minimap-disc">연결 안됨</div>
      <div id="sb-minimap-overlay">
        <div id="sb-vp-rect"></div>
      </div>
    </div>
  </div>

  <!-- ── 한글 입력 도우미 (2026-05-22) ── -->
  <div id="sb-ime-panel">
    <div id="sb-ime-header">
      <span>한글 입력 도우미</span>
      <div id="sb-ime-close" onclick="sbToggleIme()" title="닫기">✕</div>
    </div>
    <div id="sb-ime-body">
      <div id="sb-ime-hint">
        Orange3 안의 텍스트 입력 위치(예: 텍스트 주석)를 먼저 클릭한 뒤,
        아래 칸에 한글을 입력하고 <b>Enter</b> 를 누르세요.
      </div>
      <input id="sb-ime-input" type="text" autocomplete="off"
             placeholder="한글 입력 후 Enter">
    </div>
  </div>

  <!-- ── 패닝 오버레이 (Hand 툴 활성 시 표시) ── -->
  <div id="pan-overlay"></div>

  <script>
    /* ── noVNC resize=remote 재전송: 1px 줄임→복원으로 resize 이벤트 유발 ── */
    (function() {{
      var frame = document.getElementById('vnc-frame');
      function nudgeResize() {{
        frame.style.right = '1px';
        // 50ms로 단축 — 1px 변경 자체는 거의 즉시 노VNC가 감지함 (이전 200ms은 과한 여유)
        setTimeout(function() {{ frame.style.right = '0px'; }}, 50);
      }}
      frame.addEventListener('load', function() {{
        // 연결 후 1.5초 대기 → noVNC가 완전히 초기화된 뒤 resize 재전송
        setTimeout(nudgeResize, 1500);
      }});

      /* ── 리사이즈 대응: scaling=local로 클라이언트 즉시 스케일링 → 커버 거의 불필요 ──
         핵심 변화:
         · scaling=local: noVNC가 viewport 변경 시 기존 프레임을 GPU로 즉시 스케일 → 시각 즉시 반영
         · 커버 opacity 1.0 → 0.0 (불필요) — scaling=local이 본체 시각 처리하므로 흰색 마스크 제거
         · 디바운스 150 → 120ms (서버 측 framebuffer 정확도 회복 더 빨리)
         · 첫 이벤트 즉시 nudge 유지 */
      var _resizeTimer = null;
      var _resizeFirstFired = false;
      var _cover = document.getElementById('vnc-cover');
      var _maskL = document.getElementById('resize-mask-left');
      var _maskT = document.getElementById('resize-mask-top');
      // GPU 가속 힌트 — iframe transform/resize가 GPU에서 처리되도록
      if (frame) frame.style.willChange = 'transform';
      window.addEventListener('resize', function() {{
        // 마스크 즉시 표시 — 왼쪽 위젯 독·상단 이동을 가려 시각 안정화
        if (_maskL) _maskL.classList.add('active');
        if (_maskT) _maskT.classList.add('active');
        // scaling=local 덕에 본체 커버는 거의 불필요 — 매우 옅은 회색 hint만
        if (_cover) {{
          _cover.style.opacity = '0.12';
          _cover.style.transition = 'opacity 0.05s ease-in';
        }}
        if (!_resizeFirstFired) {{
          _resizeFirstFired = true;
          nudgeResize();
        }}
        clearTimeout(_resizeTimer);
        _resizeTimer = setTimeout(function() {{
          nudgeResize();
          if (_cover) {{ _cover.style.transition = 'opacity 0.1s ease-out'; _cover.style.opacity = '0'; }}
          // 마스크는 350ms 추가 지연 후 제거 — 서버 측 framebuffer 회복 + 위젯 독 정위치 회복 시점에 맞춰
          // 페이드 아웃 자체도 transition 늘려 부드러운 메뉴 등장 효과
          setTimeout(function() {{
            if (_maskL) {{ _maskL.style.transition = 'opacity 0.2s ease-out'; _maskL.classList.remove('active'); }}
            if (_maskT) {{ _maskT.style.transition = 'opacity 0.2s ease-out'; _maskT.classList.remove('active'); }}
            // 다음 리사이즈를 위해 transition 원복 (다음 .active 추가는 0.08s 빠른 페이드 인)
            setTimeout(function() {{
              if (_maskL) _maskL.style.transition = 'opacity 0.08s ease-in';
              if (_maskT) _maskT.style.transition = 'opacity 0.08s ease-in';
            }}, 250);
          }}, 350);
          _resizeFirstFired = false;
        }}, 120);
      }});

      // 흰색 커버 제거:
      // 조건 1 (서버): /screenshot 폴링 → X11에 Orange3 화면이 실제로 렌더됨 확인
      // 조건 2 (클라이언트): vnc-frame load 이후 최소 4초 경과 → noVNC가 VNC 데이터 수신·렌더 완료
      // 두 조건 모두 충족된 시점에 커버를 제거해 "미니맵은 보이는데 캔버스는 비어있는" 현상 방지
      (function() {{
        var _sid = "{sid}";
        var _started = Date.now();
        var _maxWait = 60000;
        var _interval = 800;
        var RESIZE_SETTLE_MS = 1500;    // resize=remote 완료까지 최소 보장 대기
        var _iframeLoadTime = Date.now(); // 기본값: 페이지 로드 시각
        var _doneToastShown = false;      // 로딩 완료 '완료' 알림 1회만 (2026-05-22)
        var frame = document.getElementById('vnc-frame');
        if (frame) {{
          frame.addEventListener('load', function() {{
            _iframeLoadTime = Date.now();
          }});
        }}
        function _removeCover() {{
          var cover = document.getElementById('vnc-cover');
          if (cover) {{
            cover.style.opacity = '0';
            setTimeout(function() {{ if (cover && cover.parentNode) cover.parentNode.removeChild(cover); }}, 600);
          }}
          /* Orange3 준비 완료 → noVNC iframe 자동 포커스 (키보드 이벤트 즉시 활성화) */
          var frame = document.getElementById('vnc-frame');
          if (frame) frame.focus();
          /* 로딩 완료 알림 — 캔버스 렌더 완료 시 '완료' 토스트 1회 (2026-05-22) */
          if (!_doneToastShown) {{
            _doneToastShown = true;
            if (typeof showToast === 'function') showToast('완료', 2000);
          }}
        }}
        /* 스크린샷 좌측상단(위젯 독 영역) 픽셀 평균 밝기 확인
           - 스플래시+검은 배경: 밝기 < 80  → 아직 로딩 중
           - 메인 캔버스(흰/회색): 밝기 ≥ 80 → 커버 제거 가능 */
        function _checkBright(blob) {{
          return new Promise(function(resolve) {{
            var url = URL.createObjectURL(blob);
            var img = new Image();
            img.onload = function() {{
              try {{
                var c = document.createElement('canvas');
                c.width = 80; c.height = 80;
                var ctx = c.getContext('2d');
                ctx.drawImage(img, 0, 0, 80, 80);
                var d = ctx.getImageData(0, 0, 80, 80).data;
                var sum = 0;
                for (var i = 0; i < d.length; i += 4) sum += (d[i] + d[i+1] + d[i+2]) / 3;
                resolve((sum / (d.length / 4)) > 80);
              }} catch(e) {{ resolve(true); }}
              URL.revokeObjectURL(url);
            }};
            img.onerror = function() {{ URL.revokeObjectURL(url); resolve(false); }};
            img.src = url;
          }});
        }}
        /* Tier A4 (2026-05-21): 진단보고서 U2 — 60초 초과 시 에러 UI + 재시도 버튼 */
        function _showCoverError(reason) {{
          var cover = document.getElementById('vnc-cover');
          if (!cover) return;
          var _ERR_LBL = {{
            ko: {{ title: 'Orange3 시작이 지연되고 있습니다',
                   desc:  '예상보다 시간이 오래 걸립니다. 네트워크 상태를 확인하고 다시 시도해 주세요.',
                   retry: '다시 시도' }},
            en: {{ title: 'Orange3 startup is delayed',
                   desc:  'It is taking longer than expected. Check your network and try again.',
                   retry: 'Retry' }},
            sl: {{ title: 'Zagon Orange3 je upočasnjen',
                   desc:  'Postopek traja dlje, kot je pričakovano. Preverite povezavo in poskusite znova.',
                   retry: 'Poskusi znova' }}
          }};
          var _L = _ERR_LBL['{init_lang}'] || _ERR_LBL.en;
          cover.innerHTML =
            '<div class="sk-header"></div>' +
            '<div class="sk-tabbar"></div>' +
            '<div class="sk-canvas" style="gap:14px;">' +
              '<div style="font-size:54px;color:#F47B20;line-height:1;">⚠</div>' +
              '<div style="font-size:17px;color:#222;font-weight:600;">' + _L.title + '</div>' +
              '<div style="font-size:13px;color:#888;max-width:440px;text-align:center;line-height:1.6;">' +
                _L.desc +
                '<br><span style="opacity:0.6;font-size:11px;">(' + reason + ')</span>' +
              '</div>' +
              '<button onclick="location.reload()" style="margin-top:6px;padding:10px 28px;border-radius:6px;border:0;background:#F47B20;color:#fff;font-size:14px;cursor:pointer;font-weight:600;">' + _L.retry + '</button>' +
            '</div>';
        }}
        function _pollScreenshot() {{
          if (!document.getElementById('vnc-cover')) return;
          fetch('/screenshot?sid=' + _sid + '&t=' + Date.now())
            .then(function(r) {{
              // 세션 부재(404) — 보통 session-manager 재시작·세션 만료.
              // 사용자 sid 가 무효 → 페이지 새로고침으로 새 세션 발급.
              if (r.status === 404) {{
                location.replace('/');
                return;
              }}
              if (r.ok && r.headers.get('content-type') && r.headers.get('content-type').startsWith('image/')) {{
                r.blob().then(function(blob) {{
                  _checkBright(blob).then(function(bright) {{
                    if (bright) {{
                      // 메인 캔버스 확인 → 커버 제거. 단, post-load nudgeResize(=프레임버퍼
                      // 재정렬)가 iframe load +1500ms 에 발화하므로, 그 정착 이후까지 커버를
                      // 유지해야 한다. 그 전에 제거하면 리사이즈 정착 중 캔버스 경계가
                      // 검은 라인으로 잠깐 노출됨(언어 변경 후 로딩에서 재현, 2026-06-02).
                      var NUDGE_DELAY_MS = 1500;   // = frame.load 후 nudgeResize 발화 시점
                      var elapsed = Date.now() - _iframeLoadTime;
                      var wait = Math.max(RESIZE_SETTLE_MS,
                                          NUDGE_DELAY_MS + RESIZE_SETTLE_MS - elapsed);
                      setTimeout(_removeCover, wait);
                    }} else {{
                      // 아직 어두움(스플래시/검은 배경) → 0.5초 후 재폴링
                      if (Date.now() - _started < _maxWait) setTimeout(_pollScreenshot, 500);
                      else _showCoverError('렌더 대기 60초 초과');
                    }}
                  }});
                }});
              }} else {{
                if (Date.now() - _started < _maxWait) setTimeout(_pollScreenshot, _interval);
                else _showCoverError('스크린샷 응답 형식 오류');
              }}
            }})
            .catch(function() {{
              if (Date.now() - _started < _maxWait) setTimeout(_pollScreenshot, _interval);
              else _showCoverError('스크린샷 요청 실패');
            }});
        }}
        setTimeout(_pollScreenshot, 500);
        // Safety net: iframe load 후 20초 경과해도 cover 가 남아있으면 강제 제거.
        // 스크린샷 폴링이 지속 실패하거나 brightness 임계 미달인 corner case 대응.
        if (frame) {{
          frame.addEventListener('load', function() {{
            setTimeout(function() {{
              if (document.getElementById('vnc-cover')) {{
                console.warn('[cover] safety net 20s → force remove');
                _removeCover();
              }}
            }}, 20000);
          }});
        }}
      }})();
    }})();

    let SID = "{sid}";

    /* ── 이 탭의 sessionStorage에 SID 저장 (탭별 세션 분리) ──
     * xpra-wrapped 와 noVNC 는 sid 공간이 분리되어 별도 키 사용 — 한 탭에서
     * /xpra-wrapped/<sid> 열어뒀다가 / 로 이동해도 서로 덮어쓰지 않음.
     *
     * 중요: window._isXpra 는 URL 마스킹 *전에* 한 번 결정해 전역 보관.
     * 마스킹 후 location.pathname 으로 다시 검사하면 잘못된 판정을 내림
     * (`/xpra-wrapped` 는 `/xpra-wrapped/` 의 prefix 가 아님). */
    window._isXpra = (location.pathname.indexOf('/xpra-wrapped/') === 0);
    try {{
      sessionStorage.setItem(window._isXpra ? 'orange3_xpra_sid' : 'orange3_sid', SID);
      // F5 새로고침 시 dispatch 가 마지막 선택 언어를 복원할 수 있도록 함께 저장 (2026-05-27).
      // INIT_LANG 은 이 스크립트 뒤에 정의되므로 Python format placeholder 로 직접 주입.
      var _curLang = '{init_lang}';
      if (_curLang && ['ko','en','sl'].indexOf(_curLang) >= 0)
        sessionStorage.setItem('orange3_lang', _curLang);
    }} catch(_) {{}}

    /* ── Tier B6 (2026-05-21) + 2026-05-26 xpra 보강: URL 바에서 SID 제거 ──
     * 진단보고서 S2 대응. 쿠키화는 탭별 세션 분리 모델과 충돌하므로 채택 안 함.
     * 대신 history.replaceState 로 URL 바·브라우저 히스토리·화면 공유 노출 차단.
     *   - noVNC: `/?sid=...&lang=...` → `/`
     *   - xpra : `/xpra-wrapped/<sid>` → `/xpra-wrapped`
     * SID 는 JS 변수와 sessionStorage 에 유지 → 모든 fetch 정상 동작.
     * 새로고침 시 dispatch 페이지(/, /xpra-wrapped)가 sessionStorage 로 복원. */
    try {{
      if (window._isXpra) {{
        history.replaceState({{}}, '', '/xpra-wrapped');
      }} else if (location.search) {{
        history.replaceState({{}}, '', location.pathname);
      }}
    }} catch(_) {{}}

    /* ── 세션 keepalive: 2분마다 /ping 호출로 last_seen 갱신 (30분 타임아웃 방지) ── */
    (function() {{
      function ping() {{ fetch('/ping?sid=' + SID).catch(function(){{}}); }}
      ping();  // 페이지 로드 즉시 1회
      setInterval(ping, 120000);  // 이후 2분마다
    }})();

    /* ── Phase 2 (2026-05-21): SSE 통합 이벤트 버스 ─────────────────────────
     * 진단보고서 P1 — 11개 폴 엔드포인트를 단일 /api/events 채널로 통합.
     * 설계서: _md_file_/sse_migration_plan.md
     * Phase 2 에서는 dataset 1건만 SSE 로 전환하고 나머지 폴은 그대로 유지.
     * Phase 3 에서 upload-* 9종을 한 영역씩 순차 전환.
     */
    /* 진단 메시지 가시성: console.warn (노란색) 사용 — info 필터 우회 */
    console.warn('[SseBus] IIFE init starting (parent window) — sid=' + (typeof SID !== 'undefined' ? SID : '?'));
    const SseBus = (function() {{
      var es = null;
      var backoff = 1000;
      var maxBackoff = 30000;
      var explicitlyClosed = false;
      var listeners = {{}};   // {{eventName: [handler, ...]}}
      function _bind(name) {{
        if (!es) return;
        es.addEventListener(name, function(ev) {{
          var arr = listeners[name];
          if (arr) for (var i = 0; i < arr.length; i++) {{
            try {{ arr[i](ev); }} catch(e) {{ console.error('[SseBus]', name, e); }}
          }}
        }});
      }}
      function connect() {{
        if (explicitlyClosed) return;
        console.warn('[SseBus] connecting to /api/events?sid=' + SID);
        try {{ es = new EventSource('/api/events?sid=' + SID); }}
        catch(e) {{ console.error('[SseBus] EventSource 생성 실패', e); return; }}
        // 표준 이벤트
        es.addEventListener('hello', function(e) {{
          backoff = 1000;  // 연결 성공 → 백오프 리셋
          console.warn('[SseBus] ✓ connected', e.data);
        }});
        es.addEventListener('reconnect', function() {{
          // 서버가 1시간 수명 한도 도달 → 즉시 재연결 (백오프 없이)
          if (es) {{ es.close(); es = null; }}
          setTimeout(connect, 500);
        }});
        es.addEventListener('session-gone', function() {{
          // 세션 만료/삭제 → 새 세션으로 dispatch
          explicitlyClosed = true;
          if (es) {{ es.close(); es = null; }}
          var lang = (typeof INIT_LANG !== 'undefined') ? INIT_LANG : 'en';
          location.replace('/?sid=new&lang=' + lang);
        }});
        // 등록 시점에 알려진 커스텀 이벤트 모두 바인딩
        for (var n in listeners) if (listeners.hasOwnProperty(n)) _bind(n);
        // 오류 시 지수 백오프 재연결
        es.onerror = function(e) {{
          var rs = es ? es.readyState : -1;
          console.warn('[SseBus] ✗ EventSource error, readyState=' + rs + ', retry in ' + backoff + 'ms');
          if (es) {{ es.close(); es = null; }}
          if (explicitlyClosed) return;
          setTimeout(connect, backoff);
          backoff = Math.min(backoff * 2, maxBackoff);
        }};
      }}
      connect();
      return {{
        on: function(eventName, handler) {{
          if (!listeners[eventName]) {{
            listeners[eventName] = [];
            // 이미 연결된 후라면 즉시 바인딩 (재연결 시는 connect 내부 루프에서 바인딩)
            _bind(eventName);
          }}
          listeners[eventName].push(handler);
        }},
        _debug: function() {{ return {{ es: es, readyState: es ? es.readyState : -1, listeners: Object.keys(listeners) }}; }}
      }};
    }})();

    /* ── 파일 업로드 트리거 ── */
    const POLL_INTERVAL = 4000;
    let lastTriggered = 0;         // (deprecated, 본문에서 미사용 — 외부 참조 호환 위해 보존)
    /* Phase 5 hotfix (2026-05-21): cooldown 을 이벤트별로 분리 — 한 버튼 클릭이
     * 5초간 다른 모든 버튼을 차단하던 공유 lastTriggered 버그 수정.
     * 같은 이벤트의 빠른 중복은 차단하되, 다른 이벤트는 즉시 처리 가능. */
    const lastTriggeredBy = {{}};   // {{eventName: timestamp}}
    const TRIGGER_COOLDOWN = 1500;  // 단발 중복 보호 (이전 5000 → 1500 으로 단축)

    document.getElementById('pc-file-input').addEventListener('change', async function() {{
      const fileArray = Array.from(this.files);
      this.value = '';
      if (!fileArray.length) return;
      showToast(`${{fileArray.length}}개 파일 업로드 중...`);
      const uploaded = [], errors = [];
      for (const file of fileArray) {{
        const fd = new FormData();
        fd.append('file', file);
        try {{
          const r = await fetch('/upload?sid=' + SID, {{ method:'POST', body:fd }});
          const d = await r.json();
          if (d.filename) uploaded.push(d.filename);
          else errors.push(`${{file.name}}: ${{d.error || '서버 오류'}}`);
        }} catch (e) {{
          errors.push(`${{file.name}}: 네트워크 오류`);
        }}
      }}
      if (uploaded.length) showToast(`✓ 업로드 완료: ${{uploaded.join(', ')}}`, 4000);
      if (errors.length)   showToast(`✗ 실패: ${{errors.join(' | ')}}`, 5000);
    }});

    /* Phase 3 (2026-05-21): setInterval(pollUploadRequest, ...) → SSE */
    SseBus.on('upload-request', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request'] = Date.now();
      document.getElementById('pc-file-input').click();
    }});

    /* ── Load Model 전용 업로드 폴링 (accept=".pkcls") ── */
    document.getElementById('model-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`모델 업로드 중: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=model', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ 모델 업로드: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});

    /* Phase 3 (2026-05-21): setInterval(pollModelUploadRequest, ...) → SSE */
    SseBus.on('upload-request-model', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-model'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-model'] = Date.now();
      document.getElementById('model-file-input').click();
    }});

    /* ── Import Images 전용 폴더 업로드 폴링 (webkitdirectory) ── */
    document.getElementById('image-folder-input').addEventListener('change', async function() {{
      const fileArray = Array.from(this.files);
      this.value = '';
      if (!fileArray.length) return;
      // 이미지 확장자만 필터링
      const imgExts = ['.png','.jpg','.jpeg','.gif','.tiff','.tif','.bmp','.webp','.ico','.svg'];
      const imageFiles = fileArray.filter(function(f) {{
        const lower = f.name.toLowerCase();
        return imgExts.some(function(ext) {{ return lower.endsWith(ext); }});
      }});
      if (!imageFiles.length) {{
        showToast('이미지 파일이 없습니다', 3000);
        return;
      }}
      showToast(`${{imageFiles.length}}개 이미지 업로드 중...`, 5000);
      // multipart 한 번에 모든 파일 + 각 파일의 webkitRelativePath 전송
      const fd = new FormData();
      for (const f of imageFiles) {{
        // file 필드와 동일 인덱스의 relpath 필드 → 서버에서 페어링
        fd.append('files', f);
        fd.append('relpaths', f.webkitRelativePath || f.name);
      }}
      try {{
        const r = await fetch('/upload-images?sid=' + SID, {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.ok) showToast(`✓ ${{d.count}}개 이미지 업로드 완료 → ${{d.dir}}`, 4000);
        else showToast(`✗ 업로드 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});

    /* Phase 3 (2026-05-21): setInterval(pollImageFolderUploadRequest, ...) → SSE */
    SseBus.on('upload-request-images', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-images'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-images'] = Date.now();
      document.getElementById('image-folder-input').click();
    }});

    /* ── Corpus 위젯 전용 코퍼스 파일 업로드 폴링 (.tab/.csv/.tsv/.txt) ── */
    document.getElementById('corpus-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`코퍼스 업로드 중: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=corpus', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ 코퍼스 업로드: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});

    /* Phase 3 (2026-05-21): setInterval(pollCorpusUploadRequest, ...) → SSE */
    SseBus.on('upload-request-corpus', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-corpus'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-corpus'] = Date.now();
      document.getElementById('corpus-file-input').click();
    }});

    /* ── Import Documents 전용 폴더 업로드 폴링 (webkitdirectory, 모든 파일) ── */
    document.getElementById('documents-folder-input').addEventListener('change', async function() {{
      const fileArray = Array.from(this.files);
      this.value = '';
      if (!fileArray.length) return;
      // Import Documents 는 .txt/.pdf/.docx/.conllu/.html 등 다양 — 텍스트성 확장자 우선
      const docExts = ['.txt','.pdf','.docx','.doc','.html','.htm','.xml','.json','.csv','.tsv','.conllu','.md','.rtf','.odt'];
      const docFiles = fileArray.filter(function(f) {{
        const lower = f.name.toLowerCase();
        return docExts.some(function(ext) {{ return lower.endsWith(ext); }});
      }});
      if (!docFiles.length) {{
        showToast('문서 파일이 없습니다 (.txt/.pdf/.docx 등)', 3000);
        return;
      }}
      showToast(`${{docFiles.length}}개 문서 업로드 중...`, 5000);
      const fd = new FormData();
      for (const f of docFiles) {{
        fd.append('files', f);
        fd.append('relpaths', f.webkitRelativePath || f.name);
      }}
      try {{
        const r = await fetch('/upload-documents?sid=' + SID, {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.ok) showToast(`✓ ${{d.count}}개 문서 업로드 완료 → ${{d.dir}}`, 4000);
        else showToast(`✗ 업로드 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});

    /* Phase 3 (2026-05-21): setInterval(pollDocumentsFolderUploadRequest, ...) → SSE */
    SseBus.on('upload-request-documents', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-documents'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-documents'] = Date.now();
      document.getElementById('documents-folder-input').click();
    }});

    /* ── Distance File 위젯 전용 파일 업로드 폴링 (.dst/.xlsx) ── */
    document.getElementById('distance-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`거리행렬 업로드 중: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=distance', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ 거리행렬 업로드: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});

    /* Phase 3 (2026-05-21): setInterval(pollDistanceUploadRequest, ...) → SSE */
    SseBus.on('upload-request-distance', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-distance'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-distance'] = Date.now();
      document.getElementById('distance-file-input').click();
    }});

    /* ── Network File 위젯 전용 파일 업로드 폴링 (.net/.pajek) ── */
    document.getElementById('network-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`네트워크 파일 업로드 중: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=network', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ 네트워크 업로드: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});

    /* Phase 3 (2026-05-21): setInterval(pollNetworkUploadRequest, ...) → SSE */
    SseBus.on('upload-request-network', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-network'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-network'] = Date.now();
      document.getElementById('network-file-input').click();
    }});

    /* ── Sentiment Analysis 위젯 전용 Custom dictionary 업로드 (Pos/Neg 두 슬롯) ── */
    document.getElementById('sent-pos-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Positive 사전 업로드: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=sent_pos', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ Positive 사전: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});
    /* Phase 3 (2026-05-21): setInterval(pollSentPosUploadRequest, ...) → SSE */
    SseBus.on('upload-request-sent-pos', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-sent-pos'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-sent-pos'] = Date.now();
      document.getElementById('sent-pos-file-input').click();
    }});

    document.getElementById('sent-neg-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Negative 사전 업로드: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=sent_neg', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ Negative 사전: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});
    /* Phase 3 (2026-05-21): setInterval(pollSentNegUploadRequest, ...) → SSE */
    SseBus.on('upload-request-sent-neg', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-sent-neg'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-sent-neg'] = Date.now();
      document.getElementById('sent-neg-file-input').click();
    }});

    /* ── Preprocess Text 위젯 — Stopwords / Lexicon 파일 업로드 (2026-05-28) ── */
    document.getElementById('stopwords-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Stopwords 업로드: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=stopwords', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ Stopwords: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});
    SseBus.on('upload-request-stopwords', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-stopwords'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-stopwords'] = Date.now();
      document.getElementById('stopwords-file-input').click();
    }});

    document.getElementById('lexicon-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Lexicon 업로드: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=lexicon', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ Lexicon: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});
    SseBus.on('upload-request-lexicon', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-lexicon'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-lexicon'] = Date.now();
      document.getElementById('lexicon-file-input').click();
    }});

    /* ── Single Cell · Load Data — Cell / Gene annotation 파일 업로드 (2026-05-28) ── */
    document.getElementById('sc-cell-anno-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Cell annotation 업로드: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=sc_cell_anno', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ Cell anno: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});
    SseBus.on('upload-request-sc-cell-anno', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-sc-cell-anno'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-sc-cell-anno'] = Date.now();
      document.getElementById('sc-cell-anno-file-input').click();
    }});

    document.getElementById('sc-gene-anno-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Gene annotation 업로드: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=sc_gene_anno', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ Gene anno: ${{d.filename}}`, 4000);
        else            showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});
    SseBus.on('upload-request-sc-gene-anno', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-sc-gene-anno'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-sc-gene-anno'] = Date.now();
      document.getElementById('sc-gene-anno-file-input').click();
    }});

    /* ── Spectroscopy · Multifile — 다중 파일 업로드 (2026-05-28) ── */
    document.getElementById('spec-multifile-input').addEventListener('change', async function() {{
      const files = Array.from(this.files);
      this.value = '';
      if (!files.length) return;
      showToast(`Multifile 업로드 중: ${{files.length}}개 파일`, 5000);
      const fd = new FormData();
      for (const f of files) fd.append('files', f);
      try {{
        const r = await fetch('/upload-spec-multifile?sid=' + SID, {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.ok) showToast(`✓ Multifile: ${{d.count}}개 파일 업로드`, 4000);
        else showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});
    SseBus.on('upload-request-spec-multifile', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-spec-multifile'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-spec-multifile'] = Date.now();
      document.getElementById('spec-multifile-input').click();
    }});

    /* ── Spectroscopy · Tile File 단일 파일 업로드 (2026-05-28) ── */
    document.getElementById('spec-tilefile-input').addEventListener('change', async function() {{
      const file = this.files[0];
      this.value = '';
      if (!file) return;
      showToast(`Tile File 업로드: ${{file.name}}`);
      const fd = new FormData();
      fd.append('file', file);
      try {{
        const r = await fetch('/upload?sid=' + SID + '&kind=spec_tilefile', {{ method:'POST', body:fd }});
        const d = await r.json();
        if (d.filename) showToast(`✓ Tile File: ${{d.filename}}`, 4000);
        else showToast(`✗ 실패: ${{d.error || '서버 오류'}}`, 5000);
      }} catch (e) {{
        showToast(`✗ 네트워크 오류`, 5000);
      }}
    }});
    SseBus.on('upload-request-spec-tilefile', function() {{
      if ((Date.now() - (lastTriggeredBy['upload-request-spec-tilefile'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['upload-request-spec-tilefile'] = Date.now();
      document.getElementById('spec-tilefile-input').click();
    }});

    /* ── Dataset 카탈로그 호출 폴링 (File 위젯 Dataset 버튼) ── */
    /* 분류(Classification) 전용 모달을 인페이지 오버레이로 표시 */
    function _ensureDatasetModal() {{
      if (document.getElementById('dataset-modal-overlay')) return;
      const overlay = document.createElement('div');
      overlay.id = 'dataset-modal-overlay';
      overlay.style.cssText = 'position:fixed;inset:0;z-index:99999;'
        + 'background:rgba(0,0,0,0.55);display:none;'
        + 'align-items:center;justify-content:center;backdrop-filter:blur(2px);';
      overlay.innerHTML =
        '<div style="width:min(1100px,94vw);height:min(720px,90vh);'
        + 'background:#fff;border-radius:12px;'
        + 'box-shadow:0 20px 60px rgba(0,0,0,0.35);overflow:hidden;'
        + 'display:flex;flex-direction:column;">'
        + '<iframe id="dataset-modal-iframe" src="about:blank" '
        + 'style="border:0;width:100%;height:100%;display:block;"></iframe>'
        + '</div>';
      document.body.appendChild(overlay);
      overlay.addEventListener('click', function(e) {{
        if (e.target === overlay) closeDatasetModal();
      }});
    }}

    /* 마지막에 모달을 연 카테고리 — dataset-selected 시 신호 파일 분기에 사용 */
    var _lastDatasetModalCategory = '';

    function openDatasetModal(category) {{
      _ensureDatasetModal();
      _lastDatasetModalCategory = category || '';
      const overlay = document.getElementById('dataset-modal-overlay');
      const iframe = document.getElementById('dataset-modal-iframe');
      var url = '/datasets-catalog?lang=' + INIT_LANG + '&_t=' + Date.now();
      if (category) url += '&cat=' + encodeURIComponent(category);
      iframe.src = url;
      overlay.style.display = 'flex';
    }}

    function closeDatasetModal() {{
      const overlay = document.getElementById('dataset-modal-overlay');
      if (overlay) {{
        overlay.style.display = 'none';
        const iframe = document.getElementById('dataset-modal-iframe');
        if (iframe) iframe.src = 'about:blank';
      }}
    }}

    /* iframe 모달로부터 선택 결과 수신 */
    window.addEventListener('message', async function(ev) {{
      const data = ev.data;
      if (!data || typeof data !== 'object') return;
      if (data.type === 'dataset-cancelled') {{
        closeDatasetModal();
        return;
      }}
      if (data.type === 'dataset-selected' && data.path) {{
        try {{
          // text 카테고리에서 열린 모달이면 kind=corpus → Corpus 위젯이 소비
          var kind = (_lastDatasetModalCategory === 'text') ? 'corpus' : 'data';
          var qs = 'sid=' + encodeURIComponent(SID)
                 + '&path=' + encodeURIComponent(data.path)
                 + '&kind=' + encodeURIComponent(kind);
          const r = await fetch('/dataset-select?' + qs, {{ method: 'POST' }});
          const res = await r.json();
          if (res.ok) {{
            showToast('✓ 데이터셋 적용: ' + (data.file || data.path), 3500);
            closeDatasetModal();
          }} else {{
            showToast('✗ 적용 실패: ' + (res.error || '서버 오류'), 5000);
          }}
        }} catch (e) {{
          showToast('✗ 네트워크 오류', 5000);
        }}
      }}
    }});

    /* dataset 요청: SSE /api/events 의 'dataset-request' 이벤트로 즉시 트리거 */
    SseBus.on('dataset-request', function(ev) {{
      if ((Date.now() - (lastTriggeredBy['dataset-request'] || 0)) <= TRIGGER_COOLDOWN) return;
      lastTriggeredBy['dataset-request'] = Date.now();
      var d = {{}};
      try {{ d = JSON.parse(ev.data || '{{}}'); }} catch(_) {{}}
      openDatasetModal(d.category || '');
    }});

    /* ── 내 PC 저장 폴링 (OWSave 위젯 → showSaveFilePicker 직접 호출, 모달 없음) ── */
    var _pcDownloadInflight = false;
    /* 위젯 인스턴스별 파일 핸들 캐시. key = widget_id (없으면 '__global__').
       Save Model 처럼 widget_id 를 보내는 위젯은 인스턴스별로 핸들이 분리되어
       새로 추가된 위젯이 앞 위젯의 핸들을 재사용하지 않는다. widget_id 가 없는
       Save Data 위젯은 전부 '__global__' 슬롯을 공유해 기존 동작을 유지. */
    var _pcWidgetHandles = {{}};      // {{widget_id: {{handle, basename}}}}

    /* 라벨에서 확장자 추출: "Tab-separated values (*.tab)" → ".tab" */
    function _extractExt(label) {{
      var m = label.match(/\(\*([^)]+)\)/);
      return m ? m[1] : '';
    }}

    async function pollPcDownload() {{
      if (_pcDownloadInflight) return;
      try {{
        const r = await fetch('/pc_download/check?sid=' + SID);
        const d = await r.json();
        if (!d || !d.ready || !d.files || !d.files.length) return;
        _pcDownloadInflight = true;
        console.log('[PCDL] signal detected:', d);
        // 위젯 인스턴스별 핸들 캐시 키 — widget_id 미전송(Save Data) 시 '__global__'
        var wid = d.widget_id || '__global__';
        var cached = _pcWidgetHandles[wid];
        // 1) 저장된 핸들로 자동 저장 시도 (force_new=false + 위젯별 basename 동일)
        if (!d.force_new && cached && cached.handle && cached.basename === d.basename) {{
          console.log('[PCDL] PATH=cached_handle_reuse wid=' + wid);
          try {{
            var perm = await cached.handle.queryPermission({{ mode: 'readwrite' }});
            if (perm === 'granted') {{
              var savedName = cached.handle.name;
              var matched = null;
              for (var i = 0; i < d.files.length; i++) {{
                var fext = _extractExt(d.files[i].label);
                if (fext && savedName.toLowerCase().endsWith(fext.toLowerCase())) {{
                  matched = d.files[i]; break;
                }}
              }}
              if (matched) {{
                var fr = await fetch('/pc_download/get?sid=' + SID + '&fname=' + encodeURIComponent(matched.filename) + '&cleanup=1');
                if (fr.ok) {{
                  var blob = await fr.blob();
                  var writable = await cached.handle.createWritable();
                  await writable.write(blob);
                  await writable.close();
                  showToast('✓ 저장 완료: ' + savedName, 3000);
                  try {{ fetch('/pc_download/notify_saved?sid=' + SID + '&name=' + encodeURIComponent(savedName)); }} catch(_) {{}}
                  _pcDownloadInflight = false;
                  return;
                }}
              }}
            }}
          }} catch (err) {{
            delete _pcWidgetHandles[wid];
          }}
        }}
        // 2) showSaveFilePicker 직접 호출 (모달 없음)
        console.log('[PCDL] PATH=direct_picker wid=' + wid);
        await _directSavePicker(d.basename, d.files, !!d.force_new, wid);
      }} catch(e) {{ console.error('[PCDL] poll error:', e); _pcDownloadInflight = false; }}
    }}
    setInterval(pollPcDownload, 1500);

    /* showSaveFilePicker 직접 호출 → 실패(브라우저 권한/미지원) 시 anchor 다운로드 폴백 */
    async function _directSavePicker(basename, files, forceNew, widgetId) {{
      try {{
        if (!window.showSaveFilePicker) throw new Error('not_supported');
        var types = files.map(function(f) {{
          var ext = _extractExt(f.label);
          var desc = f.label.replace(/\s*\(\*[^)]+\)\s*$/, '');
          return {{ description: desc, accept: (function() {{ var o = {{}}; o['application/octet-stream'] = [ext]; return o; }})() }};
        }});
        var defaultExt = _extractExt(files[0].label);
        var handle = await window.showSaveFilePicker({{
          suggestedName: basename + defaultExt,
          types: types
        }});
        var chosenName = handle.name || (basename + defaultExt);
        var matched = null;
        for (var i = 0; i < files.length; i++) {{
          var fext = _extractExt(files[i].label);
          if (fext && chosenName.toLowerCase().endsWith(fext.toLowerCase())) {{
            matched = files[i]; break;
          }}
        }}
        if (!matched) matched = files[0];
        var fr = await fetch('/pc_download/get?sid=' + SID + '&fname=' + encodeURIComponent(matched.filename) + '&cleanup=1');
        if (!fr.ok) throw new Error('파일 fetch 실패');
        var blob = await fr.blob();
        var writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
        if (!forceNew) {{
          // 위젯별 핸들 캐시에 저장 — widgetId 가 없으면 '__global__'(Save Data)
          var key = widgetId || '__global__';
          _pcWidgetHandles[key] = {{ handle: handle, basename: basename }};
          try {{ fetch('/pc_download/notify_saved?sid=' + SID + '&name=' + encodeURIComponent(chosenName)); }} catch(_) {{}}
        }}
        showToast('✓ 저장 완료: ' + chosenName, 3000);
      }} catch (err) {{
        if (err.name === 'AbortError') {{
          try {{ fetch('/pc_download/cleanup?sid=' + SID); }} catch(_) {{}}
        }} else {{
          // 폴백: anchor 다운로드 (브라우저가 "저장 위치 묻기" 설정 켜져 있으면 다이얼로그 표시)
          try {{
            var first = files[0];
            var fr2 = await fetch('/pc_download/get?sid=' + SID + '&fname=' + encodeURIComponent(first.filename) + '&cleanup=1');
            if (!fr2.ok) throw new Error('파일 fetch 실패');
            var blob2 = await fr2.blob();
            var url = URL.createObjectURL(blob2);
            var a = document.createElement('a');
            a.href = url; a.download = first.filename;
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            setTimeout(function() {{ URL.revokeObjectURL(url); }}, 2000);
            if (!forceNew) {{
              try {{ fetch('/pc_download/notify_saved?sid=' + SID + '&name=' + encodeURIComponent(first.filename)); }} catch(_) {{}}
            }}
            showToast('✓ 다운로드(폴백): ' + first.filename, 3000);
          }} catch (err2) {{
            showToast('저장 실패: ' + (err2.message || err2), 3000);
          }}
        }}
      }} finally {{
        _pcDownloadInflight = false;
      }}
    }}

    /* ── 토스트 ── */
    function showToast(msg, duration) {{
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.style.display = 'block';
      clearTimeout(t._timer);
      if (duration) t._timer = setTimeout(() => t.style.display = 'none', duration);
    }}

    /* ── VNC 키 이벤트 전달 (서버 사이드 xdotool) ── */
    const _keyMap = {{'=':'equal', '-':'minus', ' ':'space', '+':'plus'}};
    async function sendKey(key, modifiers) {{
      closeMenu(); closeLang();
      const xk = _keyMap[key] || key;
      const xkey = modifiers ? modifiers + '+' + xk : xk;
      try {{
        await fetch('/sendkey?sid=' + SID + '&key=' + encodeURIComponent(xkey));
      }} catch(_) {{
        showToast((modifiers ? modifiers + '+' : '') + key, 2000);
      }}
    }}

    /* ── 문서 타이틀 메뉴 ──
       헤더 #menu-btn 과 사이드바 .hwd-menu 가 동일 #menu-dropdown 을 공유.
       사이드바에서 열면 fixed 위치 inline 스타일이 적용되므로, 토글/닫기 시 항상
       inline 스타일을 초기화해 헤더에서 다시 열 때 기본 CSS(absolute) 위치로 복원됨. */
    function _resetMenuDropdownInline() {{
      var dd = document.getElementById('menu-dropdown');
      if (!dd) return;
      dd.style.position = '';
      dd.style.left = '';
      dd.style.top = '';
      dd.style.right = '';
    }}
    function toggleMenu() {{
      var dd = document.getElementById('menu-dropdown');
      var willOpen = !dd.classList.contains('open');
      if (willOpen) _resetMenuDropdownInline();  // 헤더 위치로 복원
      dd.classList.toggle('open');
      document.getElementById('lang-dropdown').classList.remove('open');
    }}
    function closeMenu() {{
      _resetMenuDropdownInline();
      document.getElementById('menu-dropdown').classList.remove('open');
    }}

    /* 사이드바 .hwd-menu 클릭 → 동일 dropdown 을 버튼 아래쪽에 fixed 위치로 표시.
       document 클릭 리스너(line 3153)는 stopPropagation 으로 트리거 안 됨. */
    function _hwdToggleSidebarMenu(btn) {{
      var dd = document.getElementById('menu-dropdown');
      if (!dd || !btn) return;
      // 이미 열려있으면 닫기 (재클릭 토글)
      if (dd.classList.contains('open')) {{ closeMenu(); return; }}
      // 사이드바 버튼 아래쪽에 fixed 위치 — getBoundingClientRect 로 좌표 산출
      var rect = btn.getBoundingClientRect();
      dd.style.position = 'fixed';
      dd.style.left = rect.left + 'px';
      dd.style.top  = (rect.bottom + 6) + 'px';
      dd.style.right = 'auto';
      dd.classList.add('open');
      // 다른 드롭다운 닫기
      var lang = document.getElementById('lang-dropdown');
      if (lang) lang.classList.remove('open');
    }}


    function openFileDialog() {{
      closeMenu();
      document.getElementById('pc-file-input').click();
    }}

    /* ── .ows 워크플로우 불러오기 ── */
    /* OPEN 모달 — Example Workflow / Local File 탭으로 .ows 열기 */
    function openOwsDialog() {{
      closeMenu();
      var m = document.getElementById('open-modal');
      m.style.display = 'flex';
      _openOwsSwitchTab('local');  // 기본 Local File 탭
      _openOwsLoadExamples();      // 백그라운드로 Examples 채우기
      _openOwsPrecheckGDrive();    // Google Drive 설정 여부 사전 확인
    }}
    /* Google Drive OAuth 설정 사전 확인 — 모달 열릴 때 1회, 미설정 시 버튼 비활성 + 안내 표시. */
    var _gdriveChecked = false;
    async function _openOwsPrecheckGDrive() {{
      if (_gdriveChecked) return;
      _gdriveChecked = true;
      try {{
        var r = await fetch('/api/gdrive/status?sid=' + SID);
        var d = await r.json().catch(function() {{ return {{}}; }});
        if (!d.logged_in) {{
          var ar = await fetch('/api/gdrive/auth?sid=' + SID, {{ method: 'POST' }});
          var ad = await ar.json().catch(function() {{ return {{}}; }});
          if (ad && ad.configured === false) {{
            var btn = document.getElementById('open-gdrive-login-btn');
            var status = document.getElementById('open-gdrive-status');
            if (btn) {{
              btn.disabled = true;
              btn.textContent = '준비 중';
              btn.style.background = '#e5e5ea';
              btn.style.color = '#9a9a9e';
              btn.style.cursor = 'not-allowed';
            }}
            if (status) status.textContent = 'Google Drive 연동은 곧 제공될 예정입니다.';
          }}
        }}
      }} catch(_) {{ }}
    }}
    /* Google Drive 로그인 — /api/gdrive/auth 가 OAuth URL 반환 시 팝업으로 계정 선택 화면 표시. */
    async function _openGDriveLogin() {{
      var btn = document.getElementById('open-gdrive-login-btn');
      var status = document.getElementById('open-gdrive-status');
      if (btn) {{ btn.disabled = true; btn.style.opacity = '0.75'; btn.textContent = '연결 중...'; }}
      if (status) status.textContent = '';
      try {{
        var r = await fetch('/api/gdrive/auth?sid=' + SID, {{ method: 'POST' }});
        var d = await r.json().catch(function() {{ return {{ ok:false }}; }});
        if (d.ok && d.url) {{
          var w = 480, h = 640;
          var L = (screen.width - w) / 2;
          var T = (screen.height - h) / 2;
          var popup = window.open(d.url, 'gdrive-oauth',
                                  'width=' + w + ',height=' + h + ',left=' + L + ',top=' + T);
          if (status) status.textContent = popup ? '새 창에서 Google 계정을 선택해 주세요...' : '팝업이 차단되었습니다.';
          if (btn) {{ btn.disabled = false; btn.style.opacity = '1'; btn.textContent = 'LOGIN TO GOOGLE'; }}
          return;
        }}
        if (d && d.configured === false) {{
          if (btn) {{ btn.disabled = true; btn.textContent = '준비 중'; btn.style.background = '#e5e5ea'; btn.style.color = '#9a9a9e'; btn.style.cursor = 'not-allowed'; }}
          if (status) status.textContent = 'Google Drive 연동은 곧 제공될 예정입니다.';
          return;
        }}
        if (status) status.textContent = (d && d.error) || '연결할 수 없습니다.';
        if (btn) {{ btn.disabled = false; btn.style.opacity = '1'; btn.textContent = 'LOGIN TO GOOGLE'; }}
      }} catch(e) {{
        if (status) status.textContent = '네트워크 오류 — 잠시 후 다시 시도하세요.';
        if (btn) {{ btn.disabled = false; btn.style.opacity = '1'; btn.textContent = 'LOGIN TO GOOGLE'; }}
      }}
    }}
    window.addEventListener('message', function(ev) {{
      if (ev && ev.data && ev.data.type === 'gdrive-auth-ok') {{
        var status = document.getElementById('open-gdrive-status');
        if (status) status.textContent = '✓ 로그인 완료.';
      }}
    }});
    function closeOpenOwsModal() {{
      var m = document.getElementById('open-modal');
      if (m) m.style.display = 'none';
    }}
    function _openOwsSwitchTab(name) {{
      ['examples','gdrive','local'].forEach(function(k) {{
        var tab = document.getElementById('opentab-' + k);
        var panel = document.getElementById('openpanel-' + k);
        var active = (k === name);
        if (tab) {{
          // Templates 모달과 동일한 활성/비활성 톤 (CSS .om-active 클래스로 위임)
          if (active) {{
            tab.classList.add('om-active');
            tab.style.background = '#1a1a1c';
            tab.style.color = '#fff';
            tab.style.fontWeight = '500';
          }} else {{
            tab.classList.remove('om-active');
            tab.style.background = '';
            tab.style.color = '#444';
            tab.style.fontWeight = '';
          }}
        }}
        if (panel) panel.style.display = active ? 'flex' : 'none';
      }});
    }}
    /* Local File 탭: 드롭/클릭 → ows-file-input 트리거 */
    (function() {{
      function _wireOpenLocal() {{
        var zone = document.getElementById('open-drop-zone');
        if (!zone || zone._wired) return;
        zone._wired = true;
        zone.addEventListener('click', function() {{
          document.getElementById('ows-file-input').click();
        }});
        zone.addEventListener('dragover', function(ev) {{
          ev.preventDefault();
          zone.style.background = '#f0f8f7';
          zone.style.borderColor = '#1aaaa0';
        }});
        zone.addEventListener('dragleave', function() {{
          zone.style.background = '';
          zone.style.borderColor = '#999';
        }});
        zone.addEventListener('drop', async function(ev) {{
          ev.preventDefault();
          zone.style.background = '';
          zone.style.borderColor = '#999';
          var files = ev.dataTransfer && ev.dataTransfer.files;
          if (!files || !files.length) return;
          var f = files[0];
          if (!f.name.toLowerCase().endsWith('.ows')) {{
            showToast('.ows 파일만 지원합니다', 3000);
            return;
          }}
          closeOpenOwsModal();
          if (typeof window.wfAddFileTab === 'function') await window.wfAddFileTab(f);
        }});
      }}
      if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', _wireOpenLocal);
      }} else {{
        _wireOpenLocal();
      }}
    }})();
    /* Example Documents 탭: /basic_templates 결과를 그리드로 표시 */
    var _openExamplesLoaded = false;
    async function _openOwsLoadExamples() {{
      if (_openExamplesLoaded) return;
      var list = document.getElementById('open-examples-list');
      try {{
        var r = await fetch('/basic_templates?sid=' + SID);
        var d = await r.json();
        if (!d.ok || !Array.isArray(d.items) || !d.items.length) {{
          list.innerHTML = '<div style="grid-column:1/-1;padding:30px;color:#888;text-align:center;">예제가 없습니다</div>';
          return;
        }}
        var html = '';
        d.items.forEach(function(it) {{
          var t = (it.title || it.filename || '').replace(/[<>]/g,'');
          var p = encodeURIComponent(it.path || '');
          html += '<div class="open-ex-card" data-path="' + p + '" data-title="' + t + '" data-filename="' + encodeURIComponent(it.filename || '') + '">'
               +  '<div style="font-weight:600;margin-bottom:4px;color:#1a1a1c;font-size:13px;">' + t + '</div>'
               +  '<div style="color:#6b7280;font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + (it.filename || '') + '</div>'
               +  '</div>';
        }});
        list.innerHTML = html;
        list.querySelectorAll('.open-ex-card').forEach(function(el) {{
          el.addEventListener('click', function() {{
            var path = decodeURIComponent(el.getAttribute('data-path'));
            var title = el.getAttribute('data-title');
            var fn = decodeURIComponent(el.getAttribute('data-filename'));
            closeOpenOwsModal();
            if (typeof window.wfAddTemplateTab === 'function') {{
              window.wfAddTemplateTab(path, title, fn);
            }}
          }});
        }});
        _openExamplesLoaded = true;
      }} catch (e) {{
        list.innerHTML = '<div style="grid-column:1/-1;padding:30px;color:#c66;text-align:center;">로드 실패: ' + (e.message || e) + '</div>';
      }}
    }}
    document.getElementById('ows-file-input').addEventListener('change', async function() {{
      const file = this.files[0];
      if (!file) return;
      this.value = '';
      // OPEN 모달이 열려있으면 닫기 (Local File 탭 클릭 경로)
      try {{ closeOpenOwsModal(); }} catch(_) {{}}
      // 기존 캔버스 덮어쓰기 X → 새 탭으로 추가 (Templates 의 wfAddTemplateTab 패턴과 동일)
      if (typeof window.wfAddFileTab === 'function') {{
        await window.wfAddFileTab(file);
      }} else {{
        // fallback (구 동작): 현재 캔버스에 직접 로드
        showToast('워크플로우 불러오는 중...', 5000);
        const form = new FormData();
        form.append('file', file);
        try {{
          const r = await fetch('/open-workflow?sid=' + SID, {{method:'POST', body:form}});
          const d = await r.json();
          if (d.ok) showToast('✓ ' + d.filename + ' 열기 완료', 2500);
          else showToast('오류: ' + (d.error || '알 수 없음'), 3000);
        }} catch(e) {{ showToast('업로드 실패', 3000); }}
      }}
    }});

    /* ── 워크플로우 저장 (OS 파일 저장 대화상자) ── */
    /* 메뉴 "저장"·"사본 만들기" 진입점 — 먼저 확인 모달 표시. 사용자가 "저장" 누르면
       _doSaveWorkflow()가 동기 호출되어 showSaveFilePicker의 사용자 제스처 컨텍스트 보존됨. */
    async function saveWorkflow() {{
      // 메뉴 dropdown 은 유지 — 저장 후 사용자가 다른 메뉴 항목을 곧바로 사용할 수 있도록
      // (이전: closeMenu() 호출로 인해 저장 클릭 즉시 dropdown 이 사라지는 문제 발생)
      // 모달 제목 결정: 1순위 - 활성 탭 라벨이 저장된 파일명이면 그것 사용,
      //                2순위 - 서버 /workflow-info, 3순위 - 'untitled'
      let wfTitle = '';
      try {{
        var activeTabEl = document.querySelector('#wf-tabbar .wf-tab.wf-active .wf-tab-title');
        var tabTitle = activeTabEl ? activeTabEl.textContent.trim() : '';
        // "Unsaved Workflow" / "Unsaved Workflow (n)" 패턴은 저장 안 된 기본 라벨
        if (tabTitle && !/^Unsaved Workflow(?: \(\d+\))?$/i.test(tabTitle)) {{
          wfTitle = tabTitle;
        }}
      }} catch(_) {{}}
      // 탭 라벨이 default 이면 서버에서 조회 fallback
      if (!wfTitle) {{
        try {{
          const r = await fetch('/workflow-info?sid=' + SID);
          if (r.ok) {{
            const j = await r.json();
            if (j.ok && j.title) wfTitle = j.title;
          }}
        }} catch(_) {{}}
      }}
      openSaveConfirm(wfTitle || 'untitled');
    }}

    function openSaveConfirm(wfTitle) {{
      document.getElementById('sc-wf-name').textContent = wfTitle || 'untitled';
      document.getElementById('save-confirm-overlay').classList.add('open');
    }}

    function closeSaveConfirm() {{
      const ov = document.getElementById('save-confirm-overlay');
      if (ov) ov.classList.remove('open');
    }}

    /* 실제 저장 — 확인 모달의 "저장" 버튼이 동기 호출 (제스처 컨텍스트 유지) */
    /* 동시 호출 방지 — 첫 저장의 showSaveFilePicker가 await 중일 때 두 번째 클릭으로 다시
       호출되면 transient activation 이 두 번째 호출에 소모되어 첫 picker가 silent-close 됨.
       Returns Promise<boolean>: true 면 실제 파일 저장 완료, false 면 취소·실패·중복 호출. */
    var _savingInProgress = false;
    /* 주의: 'function _doSaveWorkflow' 선언은 브라우저에서 자동으로 window._doSaveWorkflow
       에 바인딩됨. 별도 wrapper 추가 시 무한 재귀 발생하므로 추가 노출 코드 작성 금지. */
    async function _doSaveWorkflow() {{
      if (_savingInProgress) {{
        console.log('[save] 이전 저장 진행 중 — 중복 호출 무시');
        return false;
      }}
      _savingInProgress = true;
      try {{
        // showSaveFilePicker: HTTPS 또는 localhost 환경에서만 동작
        // 반드시 사용자 제스처(클릭) 직후 호출해야 대화상자가 열림
        // → fetch 이후 호출 시 제스처 컨텍스트 만료로 대화상자 차단됨
        if (!window.isSecureContext || !window.showSaveFilePicker) {{
          // 비보안 환경 또는 미지원 브라우저 → 다운로드 폴백
          showToast('저장 중...', 10000);
          return await _downloadWorkflow();
        }}

        // 활성 탭 라벨을 suggestedName 으로 — 이전 저장 시 파일명을 기억해 두번째 저장 UX 개선
        var suggested = 'workflow.ows';
        try {{
          var activeTabEl = document.querySelector('#wf-tabbar .wf-tab.wf-active .wf-tab-title');
          var tabTitle = activeTabEl ? activeTabEl.textContent.trim() : '';
          if (tabTitle && !/^Unsaved Workflow/i.test(tabTitle)) {{
            // 확장자 없으면 .ows 추가
            suggested = /\.ows$/i.test(tabTitle) ? tabTitle : (tabTitle + '.ows');
          }}
        }} catch(_) {{}}

        // 1. 탐색기 저장 대화상자 즉시 열기 (await 전에 동기 호출 — 제스처 컨텍스트 OK)
        let fileHandle;
        try {{
          fileHandle = await window.showSaveFilePicker({{
            suggestedName: suggested,
            types: [{{ description: 'Orange Workflow', accept: {{ 'application/octet-stream': ['.ows'] }} }}],
          }});
        }} catch(e) {{
          if (e.name === 'AbortError') {{ showToast('저장 취소', 1500); return false; }}
          console.error('[save] showSaveFilePicker 실패:', e);
          // SecurityError = 사용자 제스처 만료 (transient activation expired)
          var msg = (e.name === 'SecurityError')
            ? '저장 대화상자를 열 수 없습니다. 메뉴를 다시 열고 저장 버튼을 한 번에 눌러주세요.'
            : '대화상자 오류: ' + e.message;
          showToast(msg, 5000);
          return false;
        }}

        // 2. 대화상자 확인 후 서버에서 파일 내용 수신
        showToast('저장 중...', 10000);
        try {{
          const r = await fetch('/save-workflow?sid=' + SID);
          if (!r.ok) {{
            const d = await r.json().catch(() => ({{}}));
            showToast('저장 실패: ' + (d.error || r.status), 3000);
            return false;
          }}
          const blob = await r.blob();
          const writable = await fileHandle.createWritable();
          await writable.write(blob);
          await writable.close();
          // 저장 성공 — 활성 탭 라벨을 저장된 파일명으로 변경
          if (typeof window.wfRenameActive === 'function') {{
            window.wfRenameActive(fileHandle.name);
          }}
          showToast('✓ ' + fileHandle.name + ' 저장 완료', 3000);
          return true;
        }} catch(e) {{
          console.error('[save] 저장 처리 실패:', e);
          showToast('저장 오류: ' + e.message, 3000);
          return false;
        }}
      }} finally {{
        _savingInProgress = false;
      }}
    }}

    async function _downloadWorkflow() {{
      try {{
        const r = await fetch('/save-workflow?sid=' + SID);
        if (!r.ok) {{
          const d = await r.json().catch(() => ({{}}));
          showToast('저장 실패: ' + (d.error || r.status), 3000);
          return false;
        }}
        const blob = await r.blob();
        const cd   = r.headers.get('Content-Disposition') || '';
        const m    = cd.match(/filename="(.+)"/);
        const fname = m ? m[1] : 'workflow.ows';
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = fname;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
        // 저장 성공 — 활성 탭 라벨을 저장된 파일명으로 변경
        if (typeof window.wfRenameActive === 'function') {{
          window.wfRenameActive(fname);
        }}
        showToast('✓ ' + fname + ' 다운로드 완료', 3000);
        return true;
      }} catch(e) {{
        showToast('저장 오류', 3000);
        return false;
      }}
    }}

    /* ── 언어 드롭다운 ── */
    function toggleLang() {{
      var drop = document.getElementById('lang-dropdown');
      var btn  = document.getElementById('lang-btn');
      var bd   = document.getElementById('lang-backdrop');
      var rect = btn.getBoundingClientRect();
      drop.style.top   = (rect.bottom + 4) + 'px';
      drop.style.right = (window.innerWidth - rect.right) + 'px';
      var opening = !drop.classList.contains('open');
      drop.classList.toggle('open');
      // 백드롭: 헤더 바로 아래부터 캔버스(iframe) 전체를 덮어 바깥(캔버스) 클릭을 잡는다.
      if (bd) {{
        bd.style.top = rect.bottom + 'px';
        bd.classList.toggle('open', opening);
      }}
      document.getElementById('menu-dropdown').classList.remove('open');
    }}
    function closeLang() {{
      document.getElementById('lang-dropdown').classList.remove('open');
      var bd = document.getElementById('lang-backdrop');
      if (bd) bd.classList.remove('open');
    }}

    /* Templates 버튼 SVG 아이콘 (모든 언어 공통) */
    const _TPL_ICON = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="9" y="2" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="2" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/><rect x="9" y="9" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/></svg>';
    /* Analysis-Datasets 버튼 SVG 아이콘 (데이터베이스 원통, 모든 언어 공통) */
    const _DS_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 11v6c0 1.66 4.03 3 9 3s9-1.34 9-3v-6"/></svg>';
    const LANGS = {{
      ko: {{
        docTitle: '제목없음',
        mi: ['새 문서','불러오기','저장','다른 이름으로 저장 ...','워크플로우 정보','닫기'],
        btns: [_DS_ICON + '분석 데이터셋', _TPL_ICON + '템플릿'],
        minimap: '미니맵',
        optionLabel: '옵션',
        headerCaption: '오렌지3(Orange3) 기반의 웹 머신러닝·데이터 분석 실습 환경',
        wfInfoTitle: '워크플로우 정보',
      }},
      en: {{
        docTitle: 'Untitled',
        mi: ['New','Open','Save','Save As ...','Workflow Info','Close'],
        btns: [_DS_ICON + 'Analysis-Datasets', _TPL_ICON + 'Templates'],
        minimap: 'MinMap',
        optionLabel: 'Option',
        headerCaption: 'Web-based machine learning & data analysis platform powered by Orange3',
        wfInfoTitle: 'Workflow Info',
      }},
      sl: {{
        docTitle: 'Brez naslova',
        mi: ['Nov','Odpri','Shrani','Shrani kot ...','Informacije o poteku','Zapri'],
        btns: [_DS_ICON + 'Analitične zbirke', _TPL_ICON + 'Predloge'],
        minimap: 'MinMap',
        optionLabel: 'Možnosti',
        headerCaption: 'Spletno okolje za strojno učenje in analizo podatkov, ki temelji na Orange3',
        wfInfoTitle: 'Informacije o poteku',
      }},
    }};
    /* 툴팁(title)·aria-label 라벨 — 정적 UI 요소 (2026-05-26).
       각 키 = 요소 식별자. applyLangUI 가 한 번에 갱신. */
    const TT_LANGS = {{
      ko: {{
        btnNewOpen: '워크플로우 파일 열기',
        btnDatasets: '분석 데이터셋 카탈로그',
        hwdSearchClear: '검색어 지우기',
        hwdPanelClose: '패널 닫기',
        modalClose: '닫기',
        sbText: '텍스트 (T) — 길게 누르면 폰트 크기 선택',
        sbPen: '화살표 주석 — 길게 누르면 색상 선택',
        sbPause: '신호 전파 중단/재개 (Shift+F)',
        sbNewTab: '새 탭 (새 워크플로우)',
        sbInfo: '도움말 / 도구 안내',
        sbTool: '도구 선택',
        sbFit: '전체 보기 (Ctrl+0)',
        sbZoomOut: '축소 (Ctrl −)',
        sbZoom: '줌',
        sbZoomIn: '확대 (Ctrl ＋)',
        sbMap: '미니맵 켜기/끄기',
        sbMinimapClose: '미니맵 닫기',
      }},
      en: {{
        btnNewOpen: 'Open workflow file',
        btnDatasets: 'Analysis dataset catalog',
        hwdSearchClear: 'Clear search',
        hwdPanelClose: 'Close panel',
        modalClose: 'Close',
        sbText: 'Text (T) — long-press for font size',
        sbPen: 'Arrow annotation — long-press for color',
        sbPause: 'Pause/resume signal propagation (Shift+F)',
        sbNewTab: 'New tab (new workflow)',
        sbInfo: 'Help / tool guide',
        sbTool: 'Select tool',
        sbFit: 'Fit to view (Ctrl+0)',
        sbZoomOut: 'Zoom out (Ctrl −)',
        sbZoom: 'Zoom',
        sbZoomIn: 'Zoom in (Ctrl ＋)',
        sbMap: 'Toggle minimap',
        sbMinimapClose: 'Close minimap',
      }},
      sl: {{
        btnNewOpen: 'Odpri datoteko poteka',
        btnDatasets: 'Katalog analitičnih zbirk',
        hwdSearchClear: 'Počisti iskanje',
        hwdPanelClose: 'Zapri ploščo',
        modalClose: 'Zapri',
        sbText: 'Besedilo (T) — pridržite za velikost pisave',
        sbPen: 'Puščična opomba — pridržite za barvo',
        sbPause: 'Ustavi/nadaljuj posredovanje signalov (Shift+F)',
        sbNewTab: 'Nov zavihek (nov potek)',
        sbInfo: 'Pomoč / vodnik orodij',
        sbTool: 'Izberi orodje',
        sbFit: 'Prilagodi pogledu (Ctrl+0)',
        sbZoomOut: 'Pomanjšaj (Ctrl −)',
        sbZoom: 'Povečava',
        sbZoomIn: 'Povečaj (Ctrl ＋)',
        sbMap: 'Preklopi mini zemljevid',
        sbMinimapClose: 'Zapri mini zemljevid',
      }},
    }};
    /* DOM id ↔ TT key 매핑 (title 만 갱신, 텍스트 콘텐츠는 별도 처리) */
    const TT_MAP = {{
      'btn-new-open': 'btnNewOpen',
      'btn-datasets': 'btnDatasets',
      'hwd-panel-search-clear': 'hwdSearchClear',
      'hwd-panel-close': 'hwdPanelClose',
      'sb-text-btn': 'sbText',
      'sb-pen-btn': 'sbPen',
      'sb-pause-btn': 'sbPause',
      'sb-info-btn': 'sbInfo',
      'sb-tool-btn': 'sbTool',
      'sb-zoom-out-btn': 'sbZoomOut',
      'sb-zoom-btn': 'sbZoom',
      'sb-zoom-in-btn': 'sbZoomIn',
      'sb-map-btn': 'sbMap',
      'sb-minimap-close': 'sbMinimapClose',
    }};

    function applyLangUI(code) {{
      const d = LANGS[code];
      if (!d) return;
      document.getElementById('doc-title').textContent = d.docTitle;
      document.querySelectorAll('#menu-dropdown .mi').forEach((el,i) => {{
        if (d.mi[i] !== undefined) el.textContent = d.mi[i];
      }});
      // New Open 버튼은 모든 언어에서 영어 고정이라 매핑 대상에서 제외 (그렇지 않으면
      // 첫 인덱스(New Open)가 Analysis-Datasets innerHTML로 덮어써져 첫 버튼이 잘못 표시됨)
      const btns = document.querySelectorAll('#header-right .h-btn:not(#btn-new-open)');
      btns.forEach((el,i) => {{ if (d.btns[i] !== undefined) el.innerHTML = d.btns[i]; }});
      // 미니맵 헤더명 — 한글: '미니맵', 그 외: 'MinMapView'
      const mmLabel = document.getElementById('sb-minimap-label-text');
      if (mmLabel && d.minimap) mmLabel.textContent = d.minimap;
      // 옵션 버튼 라벨 — 한국어 '옵션', 영어·슬로베니아어 'Option' (아이콘·화살표는 별도 span이라 유지)
      const optLabel = document.getElementById('lang-label');
      if (optLabel && d.optionLabel) optLabel.textContent = d.optionLabel;
      // 헤더 가운데 안내 문구 — 언어별 분기
      const hCap = document.getElementById('header-caption');
      if (hCap && d.headerCaption) hCap.textContent = d.headerCaption;
      // Workflow Info 모달 헤더 — 언어별 분기 (2026-05-26)
      const wfTitle = document.querySelector('#wf-info-modal .wf-title-text');
      if (wfTitle && d.wfInfoTitle) wfTitle.textContent = d.wfInfoTitle;
      // 정적 툴팁(title)·aria-label 일괄 갱신 (2026-05-26)
      const ttMap = TT_LANGS[code];
      if (ttMap) {{
        Object.keys(TT_MAP).forEach(function(id) {{
          const el = document.getElementById(id);
          if (!el) return;
          const txt = ttMap[TT_MAP[id]];
          if (txt) {{
            el.setAttribute('title', txt);
            if (el.hasAttribute('aria-label')) el.setAttribute('aria-label', txt);
          }}
        }});
        // 클래스 셀렉터 — modal close 버튼 들 (.sc-close-btn, .wf-close-btn)
        document.querySelectorAll('.sc-close-btn, .wf-close-btn').forEach(function(el) {{
          el.setAttribute('title', ttMap.modalClose);
        }});
      }}
      document.querySelectorAll('.li').forEach(el => el.classList.remove('active'));
      const active = document.querySelector(`.li[onclick="setLang('${{code}}')"]`);
      if (active) active.classList.add('active');
    }}
    async function setLang(code) {{
      closeLang();
      if (!LANGS[code]) return;
      // 현재 표시 언어(INIT_LANG = 이 페이지가 로드된 언어) 재선택 → 변경 없음.
      // 불필요한 컨테이너 재시작·리로드를 막고 그대로 유지.
      if (code === INIT_LANG) return;
      try {{
        showToast('언어 변경 중…', 0);
        const resp = await fetch('/set-language?sid=' + SID + '&lang=' + code);
        const d = await resp.json().catch(function() {{ return {{ok: false}}; }});
        if (!resp.ok || !d.ok) {{
          showToast('언어 변경 실패: ' + (d.error || resp.status), 3000);
          return;
        }}
        /* /set-language 가 .app_ready 를 제거했으므로 → LOADING_PAGE 가 서빙됨 */
        window.location.href = '/?sid=' + SID + '&lang=' + code;
      }} catch(e) {{
        showToast('언어 변경 실패', 2000);
      }}
    }}
    /* 서버가 HTML 생성 시 언어 코드를 직접 삽입 — dropdown 은 스크립트 블록 이후에 위치하므로 DOM 완성 후 호출 */
    const INIT_LANG = '{init_lang}';
    document.addEventListener('DOMContentLoaded', function() {{ applyLangUI(INIT_LANG); try {{ applyLcLang(); }} catch(e) {{}} }});
    /* admin default 와 컨테이너 실제 언어가 다르면 자동 정렬 (워밍풀은 영어로 부팅됨).
       setLang() 의 reload 경로는 noVNC 전용이라 xpra 에서 못 쓰므로 직접 호출 +
       현재 URL reload. 1회만 시도 — reload 후엔 컨테이너 lang == INIT_LANG 라 재발화 안 됨.
       lang-sync 진행 중에는 한번 sessionStorage 플래그로 중복 발화 차단. */
    document.addEventListener('DOMContentLoaded', function() {{
      var FLAG = 'lang_sync_inflight_' + SID;
      if (sessionStorage.getItem(FLAG) === '1') {{
        // 직전 reload 가 이 sid 에 대해 진행 중 → flag 제거 후 skip
        sessionStorage.removeItem(FLAG); return;
      }}
      setTimeout(async function() {{
        try {{
          const r = await fetch('/language?sid=' + SID, {{cache:'no-store'}});
          const j = await r.json().catch(function(){{return {{lang:null}};}});
          if (!j || !j.lang || j.lang === INIT_LANG) return;
          console.log('[lang-sync] container=' + j.lang + ' → admin default=' + INIT_LANG);
          try {{ if (typeof showToast === 'function') showToast('언어 적용 중...', 0); }} catch(_) {{}}
          sessionStorage.setItem(FLAG, '1');
          const sr = await fetch('/set-language?sid=' + SID + '&lang=' + INIT_LANG);
          const sd = await sr.json().catch(function(){{return {{ok:false}};}});
          if (!sd.ok) {{
            console.warn('[lang-sync] /set-language 실패:', sd.error);
            sessionStorage.removeItem(FLAG); return;
          }}
          // 컨테이너 재시작 (~10s 내외) 후 현재 페이지 reload — xpra/noVNC 모두 동작.
          setTimeout(function() {{ window.location.reload(); }}, 9000);
        }} catch(e) {{
          console.warn('[lang-sync] 확인 실패:', e);
          sessionStorage.removeItem(FLAG);
        }}
      }}, 500);
    }});
    // 단계 2A: 페이지 로드 시 위젯 카탈로그 가져와 사이드바 카테고리 동적 채움
    document.addEventListener('DOMContentLoaded', function() {{ _loadWidgetCatalog(); }});


    let zoomLevel = 100;

    /* ── 분석 데이터셋 카탈로그 — 인페이지 모달 ── */
    function openAnalysisDatasets() {{
      // Dataset 버튼과 동일한 모달 구조 재사용
      _ensureDatasetModal();
      const overlay = document.getElementById('dataset-modal-overlay');
      const iframe  = document.getElementById('dataset-modal-iframe');
      iframe.src = '/analysis-datasets?lang=' + INIT_LANG + '&_t=' + Date.now();
      overlay.style.display = 'flex';
    }}

    /* ── Example Workflows 다이얼로그 열기 ── */
    async function openExampleWorkflows() {{
      try {{
        const r = await fetch('/open-example-workflows?sid=' + SID);
        const d = await r.json();
        if (!d.ok) showToast('오류: ' + (d.error || ''), 2500);
      }} catch(e) {{ showToast('연결 오류', 2000); }}
    }}

    /* ── 교안 Workflows 갤러리 ── */
    /* 모달 텍스트 i18n — data-cat/category 는 식별자라 유지하고 '표시' 텍스트만 INIT_LANG
       으로 치환한다. ko 는 HTML 하드코딩 원본을 그대로 둔다(치환 안 함). */
    var LC_CAT_I18N = {{
      '초등 Workflow': {{en:'Elementary Workflow', sl:'Osnovnošolski potek'}},
      '중등 Workflow': {{en:'Secondary Workflow', sl:'Srednješolski potek'}},
      '공통 Workflow': {{en:'Common Workflow', sl:'Skupni potek'}},
      '교재 BOOK': {{en:'Textbook', sl:'Učbenik'}}
    }};
    var LC_NOTE_I18N = {{
      en:'Select a category and click a card to instantly run an Orange3 workflow.',
      sl:'Izberite kategorijo in kliknite kartico za takojšen zagon poteka Orange3.'
    }};
    /* 카테고리 식별자 → 현재 언어 표시명 (없으면 원본 식별자 그대로) */
    function _lcDisplayCat(cat) {{
      var m = LC_CAT_I18N[cat];
      if (m && INIT_LANG !== 'ko' && m[INIT_LANG]) return m[INIT_LANG];
      return cat;
    }}
    /* 사이드바 카테고리명·헤더 안내·heading 을 INIT_LANG 으로 갱신 (ko 는 원본 유지) */
    function applyLcLang() {{
      if (INIT_LANG === 'ko') return;
      document.querySelectorAll('#lesson-sidebar .lc-cat').forEach(function(el) {{
        var c = el.getAttribute('data-cat');
        var m = LC_CAT_I18N[c];
        if (!m || !m[INIT_LANG]) return;
        var sp = el.querySelector('span:not(.lc-caret)');  // 캐럿(▾)은 건드리지 않음
        if (sp) sp.textContent = m[INIT_LANG];
      }});
      var note = document.getElementById('lesson-header-note');
      if (note && LC_NOTE_I18N[INIT_LANG]) note.textContent = LC_NOTE_I18N[INIT_LANG];
      var h = document.getElementById('lesson-heading');
      if (h) h.textContent = _lcDisplayCat(_lcActiveCat);
    }}
    var _lcActiveCat = 'All Templates';
    var _lcSearch = '';
    var _lcTemplates = [
      // 초등 Workflow: /upload_ows/elementary/*.ows lazy fetch (_ensureElementaryLoaded)
      {{ vendor:'중등', vendorIcon:'M', title:'기초 통계 분석',
         desc:'평균·분산·표준편차 등 기본 통계량 계산과 분포 시각화.',
         category:'중등 Workflow', badges:['중등','통계'], color:'#5B6BFF',
         i18n:{{ en:{{vendor:'Secondary', title:'Basic Statistics', desc:'Compute basic statistics such as mean, variance, and standard deviation, and visualize distributions.', badges:['Secondary','Statistics']}},
                sl:{{vendor:'Srednja', title:'Osnovna statistika', desc:'Izračun osnovnih statistik (povprečje, varianca, standardni odklon) in vizualizacija porazdelitev.', badges:['Srednja','Statistika']}} }} }},
      {{ vendor:'중등', vendorIcon:'M', title:'분류 모델 학습',
         desc:'로지스틱 회귀와 의사결정 트리로 분류 모델 학습·평가.',
         category:'중등 Workflow', badges:['중등','분류','ML'], color:'#9B6BFF',
         i18n:{{ en:{{vendor:'Secondary', title:'Classification Model Training', desc:'Train and evaluate classification models with logistic regression and decision trees.', badges:['Secondary','Classification','ML']}},
                sl:{{vendor:'Srednja', title:'Učenje klasifikacijskega modela', desc:'Učenje in vrednotenje klasifikacijskih modelov z logistično regresijo in odločitvenimi drevesi.', badges:['Srednja','Klasifikacija','ML']}} }} }},
      {{ vendor:'중등', vendorIcon:'M', title:'클러스터링 실습',
         desc:'k-Means와 계층적 클러스터링으로 데이터 군집화.',
         category:'중등 Workflow', badges:['중등','클러스터링'], color:'#6BD9FF',
         i18n:{{ en:{{vendor:'Secondary', title:'Clustering Practice', desc:'Cluster data using k-Means and hierarchical clustering.', badges:['Secondary','Clustering']}},
                sl:{{vendor:'Srednja', title:'Gručenje', desc:'Gručenje podatkov z metodama k-Means in hierarhičnim gručenjem.', badges:['Srednja','Gručenje']}} }} }},
      {{ vendor:'공통', vendorIcon:'C', title:'PCA 차원 축소',
         desc:'주성분 분석으로 고차원 데이터를 2D로 축소·시각화합니다.',
         category:'공통 Workflow', badges:['공통','PCA'], color:'#FF6B9C',
         i18n:{{ en:{{vendor:'Common', title:'PCA Dimensionality Reduction', desc:'Reduce high-dimensional data to 2D and visualize it using Principal Component Analysis.', badges:['Common','PCA']}},
                sl:{{vendor:'Skupno', title:'Zmanjšanje dimenzij (PCA)', desc:'Zmanjšanje visokodimenzionalnih podatkov na 2D in vizualizacija z analizo glavnih komponent.', badges:['Skupno','PCA']}} }} }},
      {{ vendor:'공통', vendorIcon:'C', title:'교차 검증',
         desc:'k-fold 교차 검증으로 모델 성능을 안정적으로 평가합니다.',
         category:'공통 Workflow', badges:['공통','평가'], color:'#A48BFF',
         i18n:{{ en:{{vendor:'Common', title:'Cross-Validation', desc:'Evaluate model performance robustly with k-fold cross-validation.', badges:['Common','Evaluation']}},
                sl:{{vendor:'Skupno', title:'Navzkrižno preverjanje', desc:'Robustno vrednotenje uspešnosti modela s k-kratnim navzkrižnim preverjanjem.', badges:['Skupno','Vrednotenje']}} }} }},
      {{ vendor:'공통', vendorIcon:'C', title:'결측값 처리',
         desc:'결측값 대치·제거 전략별 비교.',
         category:'공통 Workflow', badges:['공통','데이터'], color:'#A0C8E8',
         i18n:{{ en:{{vendor:'Common', title:'Missing Value Handling', desc:'Compare strategies for imputing and removing missing values.', badges:['Common','Data']}},
                sl:{{vendor:'Skupno', title:'Obravnava manjkajočih vrednosti', desc:'Primerjava strategij za imputacijo in odstranjevanje manjkajočih vrednosti.', badges:['Skupno','Podatki']}} }} }},
      {{ vendor:'Getting Started', vendorIcon:'G', title:'Orange3 첫걸음',
         desc:'위젯·연결·실행의 기본 흐름을 가장 작게 보여주는 시작 워크플로우.',
         category:'Getting Started', badges:['시작','기본'], color:'#5BD3D9',
         i18n:{{ en:{{title:'Orange3 First Steps', desc:'The smallest workflow demonstrating the basic flow of widgets, links, and execution.', badges:['Start','Basics']}},
                sl:{{title:'Prvi koraki z Orange3', desc:'Najmanjši potek, ki prikazuje osnovni tok gradnikov, povezav in izvajanja.', badges:['Začetek','Osnove']}} }} }},
      {{ vendor:'Getting Started', vendorIcon:'G', title:'파일 → 데이터 테이블',
         desc:'CSV/TAB 파일을 불러와 데이터 테이블 위젯에 연결합니다.',
         category:'Getting Started', badges:['시작','데이터'], color:'#FF6B6B',
         i18n:{{ en:{{title:'File → Data Table', desc:'Load a CSV/TAB file and connect it to the Data Table widget.', badges:['Start','Data']}},
                sl:{{title:'Datoteka → Tabela podatkov', desc:'Naložite datoteko CSV/TAB in jo povežite z gradnikom Tabela podatkov.', badges:['Začetek','Podatki']}} }} }},
      // '베이직'(Example Workflow) 카테고리는 _ensureBasicLoaded() 가 Orange3 내장 examples 채움.
      // 'Basic' 카테고리(통합 보기) + 8개 카테고리 sub 는 _ensureOrange3CatLoaded(cat) 가 채움.
      // Example Workflow 아래 9개 sub: Basic / Bioinformatics / Classification / Clustering /
      // Fairness / Hierarchical Clustering / Scatter Plot / Survival Analysis / Text Mining (v6, 2026-05-27).
    ];

    /* "베이직" 카테고리 — Orange3 내장 example workflows (lazy fetch, 2026-05-27 v5 원복) */
    var _lcBasicLoaded = false;
    var _lcBasicLoading = false;
    async function _ensureBasicLoaded() {{
      if (_lcBasicLoaded || _lcBasicLoading) return;
      _lcBasicLoading = true;
      try {{
        const r = await fetch('/basic_templates?sid=' + SID);
        const d = await r.json();
        if (d.ok && Array.isArray(d.items)) {{
          _lcTemplates = _lcTemplates.filter(function(t) {{ return t.category !== '베이직'; }});
          var palette = ['#5B6BFF','#FF6B9C','#FFB86B','#6BCB77','#9B6BFF','#6BD9FF','#FF6B6B','#A48BFF','#5BD3D9','#FF9B6B','#A0C8E8','#B8B8C8'];
          d.items.forEach(function(it, i) {{
            _lcTemplates.push({{
              vendor:'베이직', vendorIcon:'B',
              title: it.title || it.filename,
              desc: it.desc || '',
              category:'베이직',
              badges:['Workflow','.ows'],
              color: palette[i % palette.length],
              path: it.path,
              filename: it.filename,
              thumbnail: it.thumbnail || null
            }});
          }});
          _lcBasicLoaded = true;
        }}
      }} catch(_) {{}} finally {{ _lcBasicLoading = false; }}
    }}

    /* Sample 카테고리 8종 — /upload_ows/orange3_data/sample/<cat>/*.ows (lazy fetch)
       Sample 부모 + 8개 sub (v5, 2026-05-27). */
    var _lcOrange3CatLoaded = {{}};   // {{ 'Classification': true, ... }}
    var _lcOrange3CatLoading = {{}};
    var _ORANGE3_CATS = [
      'Bioinformatics', 'Classification', 'Clustering', 'Fairness',
      'Hierarchical Clustering', 'Scatter Plot', 'Survival Analysis', 'Text Mining'
    ];
    var _ORANGE3_CAT_COLORS = {{
      'Bioinformatics':         '#6BCB77',
      'Classification':         '#5B6BFF',
      'Clustering':             '#FFB86B',
      'Fairness':               '#FF6B9C',
      'Hierarchical Clustering':'#9B6BFF',
      'Scatter Plot':           '#A0C8E8',
      'Survival Analysis':      '#FF9B6B',
      'Text Mining':            '#6BD9FF',
    }};
    /* 8개 Sample 카테고리를 한 번에 로드 (2026-05-29 perf) — 단일 docker exec.
       이전: 8 HTTP 호출 × 200-500ms = 직렬 1.6~4s
       신규: 1 HTTP 호출 × 250-600ms = 모든 카테고리 한 번에 */
    var _lcAllSamplesLoading = false;
    async function _ensureAllOrange3Loaded() {{
      // 이미 모두 캐시됐으면 skip
      var allLoaded = _ORANGE3_CATS.every(function(c) {{ return _lcOrange3CatLoaded[c]; }});
      if (allLoaded || _lcAllSamplesLoading) return;
      _lcAllSamplesLoading = true;
      try {{
        const r = await fetch('/orange3_templates_all?sid=' + SID);
        const d = await r.json();
        if (d.ok && d.by_cat) {{
          _ORANGE3_CATS.forEach(function(cat) {{
            var items = d.by_cat[cat] || [];
            _lcTemplates = _lcTemplates.filter(function(t) {{ return t.category !== cat; }});
            var color = _ORANGE3_CAT_COLORS[cat] || '#A48BFF';
            items.forEach(function(it) {{
              _lcTemplates.push({{
                vendor: 'Orange3', vendorIcon: 'O',
                title: it.title || it.filename,
                desc: it.desc || '',
                category: cat,
                badges: ['Orange3', cat],
                color: color,
                path: it.path,
                filename: it.filename,
                thumbnail: it.thumbnail || null,
              }});
            }});
            // 모든 썸네일 OK 일 때만 캐시 — 일부 null 이면 다음 모달 오픈 시 재시도
            var hasNull = items.some(function(it){{ return !it.thumbnail; }});
            _lcOrange3CatLoaded[cat] = !hasNull;
          }});
        }}
      }} catch(_) {{}} finally {{ _lcAllSamplesLoading = false; }}
    }}

    /* 단일 카테고리 — 기존 호환성 유지용 wrapper (sub 직접 클릭 케이스).
       내부적으로는 배치 endpoint 호출 → 한 번에 8개 모두 채움. */
    async function _ensureOrange3CatLoaded(cat) {{
      if (_lcOrange3CatLoaded[cat] || _lcOrange3CatLoading[cat]) return;
      _lcOrange3CatLoading[cat] = true;
      try {{
        await _ensureAllOrange3Loaded();
      }} finally {{ _lcOrange3CatLoading[cat] = false; }}
    }}

    /* "초등 Workflow" 카테고리 — /upload_ows/elementary 내 .ows 파일들 (lazy fetch) */
    var _lcElementaryLoaded = false;
    var _lcElementaryLoading = false;
    async function _ensureElementaryLoaded() {{
      if (_lcElementaryLoaded || _lcElementaryLoading) return;
      _lcElementaryLoading = true;
      try {{
        const r = await fetch('/elementary_templates?sid=' + SID);
        const d = await r.json();
        if (d.ok && Array.isArray(d.items)) {{
          _lcTemplates = _lcTemplates.filter(function(t) {{ return t.category !== '초등 Workflow'; }});
          var palette = ['#FF9B6B','#FFB86B','#6BCB77','#5B6BFF','#FF6B9C','#9B6BFF','#6BD9FF','#FF6B6B'];
          d.items.forEach(function(it, i) {{
            _lcTemplates.push({{
              vendor:'초등', vendorIcon:'E',
              title: it.title || it.filename,
              desc: it.desc || '',
              category:'초등 Workflow',
              badges:['초등','.ows'],
              color: palette[i % palette.length],
              path: it.path,
              filename: it.filename,
              thumbnail: it.thumbnail || null
            }});
          }});
          _lcElementaryLoaded = true;
        }}
      }} catch(_) {{}} finally {{ _lcElementaryLoading = false; }}
    }}

    /* 교재 BOOK — 책 목록 + 각 책의 워크플로우 (lazy fetch, 2026-05-29) */
    var _lcBooks = [];                 /* [{{id,title,publisher,author,url,cover_url}}, ...] */
    var _lcBooksLoaded = false;
    var _lcBooksLoading = false;
    var _lcBookWorkflowsLoaded = {{}}; /* {{ "<bookId>": true, ... }} */
    var _lcBookWorkflowsLoading = {{}};
    async function _ensureBooksListLoaded() {{
      if (_lcBooksLoaded || _lcBooksLoading) return;
      _lcBooksLoading = true;
      try {{
        const r = await fetch('/orange3_books?sid=' + SID);
        const d = await r.json();
        if (d.ok && Array.isArray(d.items)) {{
          _lcBooks = d.items;
          _lcBooksLoaded = true;
          _renderBookSidebar();
        }}
      }} catch(_) {{}} finally {{ _lcBooksLoading = false; }}
    }}
    function _renderBookSidebar() {{
      var host = document.getElementById('lc-book-subs-host');
      if (!host) return;
      var html = '';
      _lcBooks.forEach(function(b) {{
        var labelSafe = (b.title||'').replace(/[<>]/g,'');
        html += '<div class="lc-cat lc-cat-sub" data-cat="교재:' + b.id + '">';
        html += '  <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 2.5C3 2.2 3.2 2 3.5 2H12c.3 0 .5.2.5.5v11c0 .3-.2.5-.5.5H4.5C3.7 14 3 13.3 3 12.5v-10z" stroke="currentColor" stroke-width="1.3"/></svg>';
        html += '  <span>' + labelSafe + '</span>';
        html += '</div>';
      }});
      host.innerHTML = html;
      // 신규 항목에도 사이드바 클릭 핸들러 attach
      host.querySelectorAll('.lc-cat').forEach(function(el) {{
        el.addEventListener('click', _lcSidebarClick);
      }});
    }}
    async function _ensureBookWorkflowsLoaded(bookId) {{
      if (_lcBookWorkflowsLoaded[bookId] || _lcBookWorkflowsLoading[bookId]) return;
      _lcBookWorkflowsLoading[bookId] = true;
      try {{
        const r = await fetch('/orange3_book_workflows?sid=' + SID +
                              '&book=' + encodeURIComponent(bookId));
        const d = await r.json();
        if (d.ok && Array.isArray(d.items)) {{
          var category = '교재:' + bookId;
          _lcTemplates = _lcTemplates.filter(function(t) {{ return t.category !== category; }});
          var palette = ['#FF9B6B','#FFB86B','#6BCB77','#5B6BFF','#FF6B9C','#9B6BFF','#6BD9FF','#FF6B6B'];
          d.items.forEach(function(it, i) {{
            _lcTemplates.push({{
              vendor:'교재', vendorIcon:'B',
              title: it.title || it.filename,
              desc: it.desc || '',
              category: category,
              badges:['교재','.ows'],
              color: palette[i % palette.length],
              path: it.path,
              filename: it.filename,
              thumbnail: it.thumbnail || null
            }});
          }});
          _lcBookWorkflowsLoaded[bookId] = true;
        }}
      }} catch(_) {{}} finally {{ _lcBookWorkflowsLoading[bookId] = false; }}
    }}
    /* 책 정보 카드 표시 / 숨김 */
    var _lcCurrentBookId = null;
    function _showBookInfo(bookId) {{
      _lcCurrentBookId = bookId;
      var info = document.getElementById('lesson-book-info');
      if (!info) return;
      var meta = _lcBooks.find(function(b) {{ return b.id === bookId; }});
      if (!meta) {{ _hideBookInfo(); return; }}
      info.classList.add('show');
      var cover = document.getElementById('lesson-book-cover');
      if (cover) {{
        // 표지 placeholder 제거 (2026-05-29): 로드 전엔 비워둠, 로드되면 이미지 표시
        cover.innerHTML = '';
        var img = new Image();
        img.onload = function() {{
          cover.innerHTML = '';
          cover.appendChild(img);
        }};
        img.onerror = function() {{
          /* 에러 시에도 비워둠 — placeholder 표시 안 함 */
          cover.innerHTML = '';
        }};
        img.src = meta.cover_url;
        img.alt = meta.title;
      }}
      var titleEl = document.getElementById('lesson-book-title');
      if (titleEl) titleEl.textContent = meta.title || '';
      var metaEl = document.getElementById('lesson-book-meta');
      if (metaEl) {{
        /* 2026-05-29 v3: 출판사 / 저자를 각각 별도 라인으로 표시 (4-line 구성 사용자 요청)
           1줄: 제목 (lesson-book-title)
           2줄: 출판사
           3줄: 저자
           4줄: URL + 다운로드 (bi-actions) */
        var html = '';
        if (meta.publisher) html += '<div class="bi-meta-row"><b>출판사</b><span>' + meta.publisher.replace(/[<>]/g,'') + '</span></div>';
        if (meta.author) html += '<div class="bi-meta-row"><b>저자</b><span>' + meta.author.replace(/[<>]/g,'') + '</span></div>';
        metaEl.innerHTML = html;
      }}
      var urlEl = document.getElementById('lesson-book-url');
      if (urlEl) {{
        if (meta.url) {{
          urlEl.href = meta.url;
          urlEl.style.display = '';
          var urlText = document.getElementById('lesson-book-url-text');
          if (urlText) urlText.textContent = meta.url.replace(/^https?:\\/\\//, '').slice(0, 50);
        }} else {{
          urlEl.style.display = 'none';
        }}
      }}
    }}
    function _hideBookInfo() {{
      _lcCurrentBookId = null;
      var info = document.getElementById('lesson-book-info');
      if (info) info.classList.remove('show');
    }}
    /* 다운로드 버튼 — 출판사의 보조자료 zip 다운로드 페이지로 이동 (download_url 우선) */
    window.downloadBookZip = function() {{
      if (!_lcCurrentBookId) return;
      var meta = _lcBooks.find(function(b) {{ return b.id === _lcCurrentBookId; }});
      var dlUrl = meta && (meta.download_url || meta.url);
      if (dlUrl) {{
        window.open(dlUrl, '_blank', 'noopener,noreferrer');
      }}
    }};

    async function openLessonTemplates() {{
      document.getElementById('lesson-modal').classList.add('open');
      // 모달 오픈 시 항상 새로 로딩 — 캐시 플래그 초기화 (v6, 2026-05-27)
      _lcBasicLoaded = false; _lcBasicLoading = false;
      _lcElementaryLoaded = false; _lcElementaryLoading = false;
      _lcOrange3CatLoaded = {{}}; _lcOrange3CatLoading = {{}};
      // 교재 BOOK 캐시도 모달 오픈 시 리셋 (2026-05-29)
      _lcBookWorkflowsLoaded = {{}}; _lcBookWorkflowsLoading = {{}};
      // 책 목록은 sidebar sub 항목 생성에 필요 — 즉시 fetch
      _ensureBooksListLoaded();
      _renderLessonGrid();
      // 모달 열릴 때 현재 활성 카테고리 데이터를 백그라운드 로드 후 재렌더
      // 2026-05-29 perf: 8개 Sample 카테고리를 단일 배치 호출로 통합 (9→2 HTTP)
      if (_lcActiveCat === 'All Templates') {{
        var _all = [_ensureBasicLoaded(), _ensureElementaryLoaded(), _ensureAllOrange3Loaded()];
        _all.forEach(function(p) {{ p.then(function() {{ _renderLessonGrid(); }}); }});
        await Promise.all(_all);
      }} else if (_lcActiveCat === 'Example Workflow') {{
        // 통합 보기: Basic(Orange3 내장) + 8개 카테고리 — 각 완료마다 즉시 렌더 (v7+perf)
        var _ew = [_ensureBasicLoaded(), _ensureAllOrange3Loaded()];
        _ew.forEach(function(p) {{ p.then(function() {{ _renderLessonGrid(); }}); }});
        await Promise.all(_ew);
      }} else if (_lcActiveCat === '베이직') {{
        await _ensureBasicLoaded();
      }} else if (_lcActiveCat === '초등 Workflow') {{
        await _ensureElementaryLoaded();
      }} else if (_lcActiveCat === '교재 BOOK') {{
        // 부모 카테고리: 모든 책의 워크플로우 병렬 로드 (각 완료마다 렌더)
        await _ensureBooksListLoaded();
        if (_lcBooks.length) {{
          var _bw = _lcBooks.map(function(b) {{ return _ensureBookWorkflowsLoaded(b.id); }});
          _bw.forEach(function(p) {{ p.then(function() {{ _renderLessonGrid(); }}); }});
          await Promise.all(_bw);
        }}
      }} else if (typeof _lcActiveCat === 'string' && _lcActiveCat.indexOf('교재:') === 0) {{
        await _ensureBookWorkflowsLoaded(_lcActiveCat.slice('교재:'.length));
      }} else if (_ORANGE3_CATS.indexOf(_lcActiveCat) >= 0) {{
        await _ensureOrange3CatLoaded(_lcActiveCat);
      }}
      _renderLessonGrid();
    }}
    function closeLessonModal() {{
      document.getElementById('lesson-modal').classList.remove('open');
    }}

    function _renderLessonGrid() {{
      var grid = document.getElementById('lesson-grid');
      var heading = document.getElementById('lesson-heading');
      // 교재 BOOK 분기 (2026-05-29) — '교재:<bookId>' 형식 카테고리 처리
      var _isBookCat = (typeof _lcActiveCat === 'string' && _lcActiveCat.indexOf('교재:') === 0);
      var _isBookParent = (_lcActiveCat === '교재 BOOK');
      // 카테고리 표시명 — 현재는 data-cat 값 그대로 노출 (베이직→Example Workflow 매핑 제거됨, 2026-05-27)
      // 카테고리 표시명 매핑 (data-cat 내부값 → 화면 표시 라벨)
      // v7: '베이직' 자리가 'Basic' sub 로 이동, 'Example Workflow' 는 통합 부모.
      var _CAT_DISPLAY = {{ '베이직': 'Basic' }};
      var headingText = _CAT_DISPLAY[_lcActiveCat] || _lcDisplayCat(_lcActiveCat);
      if (_isBookCat) {{
        var _bid = _lcActiveCat.slice('교재:'.length);
        var _bmeta = _lcBooks.find(function(b) {{ return b.id === _bid; }});
        if (_bmeta) headingText = _bmeta.title;
      }}
      heading.textContent = headingText;
      // 책 정보 카드 표시 — 단일 책 선택 시에만 (부모 '교재 BOOK' 카테고리는 카드 숨김)
      if (_isBookCat) {{
        _showBookInfo(_lcActiveCat.slice('교재:'.length));
      }} else {{
        _hideBookInfo();
      }}
      // 카테고리별 출처/설명 — Example Workflow 부모에서만 Orange3 공식 URL 노출 (v8, 2026-05-27)
      var _CAT_SOURCE = {{
        'Example Workflow': '[출처] <a href="https://orangedatamining.com/examples/" target="_blank" rel="noopener noreferrer">https://orangedatamining.com/examples/</a>'
      }};
      var srcEl = document.getElementById('lesson-source');
      if (srcEl) {{
        if (_isBookParent || _isBookCat) {{
          // 교재 BOOK 안내문 (2026-05-29) — 부모 + 개별 책 모두 표시
          srcEl.innerHTML = '<div class="lc-book-notice">' +
            '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" style="flex-shrink:0;margin-top:2px;"><circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.4"/><line x1="8" y1="5" x2="8" y2="9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="11.2" r="0.8" fill="currentColor"/></svg>' +
            '<span>교재의 샘플 ows 테스트 목적 등록입니다. 저작권 및 출판사 확인 후 삭제 예정입니다.</span>' +
            '</div>';
        }} else {{
          srcEl.innerHTML = _CAT_SOURCE[_lcActiveCat] || '';
        }}
      }}
      // 카테고리별 로딩 상태 — Example Workflow 부모는 일부 카테고리 완료 시 즉시 부분 렌더 (2026-05-27 perf)
      var _isOrange3Cat = _ORANGE3_CATS.indexOf(_lcActiveCat) >= 0;
      var _isExampleParent = (_lcActiveCat === 'Example Workflow');
      // 부모/All 의 경우 — 진행률 표시. 단일 카테고리만 미완료면 기존 동작.
      if (_isExampleParent || _lcActiveCat === 'All Templates') {{
        var _doneCnt = (_lcBasicLoaded ? 1 : 0);
        var _totalCnt = 1 + _ORANGE3_CATS.length + (_lcActiveCat === 'All Templates' ? 1 : 0);
        if (_lcActiveCat === 'All Templates' && _lcElementaryLoaded) _doneCnt++;
        _ORANGE3_CATS.forEach(function(c) {{ if (_lcOrange3CatLoaded[c]) _doneCnt++; }});
        // 한 개도 안 끝났으면 "로딩 중", 일부 완료 시 카드 + 진행 배너.
        if (_doneCnt === 0) {{
          grid.innerHTML = '<div style="grid-column:1/-1;padding:40px;color:#888;text-align:center;">로딩 중...</div>';
          return;
        }}
        // 부분 로드: 진행 배너 + 현재까지 카드는 아래에서 렌더 (return 안 함).
      }} else if ((_lcActiveCat === '베이직' && !_lcBasicLoaded) ||
          (_isOrange3Cat && !_lcOrange3CatLoaded[_lcActiveCat]) ||
          (_lcActiveCat === '초등 Workflow' && !_lcElementaryLoaded) ||
          (_isBookCat && !_lcBookWorkflowsLoaded[_lcActiveCat.slice('교재:'.length)])) {{
        grid.innerHTML = '<div style="grid-column:1/-1;padding:40px;color:#888;text-align:center;">로딩 중...</div>';
        return;
      }} else if (_isBookParent) {{
        // 책 목록 미로드 + 책별 워크플로우 미로드 진행 상태 — 점진 렌더 (Example Workflow 와 동일 패턴, 2026-05-29)
        if (!_lcBooksLoaded) {{
          grid.innerHTML = '<div style="grid-column:1/-1;padding:40px;color:#888;text-align:center;">로딩 중...</div>';
          return;
        }}
        var _bDone = _lcBooks.filter(function(b) {{ return _lcBookWorkflowsLoaded[b.id]; }}).length;
        if (_bDone === 0 && _lcBooks.length > 0) {{
          /* 책 목록은 있지만 워크플로우는 한 개도 안 끝남 — 진행률 표시 */
          grid.innerHTML = '<div style="grid-column:1/-1;padding:30px;color:#888;text-align:center;">' +
            '교재 워크플로우 로딩 중 (0 / ' + _lcBooks.length + ' 권)...' +
            '</div>';
          return;
        }}
        /* 부분 로드: 진행 배너 + 현재까지 카드 — 아래에서 렌더 (return 안 함). */
      }}
      var q = (_lcSearch || '').toLowerCase();
      var filtered = _lcTemplates.filter(function(t) {{
        // 'Example Workflow' 부모 → Basic + 8개 sub 카테고리 카드 모두 통합 (v7)
        if (_isExampleParent) {{
          if (t.category !== '베이직' && _ORANGE3_CATS.indexOf(t.category) < 0) return false;
        }} else if (_isBookParent) {{
          // 교재 BOOK 부모: 모든 교재:* 카테고리 통합 표시
          if (typeof t.category !== 'string' || t.category.indexOf('교재:') !== 0) return false;
        }} else if (_lcActiveCat !== 'All Templates' && t.category !== _lcActiveCat) {{
          return false;
        }}
        if (q && (t.title.toLowerCase().indexOf(q) < 0) && (t.desc.toLowerCase().indexOf(q) < 0)) return false;
        return true;
      }});
      if (filtered.length === 0) {{
        grid.innerHTML = '<div style="grid-column:1/-1;padding:40px;color:#888;text-align:center;">결과 없음</div>';
        return;
      }}
      var html = '';
      // 부분 로딩 배너 — Example Workflow / All Templates 에서 일부 카테고리 미완료 시 표시
      if (_isExampleParent || _lcActiveCat === 'All Templates') {{
        var _dN = (_lcBasicLoaded ? 1 : 0);
        var _tN = 1 + _ORANGE3_CATS.length + (_lcActiveCat === 'All Templates' ? 1 : 0);
        if (_lcActiveCat === 'All Templates' && _lcElementaryLoaded) _dN++;
        _ORANGE3_CATS.forEach(function(c) {{ if (_lcOrange3CatLoaded[c]) _dN++; }});
        if (_dN < _tN) {{
          html += '<div style="grid-column:1/-1;padding:8px 12px;color:#aaa;font-size:12px;text-align:center;background:#1f1f23;border-radius:6px;margin-bottom:4px;">로딩 중 ' + _dN + ' / ' + _tN + ' 카테고리...</div>';
        }}
      }}
      filtered.forEach(function(t, idx) {{
        // 언어별 표시 — i18n 있으면 INIT_LANG 번역, 없으면(동적 .ows 카드 등) 기본값 폴백
        var _Li = (t.i18n && INIT_LANG !== 'ko') ? (t.i18n[INIT_LANG] || t.i18n.en) : null;
        var titleEsc = ((_Li && _Li.title) || t.title || '').replace(/[<>]/g,'');
        var descEsc = ((_Li && _Li.desc) || t.desc || '').replace(/[<>]/g,'');
        var vendorEsc = ((_Li && _Li.vendor) || t.vendor || '').replace(/[<>]/g,'');
        var _badges = (_Li && _Li.badges) || t.badges || [];
        // 항상 흰 배경 (2026-05-29) — 썸네일 SVG 가 있으면 위에 오버레이.
        // 이전 그라데이션 fallback 제거 (사용자 요청: 로딩 전 placeholder 흰색 통일).
        // loading="lazy" 추가 — 화면 보이는 카드만 즉시 로드, 나머지는 스크롤 시 (Tier1①)
        var thumbStyle = 'background:#fff;';
        var thumbInner = '';
        if (t.thumbnail) {{
          thumbInner = '<img src="' + t.thumbnail + '" class="lc-thumb-svg" alt="" loading="lazy" decoding="async">';
        }}
        html += '<div class="lc-card" data-idx="' + idx + '">';
        html += '  <div class="lc-thumb" style="' + thumbStyle + '">';
        html += thumbInner;
        html += '    <div class="lc-vendor"><span style="display:inline-block;width:14px;height:14px;border-radius:50%;background:' + t.color + ';"></span>' + vendorEsc + '</div>';
        html += '    <div class="lc-badges">';
        _badges.forEach(function(b) {{
          html += '<span class="lc-badge">' + b.replace(/[<>]/g,'') + '</span>';
        }});
        html += '    </div>';
        html += '  </div>';
        html += '  <div class="lc-card-title">' + titleEsc + '</div>';
        html += '  <div class="lc-card-desc">' + descEsc + '</div>';
        html += '</div>';
      }});
      grid.innerHTML = html;
      grid.querySelectorAll('.lc-card').forEach(function(el) {{
        el.addEventListener('click', function() {{
          var idx = parseInt(el.getAttribute('data-idx'), 10);
          var t = filtered[idx];
          if (!t) return;
          // 베이직 템플릿: 워크플로우 탭바에 새 탭 추가 + 파일명 그대로 탭 타이틀 사용
          if (t.path) {{
            closeLessonModal();
            if (typeof window.wfAddTemplateTab === 'function') {{
              window.wfAddTemplateTab(t.path, t.title, t.filename);
            }}
          }} else {{
            showToast('템플릿 선택: ' + t.title + ' (준비 중)', 2500);
          }}
        }});
      }});
    }}

    /* 모달 사이드바 / 검색 / 배경 클릭 핸들러 */
    async function _lcSidebarClick() {{
      var el = this;
      /* 부모 카테고리 (Example Workflow / 교재 BOOK) 토글 처리 (2026-05-29)
         - 이미 active 인 부모를 다시 클릭 → sub 그룹 접기/펼치기 토글만 수행
         - 비활성 상태에서 클릭 → 활성화 + 펼침 (collapsed 제거) */
      var collapseTargetId = el.getAttribute('data-collapse-target');
      if (collapseTargetId) {{
        var target = document.getElementById(collapseTargetId);
        if (el.classList.contains('active')) {{
          /* 두 번째 클릭 — 접기/펼치기 토글 */
          var nowCollapsed = el.classList.toggle('collapsed');
          if (target) target.classList.toggle('collapsed', nowCollapsed);
          return; /* active 상태·카테고리 그대로 유지 */
        }} else {{
          /* 첫 클릭 — 활성화 + 자동 펼침 */
          el.classList.remove('collapsed');
          if (target) target.classList.remove('collapsed');
        }}
      }}
      document.querySelectorAll('#lesson-sidebar .lc-cat').forEach(function(x) {{
        x.classList.remove('active');
      }});
      el.classList.add('active');
      _lcActiveCat = el.getAttribute('data-cat');
      // 카테고리별 lazy fetch (초등 / 베이직(Example Workflow) / Sample 부모 / 8개 sub / 교재 BOOK)
      var grid = document.getElementById('lesson-grid');
      var _isOrange3Cat = _ORANGE3_CATS.indexOf(_lcActiveCat) >= 0;
      var _isExampleParent = (_lcActiveCat === 'Example Workflow');
      var _isBookParent = (_lcActiveCat === '교재 BOOK');
      var _isBookCat = (typeof _lcActiveCat === 'string' && _lcActiveCat.indexOf('교재:') === 0);
      var needLoad = false;
      if (_lcActiveCat === 'All Templates') {{
        needLoad = !_lcBasicLoaded || !_lcElementaryLoaded ||
                   _ORANGE3_CATS.some(function(c) {{ return !_lcOrange3CatLoaded[c]; }});
      }} else if (_isExampleParent) {{
        // 통합 보기: Basic + 8개 (v7)
        needLoad = !_lcBasicLoaded || _ORANGE3_CATS.some(function(c) {{ return !_lcOrange3CatLoaded[c]; }});
      }} else if (_lcActiveCat === '베이직') {{
        needLoad = !_lcBasicLoaded;
      }} else if (_lcActiveCat === '초등 Workflow') {{
        needLoad = !_lcElementaryLoaded;
      }} else if (_isOrange3Cat) {{
        needLoad = !_lcOrange3CatLoaded[_lcActiveCat];
      }} else if (_isBookParent) {{
        // 부모: 모든 책의 워크플로우 로드 필요
        needLoad = !_lcBooksLoaded ||
                   _lcBooks.some(function(b) {{ return !_lcBookWorkflowsLoaded[b.id]; }});
      }} else if (_isBookCat) {{
        var _bid = _lcActiveCat.slice('교재:'.length);
        needLoad = !_lcBookWorkflowsLoaded[_bid];
      }}
      if (needLoad) {{
        grid.innerHTML = '<div style="grid-column:1/-1;padding:40px;color:#888;text-align:center;">로딩 중...</div>';
        if (_lcActiveCat === 'All Templates') {{
          // 2026-05-29 perf: 배치 호출로 8개 카테고리 한 번에
          await Promise.all([_ensureBasicLoaded(), _ensureElementaryLoaded(), _ensureAllOrange3Loaded()]);
        }} else if (_isExampleParent) {{
          await Promise.all([_ensureBasicLoaded(), _ensureAllOrange3Loaded()]);
        }} else if (_lcActiveCat === '베이직') {{
          await _ensureBasicLoaded();
        }} else if (_lcActiveCat === '초등 Workflow') {{
          await _ensureElementaryLoaded();
        }} else if (_isOrange3Cat) {{
          await _ensureOrange3CatLoaded(_lcActiveCat);
        }} else if (_isBookParent) {{
          await _ensureBooksListLoaded();
          var _bw = _lcBooks.map(function(b) {{ return _ensureBookWorkflowsLoaded(b.id); }});
          _bw.forEach(function(p) {{ p.then(function() {{ _renderLessonGrid(); }}); }});
          await Promise.all(_bw);
        }} else if (_isBookCat) {{
          await _ensureBookWorkflowsLoaded(_lcActiveCat.slice('교재:'.length));
        }}
      }}
      _renderLessonGrid();
    }}
    setTimeout(function() {{
      document.querySelectorAll('#lesson-sidebar .lc-cat').forEach(function(el) {{
        el.addEventListener('click', _lcSidebarClick);
      }});
      var s = document.getElementById('lesson-search');
      if (s) s.addEventListener('input', function(e) {{
        _lcSearch = e.target.value || '';
        _renderLessonGrid();
      }});
      var m = document.getElementById('lesson-modal');
      if (m) m.addEventListener('click', function(e) {{
        if (e.target === m) closeLessonModal();
      }});
    }}, 100);

    /* ── 헤더/탭바/사이드바 클릭 시 noVNC iframe 키보드 포커스 보호 ──
       mousedown 의 기본 동작(포커스 이동)을 차단해 DEL 등 키 이벤트가
       noVNC iframe 에 계속 전달되도록 한다. click 이벤트는 영향 없음. */
    ['header-bar', 'wf-tabbar', 'sb-wrap'].forEach(function(id) {{
      var el = document.getElementById(id);
      if (el) el.addEventListener('mousedown', function(e) {{
        /* input/textarea 는 직접 포커스가 필요하므로 제외 */
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
        e.preventDefault();
      }});
    }});

    /* ── noVNC iframe → Delete/BackSpace postMessage 수신 ──────────────────
       noVNC HTML의 x-del-intercept 스크립트가 capture 단계에서 키를 가로채
       부모(wrapper) 페이지로 postMessage 전달.
       Delete  → /tool?tool=delete 로 Qt QAction(remove-selected) 직접 트리거
                 (xdotool 우회: 창 포커스 변경 없이 Qt 이벤트 루프에서 안전 실행)
       BackSpace → /sendkey 유지 */
    window.addEventListener('message', function(e) {{
      if (e.data && e.data.type === 'vnc-del') {{
        try {{ fetch('/tool?sid=' + SID + '&tool=delete'); }} catch(_) {{}}
      }} else if (e.data && e.data.type === 'vnc-selectall') {{
        try {{ fetch('/tool?sid=' + SID + '&tool=selectall'); }} catch(_) {{}}
      }} else if (e.data && e.data.type === 'vnc-undo') {{
        try {{ fetch('/tool?sid=' + SID + '&tool=undo'); }} catch(_) {{}}
      }} else if (e.data && e.data.type === 'vnc-redo') {{
        try {{ fetch('/tool?sid=' + SID + '&tool=redo'); }} catch(_) {{}}
      }} else if (e.data && e.data.type === 'vnc-reload') {{
        location.reload();
      }}
    }});

    /* 부모 페이지에서도 F5 → 전체 페이지 새로고침 (브라우저 기본 동작 명시적 재호출) */
    document.addEventListener('keydown', function(e) {{
      if (e.key === 'F5') {{
        e.preventDefault();
        location.reload();
      }}
    }}, true);

    /* 2026-05-28: xpra-wrapped 모드에서 Del/Backspace 키 처리 추가.
       xpra HTML5 클라이언트가 iframe 외부 포커스 시 키 누락 → 부모에서 잡아
       /tool?tool=delete 로 Qt QAction(remove-selected) 직접 트리거.
       input/textarea/contenteditable 직접 입력 중일 때는 브라우저 기본 동작 유지. */
    document.addEventListener('keydown', function(e) {{
      if (e.key !== 'Delete' && e.key !== 'Backspace') return;
      var tag = (e.target && e.target.tagName) || '';
      if (tag === 'INPUT' || tag === 'TEXTAREA' || (e.target && e.target.isContentEditable)) return;
      // xpra iframe 내부 입력 중일 수 있어 active element 가 iframe 이 아닐 때만 처리.
      var isXpraIframe = false;
      try {{
        var ae = document.activeElement;
        isXpraIframe = ae && ae.tagName === 'IFRAME';
      }} catch(_) {{}}
      // iframe 포커스 상태에서도 Del 이 잘 안 들어가는 경우가 있어 항상 fallback 호출.
      try {{ fetch('/tool?sid=' + SID + '&tool=delete'); }} catch(_) {{}}
    }}, true);

    /* 단계 3C: 부모 document Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z → /tool?tool=undo|redo 라우팅.
       사이드바에서 위젯을 캔버스에 드롭한 직후 포커스가 부모에 있을 때, 키 이벤트가 noVNC 까지
       도달하지 않는 문제 우회. input/textarea 직접 입력 중일 때는 브라우저 기본 동작 유지. */
    document.addEventListener('keydown', function(e) {{
      if (!(e.ctrlKey || e.metaKey)) return;
      var tag = (e.target && e.target.tagName) || '';
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      var isUndo = (e.key === 'z' || e.key === 'Z') && !e.shiftKey;
      var isRedo = ((e.key === 'y' || e.key === 'Y')) || ((e.key === 'z' || e.key === 'Z') && e.shiftKey);
      if (!isUndo && !isRedo) return;
      e.preventDefault();
      try {{ fetch('/tool?sid=' + SID + '&tool=' + (isUndo ? 'undo' : 'redo')); }} catch(_) {{}}
    }}, true);

    /* ── 바깥 클릭 시 드롭다운 닫기 ── */
    document.addEventListener('click', function(e) {{
      // 헤더 menu-wrap, 사이드바 .hwd-menu, 또는 dropdown 자체 외부 클릭 시 닫기
      // 단, 저장 confirm modal 이 열려있으면 menu dropdown 은 유지 (저장 후 사용자가
      // dropdown 의 다른 항목을 곧바로 선택할 수 있도록).
      var menuWrap = document.getElementById('menu-wrap');
      var menuDD   = document.getElementById('menu-dropdown');
      var saveModal = document.getElementById('save-confirm-overlay');
      var saveModalOpen = saveModal && saveModal.classList.contains('open');
      if (!saveModalOpen) {{
        var inMenu = (menuWrap && menuWrap.contains(e.target))
                  || (menuDD && menuDD.contains(e.target))
                  || (e.target.closest && e.target.closest('.hwd-menu'));
        if (!inMenu) closeMenu();
      }}
      if (!document.getElementById('lang-wrap').contains(e.target) &&
          !document.getElementById('lang-dropdown').contains(e.target))  closeLang();
      if (!document.getElementById('sb-wrap').contains(e.target)) {{
        document.querySelectorAll('.sb-drop').forEach(function(d) {{ d.classList.remove('sb-open'); }});
      }}
    }});

    /* ── 좌하단 상태바 ── */
    let sbCurrentTool = 'select';
    function sbToggleDrop(id) {{
      const drop = document.getElementById('sb-drop-' + id);
      const wasOpen = drop.classList.contains('sb-open');
      document.querySelectorAll('.sb-drop').forEach(function(d) {{ d.classList.remove('sb-open'); }});
      if (!wasOpen) drop.classList.add('sb-open');
    }}
    const _SELECT_SVG = '<path d="M3.5 3 L12.5 9 L8.5 10 L7.2 13.5 Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" fill="none"/>';
    const _HAND_SVG = '<path d="M6 11V5C6 4.5 6.5 4 7 4S8 4.5 8 5V8M8 5V4C8 3.5 8.5 3 9 3S10 3.5 10 4V8M10 4.5V4C10 3.5 10.5 3 11 3S12 3.5 12 4V9M12 6V5.5C12 5 12.5 4.5 13 4.5S14 5 14 5.5V11C14 12.5 12 14 10 14H8C6.5 14 5.5 13 4.5 11.5L3 9.5C2.5 8.5 3.5 7.5 4.5 8L6 9" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round" fill="none"/>';
    function sbTool(name) {{
      sbCurrentTool = name;
      const ico = document.getElementById('sb-tool-ico');
      const overlay = document.getElementById('pan-overlay');
      ico.setAttribute('viewBox', '0 0 16 16');
      if (name === 'select') {{
        ico.innerHTML = _SELECT_SVG;
        document.getElementById('sb-tool-btn').classList.remove('sb-active');
        overlay.style.display = 'none';
        sendKey('Escape', '');
      }} else {{
        ico.innerHTML = _HAND_SVG;
        document.getElementById('sb-tool-btn').classList.add('sb-active');
        overlay.style.display = 'block';
        overlay.style.cursor = 'grab';
        sendKey('h', '');
      }}
      document.getElementById('sb-drop-tool').classList.remove('sb-open');
    }}
    /* ── 미니맵 뷰포트 표시기 ── */
    const MINI_W = 280, MINI_H = 158;
    let mapPanX = 0, mapPanY = 0;  // indicator center offset from minimap center (px)

    function updateVpRect() {{
      const r = document.getElementById('sb-vp-rect');
      if (!r) return;
      const iW = Math.round(MINI_W * 2 / 3 * 0.8);
      const iH = Math.round(MINI_H * 2 / 3 * 0.8);
      const cX = MINI_W / 2 + mapPanX;
      const cY = MINI_H / 2 + mapPanY;
      r.style.width  = iW + 'px';
      r.style.height = iH + 'px';
      r.style.left   = Math.max(0, Math.min(MINI_W - iW, cX - iW / 2)) + 'px';
      r.style.top    = Math.max(0, Math.min(MINI_H - iH, cY - iH / 2)) + 'px';
    }}

    // 패닝 후 미니맵 표시기 위치 갱신 (VNC 좌표 기준)
    function applyMapPan(fx, fy, tx, ty) {{
      const f = document.getElementById('vnc-frame');
      const vW = f.offsetWidth  || window.innerWidth;
      const vH = f.offsetHeight || (window.innerHeight - 83);
      mapPanX += (fx - tx) / vW * MINI_W;
      mapPanY += (fy - ty) / vH * MINI_H;
      updateVpRect();
    }}

    function sbZoom(action) {{
      var toolName = null;
      if (action === 'in') {{
        zoomLevel = Math.min(400, zoomLevel + 10);
        toolName = 'zoomin';
      }} else if (action === 'out') {{
        zoomLevel = Math.max(10, zoomLevel - 10);
        toolName = 'zoomout';
      }} else if (action === 'fit') {{
        zoomLevel = 100; mapPanX = 0; mapPanY = 0;
        toolName = 'zoomreset';
      }}
      if (toolName) {{
        try {{ fetch('/tool?sid=' + SID + '&tool=' + toolName); }} catch(_) {{}}
      }}
      const pct = zoomLevel + '%';
      document.getElementById('sb-zoom-pct').textContent = pct;
      const inp = document.getElementById('sb-zoom-input');
      if (inp) inp.value = zoomLevel;
      document.getElementById('sb-drop-zoom').classList.remove('sb-open');
      updateVpRect();
    }}
    function sbZoomSet(val) {{
      const v = Math.min(400, Math.max(10, parseInt(val) || 100));
      zoomLevel = v;
      document.getElementById('sb-zoom-pct').textContent = v + '%';
      const inp = document.getElementById('sb-zoom-input');
      if (inp) inp.value = v;
      document.getElementById('sb-drop-zoom').classList.remove('sb-open');
      updateVpRect();
    }}
    function sbFit() {{
      zoomLevel = 100; mapPanX = 0; mapPanY = 0; _mmAnalyzed = false;
      try {{ fetch('/tool?sid=' + SID + '&tool=zoomreset'); }} catch(_) {{}}
      document.getElementById('sb-zoom-pct').textContent = '100%';
      const inp = document.getElementById('sb-zoom-input');
      if (inp) inp.value = 100;
      updateVpRect();
    }}
    async function sbShortcut(name) {{
      const textBtn  = document.getElementById('sb-text-btn');
      const penBtn   = document.getElementById('sb-pen-btn');
      const pauseBtn = document.getElementById('sb-pause-btn');
      if (name === 'text') {{
        const isActive = textBtn.classList.contains('sb-active');
        textBtn.classList.remove('sb-active');
        penBtn.classList.remove('sb-active');
        if (!isActive) {{
          textBtn.classList.add('sb-active');
          // 현재 선택된 폰트 크기 함께 전송 → 텍스트 모드 + 폰트 크기 한번에 적용
          const sz = (typeof _ctFontSize === 'number') ? _ctFontSize : 16;
          try {{ await fetch('/tool?sid=' + SID + '&tool=text:' + sz); }} catch(_) {{}}
        }}
      }} else if (name === 'pen') {{
        const isActive = penBtn.classList.contains('sb-active');
        textBtn.classList.remove('sb-active');
        penBtn.classList.remove('sb-active');
        if (!isActive) {{
          penBtn.classList.add('sb-active');
          // 마지막 선택된 색상 함께 전송 → 화살표 모드 + 색상 한번에 적용
          const c = (typeof _ctPenColor === 'string') ? _ctPenColor : 'C1272D';
          try {{ await fetch('/tool?sid=' + SID + '&tool=pen:' + c); }} catch(_) {{}}
        }}
      }} else if (name === 'pause') {{
        pauseBtn.classList.toggle('sb-active');
        try {{ await fetch('/tool?sid=' + SID + '&tool=pause'); }} catch(_) {{}}
      }}
    }}

    /* ── T 버튼 롱프레스 → 폰트 크기 드롭다운 ── */
    let _ctFontSize = 16;          // 현재 선택된 폰트 크기 (px). Orange3 기본값과 일치.
    let _ctPressTimer = null;
    let _ctLongPressed = false;
    const _CT_LONG_PRESS_MS = 500;  // 500ms 이상 누르면 롱프레스

    function _ctOpenFontDrop() {{
      const drop = document.getElementById('ct-font-drop');
      if (drop) drop.classList.add('open');
    }}
    function _ctCloseFontDrop() {{
      const drop = document.getElementById('ct-font-drop');
      if (drop) drop.classList.remove('open');
    }}
    function _ctClearPressTimer() {{
      if (_ctPressTimer) {{ clearTimeout(_ctPressTimer); _ctPressTimer = null; }}
    }}

    /* T 버튼: mousedown으로 타이머 시작, mouseup/leave로 취소
       - 짧은 클릭(< 500ms) → 일반 sbShortcut('text') 호출
       - 길게 누르기(>= 500ms) → 드롭다운 표시 */
    (function _ctInitTextBtn() {{
      const btn = document.getElementById('sb-text-btn');
      if (!btn) return;
      btn.addEventListener('mousedown', function(e) {{
        if (e.button !== 0) return;  // 좌클릭만
        _ctLongPressed = false;
        _ctClearPressTimer();
        _ctPressTimer = setTimeout(function() {{
          _ctLongPressed = true;
          _ctOpenFontDrop();
        }}, _CT_LONG_PRESS_MS);
      }});
      btn.addEventListener('mouseup', _ctClearPressTimer);
      btn.addEventListener('mouseleave', function() {{
        // mouseleave는 mousedown 도중 마우스가 벗어나면 fire — 타이머 취소
        _ctClearPressTimer();
      }});
      btn.addEventListener('click', function(e) {{
        if (_ctLongPressed) {{
          // 롱프레스 후의 click 이벤트는 무시 (드롭다운만 열기)
          e.preventDefault();
          e.stopPropagation();
          _ctLongPressed = false;
          return;
        }}
        sbShortcut('text');
      }});
      btn.addEventListener('contextmenu', function(e) {{ e.preventDefault(); }});
    }})();

    /* 드롭다운 바깥 클릭 시 닫기 */
    document.addEventListener('click', function(e) {{
      const drop = document.getElementById('ct-font-drop');
      const btn  = document.getElementById('sb-text-btn');
      if (!drop || !drop.classList.contains('open')) return;
      if (drop.contains(e.target) || (btn && btn.contains(e.target))) return;
      _ctCloseFontDrop();
    }});

    /* 임시 — HTML 위젯 사이드바 카테고리 클릭 시 안내 (단계 2B에서 패널 표시로 교체 예정) */
    function hwdAlert(category) {{
      // 토스트가 있으면 그걸 사용, 없으면 콘솔 로그만
      if (typeof showToast === 'function') {{
        showToast('"' + category + '" 카테고리 — 위젯 추가 동작 미연결 (단계 2B에서 연결)', 2000);
      }} else {{
        console.log('[hwd] click:', category);
      }}
    }}

    /* ── 단계 2A: /widget-catalog 응답을 받아 사이드바 카테고리 동적 렌더링 ── */
    // catalog 카테고리명(영문/한글) → /category-icon/<key> 매핑
    // 매핑되지 않은 카테고리(Transform/Time Series/Orange Obsolete 등)는 색상 원 + 이니셜 fallback
    function _hwdIconKey(catName) {{
      var map = {{
        // 영문
        'Data': 'data', 'Transform': 'transform',
        'Visualize': 'visualize', 'Model': 'model',
        'Evaluate': 'evaluate', 'Unsupervised': 'unsupervised',
        'Image Analytics': 'imageanalytics', 'Network': 'network',
        'Time Series': 'timeseries',
        'Text Mining': 'text', 'Geo': 'geo',
        // 한글 (Orange3 한국어 번역 — `비지도학습`처럼 실제 응답명과 일치하도록)
        '데이터': 'data', '변환': 'transform',
        '시각화': 'visualize', '모델': 'model',
        '평가': 'evaluate',
        '비지도': 'unsupervised', '비지도학습': 'unsupervised',
        '이미지 분석': 'imageanalytics', '네트워크': 'network',
        '시계열': 'timeseries',
        '텍스트 마이닝': 'text', '지리': 'geo',
        // Slovenian (Orange3 슬로베니아 번역)
        'Podatki': 'data', 'Predelava podatkov': 'transform',
        'Vizualizacija': 'visualize',  /* 'Model' 은 영문과 동일 */
        'Vrednotenje': 'evaluate',
        'Nenadzorovano': 'unsupervised', 'Nenadzorovano učenje': 'unsupervised'
      }};
      return map[catName] || null;
    }}

    // Orange3 background 값 정규화 ("light-blue" → "lightblue", invalid → fallback)
    function _hwdNormalizeColor(c) {{
      if (!c) return '#cccccc';
      if (c.charAt(0) === '#') return c;
      return String(c).replace(/-/g, '').toLowerCase();
    }}

    function _hwdEscape(s) {{
      return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }}

    function _renderHtmlDock(categories) {{
      var dock = document.getElementById('html-widget-dock');
      if (!dock) return;
      // 기존 카테고리 + 동적 구분 라인 제거 (.hwd-menu / 메뉴↔카테고리 정적 divider는 보존)
      var olds = dock.querySelectorAll('.hwd-cat, .hwd-cat-sep');
      for (var i = 0; i < olds.length; i++) olds[i].remove();

      if (!categories || !categories.length) return;

      var frag = document.createDocumentFragment();
      // 사이드바에서 숨길 카테고리 (Orange3 obsolete 카테고리 등) — 영문/한글/슬로베니아 모두 처리
      var _hwdHiddenCats = {{
        'Orange Obsolete': true,
        'Orange 사용 중단됨': true,
        'Zastarelo': true  /* Slovenian "Obsolete" */
      }};
      // 비영문 모드에서 영문 카테고리명 (번역 안 된 위젯이 만드는 별도 카테고리) 숨김.
      // 정상적으로 번역된 카테고리에 통합된 듯 보이게 함.
      // window._hwdLang 은 _loadWidgetCatalog 가 응답으로 받은 language 코드.
      if (window._hwdLang === 'ko' || window._hwdLang === 'sl') {{
        _hwdHiddenCats['Transform'] = true;
        _hwdHiddenCats['Data'] = true;
        _hwdHiddenCats['Visualize'] = true;
        // 'Model' 은 슬로베니아어도 동일 → 숨기지 않음
        if (window._hwdLang === 'ko') _hwdHiddenCats['Model'] = true;
        _hwdHiddenCats['Evaluate'] = true;
        _hwdHiddenCats['Unsupervised'] = true;
      }}
      // 2026-05-25: 백엔드(/widget-catalog) 가 각 cat 객체에 'phase' 필드 부여.
      // phase 경계마다 divider 자동 삽입 (1차↔2차, 2차↔3차, 3차↔4차).
      var visible = categories.filter(function(c) {{ return !_hwdHiddenCats[c.name]; }});
      visible.forEach(function(cat, idx) {{
        var el = document.createElement('div');
        el.className = 'hwd-cat';
        // 사이드바 아이콘 호버 시 메뉴명 풍선 (아이콘 아래쪽에 표시 — 2026-05-25)
        el.setAttribute('data-tip', cat.name || '');
        el.dataset.catName = cat.name || '';
        var iconKey = _hwdIconKey(cat.name);
        var firstWidget = (cat.widgets && cat.widgets.length) ? cat.widgets[0] : null;
        // 로딩 실패 시 색상 fallback 으로 교체할 HTML (이름 첫 글자 + 카테고리 색)
        var _color = _hwdNormalizeColor(cat.color);
        var _initial = (cat.name || '?').substring(0, 1);
        var _fallbackHtml = '<div class=\\'hwd-cat-icon\\' style=\\'background:' + _hwdEscape(_color)
          + ';color:#1a1a1c;font-size:11px;font-weight:700;line-height:22px;text-align:center;\\'>'
          + _hwdEscape(_initial) + '</div>';
        // onerror — 로딩 실패 시 fallback 으로 교체 (broken image glyph 숨김)
        var _onErr = 'this.outerHTML=\\'' + _fallbackHtml + '\\'';
        if (iconKey) {{
          // 1순위: Orange3 가 제공하는 카테고리 전용 SVG.
          // width/height attr + decoding=async → 로딩 중 layout shift 방지.
          el.innerHTML = '<img class="hwd-cat-icon" src="/category-icon/' + iconKey
            + '" alt="' + _hwdEscape(cat.name) + '"'
            + ' width="22" height="22" decoding="async" loading="eager"'
            + ' onerror="' + _onErr + '"/>';
        }} else if (firstWidget && firstWidget.icon_b64) {{
          // 2순위: Transform/Obsolete 등 가상 카테고리 → 첫 위젯 아이콘을 대표로 사용
          // (Orange3 native dock도 비슷한 fallback을 적용)
          el.innerHTML = '<img class="hwd-cat-icon" alt="' + _hwdEscape(cat.name) + '"'
            + ' width="22" height="22" decoding="async"'
            + ' src="data:image/png;base64,' + firstWidget.icon_b64 + '"'
            + ' onerror="' + _onErr + '"/>';
        }} else {{
          // 3순위: 위젯 정보도 없으면 색상 원 + 이니셜
          el.innerHTML = '<div class="hwd-cat-icon" style="background:' + _hwdEscape(_color)
            + ';color:#1a1a1c;font-size:11px;font-weight:700;line-height:22px;text-align:center;">'
            + _hwdEscape(_initial) + '</div>';
        }}
        var catName = cat.name || '';
        // 단계 2B: 사이드바 클릭 시 토스트 대신 위젯 목록 패널 토글
        el.addEventListener('click', function(e) {{
          e.stopPropagation();  // 문서 클릭 리스너의 즉시-닫기 방지
          _toggleWidgetPanel(catName);
        }});
        frag.appendChild(el);
        // phase 경계 divider — 1차↔2차, 2차↔3차, 3차↔4차 사이에 자동 삽입.
        var next = visible[idx + 1];
        if (next) {{
          var p1 = cat.phase || 0, p2 = next.phase || 0;
          if (p1 !== p2) {{
            var sep = document.createElement('div');
            sep.className = 'hwd-divider hwd-cat-sep';
            sep.setAttribute('aria-hidden', 'true');
            frag.appendChild(sep);
          }}
        }}
      }});
      // 사이드바 리스트 끝(마지막 카테고리 아래) divider — 푸터 영역과 시각 경계 (2026-05-24)
      if (visible.length) {{
        var endSep = document.createElement('div');
        endSep.className = 'hwd-divider hwd-cat-sep hwd-cat-sep-end';
        endSep.setAttribute('aria-hidden', 'true');
        frag.appendChild(endSep);
      }}
      dock.appendChild(frag);
    }}

    /* ── 풍선 툴팁 (이미지 2 "Templates" 스타일) ──
       body에 append되는 단일 #hwd-tip 요소를 모든 [data-tip] 요소가 공유.
       부모 overflow:hidden/auto 영향 안 받음 — 스크롤 영역 안 위젯 셀에도 표시됨.
       위치: 대상 우측에 10px 여백, 화면 우측 경계 초과 시 좌측으로 자동 전환. */
    var _hwdTip = null;
    var _hwdTipShowTimer = null;
    var _hwdTipHideTimer = null;
    var _hwdTipCurrent = null;  // 현재 hover 중인 대상 (재진입 처리)

    function _hwdEnsureTip() {{
      if (_hwdTip) return _hwdTip;
      _hwdTip = document.createElement('div');
      _hwdTip.id = 'hwd-tip';
      document.body.appendChild(_hwdTip);
      return _hwdTip;
    }}

    /* qname 으로 widget 메타 조회해 풍부 HTML 툴팁 빌드 (Phase 5, 2026-05-24).
       Orange3 native 툴팁 형식 — 이름·(from package)·설명·Inputs·Outputs. */
    function _hwdBuildRichTip(w) {{
      function esc(s){{
        return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){{
          return ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}})[c];
        }});
      }}
      function sigList(items){{
        if (!items || !items.length) return '';
        var s = '';
        items.forEach(function(it){{
          s += '<li>' + esc(it.name);
          if (it.type) s += ' <span class="hwd-tip-type">(' + esc(it.type) + ')</span>';
          s += '</li>';
        }});
        return s;
      }}
      var html = '<div class="hwd-tip-title">'
               + '<b>' + esc(w.name || '') + '</b>';
      if (w.package) html += ' <span class="hwd-tip-pkg">(from ' + esc(w.package) + ')</span>';
      html += '</div>';
      if (w.description) html += '<div class="hwd-tip-desc">' + esc(w.description) + '</div>';
      var ins = sigList(w.inputs);
      if (ins) html += '<div class="hwd-tip-section">Inputs:<ul>' + ins + '</ul></div>';
      var outs = sigList(w.outputs);
      if (outs) html += '<div class="hwd-tip-section">Outputs:<ul>' + outs + '</ul></div>';
      return html;
    }}

    function _hwdShowTip(target) {{
      // 비활성(admin 에서 off) 위젯은 회색 표시이므로 툴팁도 노출하지 않음 (2026-06-02)
      if (target.classList && target.classList.contains('is-disabled')) return;
      var text = target.getAttribute('data-tip');
      if (!text) return;
      var tip = _hwdEnsureTip();
      _hwdTipCurrent = target;
      // qname 으로 widget meta 조회 — 있으면 풍부 HTML, 없으면 plain text fallback
      var qn = target.getAttribute('data-qname') || '';
      var w = qn && window._hwdWidgetByQname ? window._hwdWidgetByQname[qn] : null;
      if (w && (w.inputs || w.outputs || w.package)) {{
        tip.innerHTML = _hwdBuildRichTip(w);
      }} else {{
        tip.textContent = text;
      }}
      tip.style.display = 'block';
      // 측정용 임시 숨김 — left/top 산출 후 visibility 복원
      tip.style.visibility = 'hidden';
      tip.style.left = '0px'; tip.style.top = '0px';
      tip.style.transform = 'none';
      var rect = target.getBoundingClientRect();
      var tipRect = tip.getBoundingClientRect();
      var left = rect.right + 10;
      // tail (::before/::after) 가 tooltip top + 16 + tail_half(8) = 24px
      // 지점에 위치 → tail 중심이 widget 세로 중심을 가리키도록 정렬.
      // 결과: 툴팁이 widget 옆에 자연스럽게 붙고, 위쪽으로 너무 띄지 않음.
      var top  = rect.top + rect.height/2 - 24;
      var onLeft = false;
      // 화면 우측 경계 초과 → 좌측 표시 (tail 방향 반전 클래스 적용)
      if (left + tipRect.width > window.innerWidth - 10) {{
        left = rect.left - tipRect.width - 10;
        onLeft = true;
      }}
      tip.classList.toggle('hwd-tip-left', onLeft);
      // 화면 상/하 경계 보정
      if (top < 10) top = 10;
      if (top + tipRect.height > window.innerHeight - 10) {{
        top = window.innerHeight - tipRect.height - 10;
      }}
      tip.style.left = left + 'px';
      tip.style.top  = top  + 'px';
      tip.style.visibility = 'visible';
      clearTimeout(_hwdTipHideTimer);
      clearTimeout(_hwdTipShowTimer);
      // 2초 hover 유지 시에만 툴팁 표시 (2026-05-26) — 즉시 노출은 지저분.
      // 캔버스 NodeItem 풍선 툴팁 (launcher.py) 과 동일한 2000ms 지연.
      _hwdTipShowTimer = setTimeout(function() {{
        if (_hwdTipCurrent === target) tip.classList.add('visible');
      }}, 2000);
    }}

    function _hwdHideTip() {{
      _hwdTipCurrent = null;
      clearTimeout(_hwdTipShowTimer);
      if (!_hwdTip) return;
      _hwdTip.classList.remove('visible');
      clearTimeout(_hwdTipHideTimer);
      _hwdTipHideTimer = setTimeout(function() {{
        if (_hwdTip) _hwdTip.style.display = 'none';
      }}, 130);
    }}

    // 이벤트 위임 — 동적으로 추가되는 .hwd-cat / .hwd-widget도 자동 처리
    document.addEventListener('mouseover', function(e) {{
      var t = e.target.closest ? e.target.closest('[data-tip]') : null;
      if (t) _hwdShowTip(t);
    }});
    document.addEventListener('mouseout', function(e) {{
      var t = e.target.closest ? e.target.closest('[data-tip]') : null;
      // mouseout은 자식 진입 시에도 발생 — relatedTarget이 같은 대상 내부면 무시
      if (t && (!e.relatedTarget || !t.contains(e.relatedTarget))) _hwdHideTip();
    }});
    // 패널 본문 스크롤 또는 윈도 스크롤/리사이즈 시 툴팁 즉시 숨김 (위치 어긋남 방지)
    window.addEventListener('scroll', _hwdHideTip, true);
    window.addEventListener('resize', _hwdHideTip);

    async function _loadWidgetCatalog(attempt) {{
      attempt = attempt || 0;
      var MAX_ATTEMPTS = 5;   // 부팅 지연 대비 — 최대 재시도 횟수 (2026-05-25 강화)
      try {{
        var r = await fetch('/widget-catalog?sid=' + SID);
        // 504(timeout) / 500(서버 에러) / 503(서비스 미준비) → 재시도
        if ((r.status === 504 || r.status === 500 || r.status === 503)
            && attempt < MAX_ATTEMPTS) {{
          console.warn('[hwd] catalog retry', attempt + 1, 'http=', r.status);
          setTimeout(function() {{ _loadWidgetCatalog(attempt + 1); }}, 2500);
          return;
        }}
        if (!r.ok) {{
          console.warn('[hwd] catalog http', r.status);
          if (attempt < MAX_ATTEMPTS) setTimeout(function() {{ _loadWidgetCatalog(attempt + 1); }}, 3000);
          return;
        }}
        var j = await r.json();
        if (!j || !j.ok) {{
          console.warn('[hwd] catalog err', j && j.error);
          if (attempt < MAX_ATTEMPTS) setTimeout(function() {{ _loadWidgetCatalog(attempt + 1); }}, 2500);
          return;
        }}
        window._hwdLang = j.language || 'en';
        window._hwdWidgetByQname = {{}};
        window._hwdCats = (j.categories || []).slice();
        _renderHtmlDock(window._hwdCats);
      }} catch(e) {{
        console.warn('[hwd] catalog load failed:', e);
        if (attempt < MAX_ATTEMPTS) setTimeout(function() {{ _loadWidgetCatalog(attempt + 1); }}, 2500);
      }}
    }}

    /* ── 단계 2B: 위젯 목록 패널 토글 ── */
    /* 위젯 카드에 click/drag 핸들러 일괄 바인딩 — 모든 섹션의 위젯에 동일 적용 */
    function _hwdBindWidgetHandlers(rootEl) {{
      rootEl.querySelectorAll('.hwd-widget').forEach(function(el) {{
        // admin 에서 비활성된 위젯: 모든 click/drag 차단 (이벤트 등록 자체 skip)
        if (el.getAttribute('data-disabled') === '1' || el.classList.contains('is-disabled')) {{
          // 호버 툴팁(_hwdShowTip)은 그대로 표시 — 사용자가 왜 비활성인지 인지 가능
          return;
        }}
        var pressedQname = null;
        var pressedAt = 0;
        function _markPressed(e) {{
          if (e.button != null && e.button !== 0) return;
          pressedQname = el.getAttribute('data-qname') || null;
          pressedAt = Date.now();
        }}
        function _tryClick(e) {{
          if (e.button != null && e.button !== 0) return;
          var qname = pressedQname;
          pressedQname = null;
          if (!qname) return;
          if (window._hwdDragging) return;
          if (!/^[\w.]+$/.test(qname)) return;
          if (Date.now() - pressedAt > 800) return;
          _hwdPostAddWidget(qname, 0, 0, true);
        }}
        el.addEventListener('pointerdown', _markPressed);
        el.addEventListener('mousedown',   _markPressed);
        el.addEventListener('pointerup',   _tryClick);
        el.addEventListener('mouseup',     _tryClick);
        el.addEventListener('click', function(e) {{
          if (pressedQname == null) return;
          _tryClick(e);
        }});
        el.addEventListener('dragstart', function(e) {{
          pressedQname = null;
          var qname = el.getAttribute('data-qname') || '';
          try {{
            e.dataTransfer.effectAllowed = 'copy';
            e.dataTransfer.setData('text/plain', qname);
            e.dataTransfer.setData('application/x-hwd-qname', qname);
          }} catch(_) {{}}
          window._hwdDragging = true;
          if (window._hwdDragClearTimer) {{
            clearTimeout(window._hwdDragClearTimer);
            window._hwdDragClearTimer = null;
          }}
          _hwdActivateDropZone();
        }});
        el.addEventListener('dragend', function() {{
          pressedQname = null;
          _hwdDeactivateDropZone();
          window._hwdDragClearTimer = setTimeout(function() {{
            window._hwdDragging = false;
            window._hwdDragClearTimer = null;
          }}, 300);
        }});
      }});
    }}

    /* 모든 카테고리를 섹션 단위로 누적 렌더 (Orange3 native dock 스타일, 이미지 2 참조).
       사이드바 카테고리 클릭 동작 (블루 영역):
         - 패널 닫힘 → 전체 렌더 + 클릭한 섹션만 펼침
         - 패널 열림 + 클릭한 카테고리 섹션이 이미 펼친 상태 → 패널 전체 닫기 (두 번 클릭 = 닫기)
         - 패널 열림 + 클릭한 카테고리 섹션이 접힌 상태 → 아코디언:
             그 섹션만 펼치고 다른 모든 섹션 접음 (현재 선택한 메뉴만 활성화) */
    function _toggleWidgetPanel(catName) {{
      var panel = document.getElementById('hwd-panel');
      if (!panel) return;
      var bodyEl = document.getElementById('hwd-panel-body');

      // 사이드바 활성 상태를 패널의 펼침 섹션 기준으로 동기화하는 헬퍼
      function _syncSidebarActive() {{
        if (!bodyEl) return;
        var active = {{}};
        bodyEl.querySelectorAll('.hwd-cat-section:not(.is-collapsed)').forEach(function(s) {{
          active[s.getAttribute('data-cat-section') || ''] = true;
        }});
        document.querySelectorAll('#html-widget-dock .hwd-cat').forEach(function(el) {{
          if (active[el.dataset.catName]) el.classList.add('active');
          else el.classList.remove('active');
        }});
      }}
      // window 전역 노출 — 헤더/햄버거 핸들러에서도 호출
      window._hwdSyncSidebarActive = _syncSidebarActive;

      // 패널 이미 열려있을 때
      if (panel.classList.contains('open') && bodyEl) {{
        var selector = '.hwd-cat-section[data-cat-section="'
                     + (window.CSS && CSS.escape ? CSS.escape(catName) : catName.replace(/"/g, '\\\\"'))
                     + '"]';
        var existingSection = bodyEl.querySelector(selector);
        if (existingSection) {{
          // 클릭한 카테고리 섹션이 현재 펼친 상태 → 패널 전체 닫기 (두 번 클릭 동작)
          if (!existingSection.classList.contains('is-collapsed')) {{
            _closeWidgetPanel();
            return;
          }}
          // 접힌 상태 → 아코디언: 다른 모든 섹션 접고 이 섹션만 펼침
          bodyEl.querySelectorAll('.hwd-cat-section').forEach(function(s) {{
            s.classList.add('is-collapsed');
          }});
          existingSection.classList.remove('is-collapsed');
          panel.dataset.cat = catName;
          _syncSidebarActive();
          try {{ existingSection.scrollIntoView({{ behavior: 'smooth', block: 'start' }}); }} catch(_) {{}}
          return;
        }}
      }}

      var allCats = window._hwdCats || [];
      if (!allCats.length) return;

      // 사이드바와 동일한 필터링 (Obsolete, Slovenian Zastarelo, 비영문 모드 영문 중복)
      var _hwdHiddenCats = {{
        'Orange Obsolete': true, 'Orange 사용 중단됨': true, 'Zastarelo': true
      }};
      if (window._hwdLang === 'ko' || window._hwdLang === 'sl') {{
        _hwdHiddenCats['Transform'] = true;
        _hwdHiddenCats['Data'] = true;
        _hwdHiddenCats['Visualize'] = true;
        if (window._hwdLang === 'ko') _hwdHiddenCats['Model'] = true;
        _hwdHiddenCats['Evaluate'] = true;
        _hwdHiddenCats['Unsupervised'] = true;
      }}
      var cats = allCats.filter(function(c) {{ return !_hwdHiddenCats[c.name]; }});

      // 기존 헤더 hide — 각 섹션이 자체 sticky 헤더를 가짐
      var header = document.getElementById('hwd-panel-header');
      if (header) header.style.display = 'none';

      // 본문 — 모든 카테고리를 섹션 단위로 누적 렌더
      var body = document.getElementById('hwd-panel-body');
      if (body) {{
        // 누적 모드 — 섹션 grid 가 layout 담당. view-grid (구버전 단일 모드) 클래스 제거.
        body.classList.remove('view-grid');
        // 저장된 view-mode 적용 — 기본값 grid (이미지 2 스타일).
        var savedMode = (localStorage.getItem('hwd-view-mode') === 'list') ? 'list' : 'grid';
        if (savedMode === 'list') body.classList.add('view-list');
        else body.classList.remove('view-list');

        // 햄버거(3-line) 토글 아이콘 SVG — 클릭 시 list 모드로 전환
        var hamburgerIcon = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none">'
          + '<rect x="2" y="3"  width="12" height="2" rx="1" fill="currentColor"/>'
          + '<rect x="2" y="7"  width="12" height="2" rx="1" fill="currentColor"/>'
          + '<rect x="2" y="11" width="12" height="2" rx="1" fill="currentColor"/></svg>';
        // 4-칸 grid 아이콘 — list 모드일 때 다시 grid 로 전환하는 버튼에 사용
        var gridIcon = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none">'
          + '<rect x="2" y="2" width="5" height="5" rx="1" fill="currentColor"/>'
          + '<rect x="9" y="2" width="5" height="5" rx="1" fill="currentColor"/>'
          + '<rect x="2" y="9" width="5" height="5" rx="1" fill="currentColor"/>'
          + '<rect x="9" y="9" width="5" height="5" rx="1" fill="currentColor"/></svg>';
        var toggleIconHtml = (savedMode === 'list') ? gridIcon : hamburgerIcon;
        var toggleTitle    = (savedMode === 'list') ? '아이콘 격자 보기' : '목록 보기';

        var html = '';
        cats.forEach(function(cat) {{
          var color = _hwdNormalizeColor(cat.color);
          var iconKey = _hwdIconKey(cat.name);
          var firstW = (cat.widgets && cat.widgets.length) ? cat.widgets[0] : null;
          var headerIconHtml;
          if (iconKey) {{
            headerIconHtml = '<img alt="" src="/category-icon/' + iconKey + '"/>';
          }} else if (firstW && firstW.icon_b64) {{
            headerIconHtml = '<img alt="" src="data:image/png;base64,' + firstW.icon_b64 + '"/>';
          }} else {{
            headerIconHtml = '<span class="hwd-panel-color-dot" style="background:'
              + _hwdEscape(color) + '"></span>';
          }}
          // --cat-color CSS 변수로 아이콘 박스 + 타이틀 (펼쳤을 때) 배경 지정.
          // 접혔을 때는 CSS 가 title background 를 transparent 로 override 함.
          // 클릭된 카테고리만 펼침 — 나머지는 .is-collapsed 클래스 부여.
          var collapsedAttr = (cat.name === catName) ? '' : ' is-collapsed';
          html += '<div class="hwd-cat-section' + collapsedAttr + '"'
                + ' data-cat-section="' + _hwdEscape(cat.name) + '"'
                + ' style="--cat-color:' + _hwdEscape(color) + ';">';
          html += '  <div class="hwd-cat-section-header">';
          html += '    <div class="hwd-section-icon-box">';
          html += '      ' + headerIconHtml;
          html += '    </div>';
          // 카테고리명 + 우측 끝 위젯 개수 (N) — 햄버거 아이콘 바로 왼쪽
          // (Phase 5, 2026-05-24)
          var _wcount = (cat.widgets && cat.widgets.length) || 0;
          html += '    <span class="hwd-cat-section-title">'
                + '<span>' + _hwdEscape(cat.name) + '</span>'
                + '<span class="hwd-cat-section-count">(' + _wcount + ')</span>'
                + '</span>';
          html += '    <button class="hwd-view-toggle-btn hwd-section-view-toggle"'
                + ' title="' + toggleTitle + '" aria-label="' + toggleTitle + '">'
                + toggleIconHtml + '</button>';
          html += '  </div>';
          html += '  <div class="hwd-cat-section-grid">';
          (cat.widgets || []).forEach(function(w) {{
            var widgetIcon = w.icon_b64
              ? '<img src="data:image/png;base64,' + w.icon_b64 + '" alt="">'
              : '<div class="hwd-widget-iconbox" style="background:' + _hwdEscape(color) + '"></div>';
            // qname → widget meta lookup (rich tooltip 용). 풀 데이터는
            // window._hwdWidgetByQname 에 보관 — _hwdShowTip 에서 조회.
            var qn = w.qualified_name || '';
            if (qn) window._hwdWidgetByQname[qn] = w;
            var tip = w.description || w.name || '';
            // admin 에서 비활성화된 위젯: draggable=false, .is-disabled 클래스,
            // tooltip 에 "(비활성)" 접미. 클릭 핸들러는 추후 .is-disabled 검사로 차단.
            var isDisabled = !!w.disabled;
            var cls = 'hwd-widget' + (isDisabled ? ' is-disabled' : '');
            html += '<div class="' + cls + '"'
                 +  (isDisabled ? '' : ' draggable="true"')
                 +  ' data-qname="' + _hwdEscape(qn) + '"'
                 +  (isDisabled ? ' data-disabled="1"' : '')
                 +  ' data-tip="' + _hwdEscape(tip) + (isDisabled ? ' (비활성)' : '') + '">'
                 +  widgetIcon
                 +  '<span class="hwd-widget-name">' + _hwdEscape(w.name || '') + '</span>'
                 +  '</div>';
          }});
          html += '  </div>';
          html += '</div>';
        }});
        body.innerHTML = html;

        // 모든 위젯에 click/drag 핸들러 바인딩
        _hwdBindWidgetHandlers(body);

        /* 접힌 섹션 활성화 — 독립 토글 (다른 섹션 상태 유지) */
        function _hwdActivateSection(section) {{
          section.classList.remove('is-collapsed');
          if (typeof window._hwdSyncSidebarActive === 'function') window._hwdSyncSidebarActive();
        }}

        /* Open all / Close all (Phase 5, 2026-05-24) — 카테고리 우클릭 컨텍스트
           메뉴. 한 번에 모든 섹션을 펼치거나 접음. */
        function _hwdOpenAllSections() {{
          body.querySelectorAll('.hwd-cat-section').forEach(function(sec){{
            sec.classList.remove('is-collapsed');
          }});
          if (typeof window._hwdSyncSidebarActive === 'function') window._hwdSyncSidebarActive();
        }}
        function _hwdCloseAllSections() {{
          body.querySelectorAll('.hwd-cat-section').forEach(function(sec){{
            sec.classList.add('is-collapsed');
          }});
          if (typeof window._hwdSyncSidebarActive === 'function') window._hwdSyncSidebarActive();
        }}
        function _hwdShowCatContextMenu(x, y) {{
          var menu = document.getElementById('hwd-cat-ctx-menu');
          if (!menu) {{
            menu = document.createElement('div');
            menu.id = 'hwd-cat-ctx-menu';
            menu.innerHTML =
              '<div class="hwd-ctx-item" data-act="open">Open Menu all</div>' +
              '<div class="hwd-ctx-item" data-act="close">Close Menu all</div>';
            document.body.appendChild(menu);
            // mousedown/click 모두 stopPropagation — 외부 panel close 핸들러
            // (document click) 가 menu 클릭을 외부 클릭으로 오인하지 않게 차단.
            menu.addEventListener('mousedown', function(e){{ e.stopPropagation(); }});
            menu.addEventListener('click', function(e){{
              e.stopPropagation();
              var it = e.target.closest('.hwd-ctx-item');
              if (!it) return;
              var act = it.getAttribute('data-act');
              if (act === 'open') _hwdOpenAllSections();
              else if (act === 'close') _hwdCloseAllSections();
              menu.style.display = 'none';
            }});
            // 외부 클릭/ESC 시 닫기
            document.addEventListener('mousedown', function(e){{
              if (menu.style.display === 'block' && !menu.contains(e.target)) {{
                menu.style.display = 'none';
              }}
            }}, true);
            document.addEventListener('keydown', function(e){{
              if (e.key === 'Escape') menu.style.display = 'none';
            }});
          }}
          // viewport 경계 보정
          menu.style.display = 'block';
          menu.style.left = '0px'; menu.style.top = '0px';
          var r = menu.getBoundingClientRect();
          var maxX = window.innerWidth - r.width - 8;
          var maxY = window.innerHeight - r.height - 8;
          menu.style.left = Math.min(x, maxX) + 'px';
          menu.style.top  = Math.min(y, maxY) + 'px';
        }}

        // 섹션 헤더의 햄버거 토글:
        //   - 펼친 섹션의 햄버거 → grid ↔ list 보기 모드 전환 (전역)
        //   - 접힌 섹션의 햄버거 → 그 섹션 활성화 (보기 모드 변경 없음)
        body.querySelectorAll('.hwd-section-view-toggle').forEach(function(btn) {{
          btn.addEventListener('click', function(e) {{
            e.stopPropagation();
            var section = btn.closest('.hwd-cat-section');
            if (section && section.classList.contains('is-collapsed')) {{
              _hwdActivateSection(section);
              return;
            }}
            var cur = (localStorage.getItem('hwd-view-mode') === 'list') ? 'list' : 'grid';
            var next = (cur === 'list') ? 'grid' : 'list';
            localStorage.setItem('hwd-view-mode', next);
            if (next === 'list') body.classList.add('view-list');
            else body.classList.remove('view-list');
            // 모든 토글 버튼의 아이콘/title 즉시 갱신 (전역 동기화)
            var nextIcon  = (next === 'list') ? gridIcon : hamburgerIcon;
            var nextTitle = (next === 'list') ? '아이콘 격자 보기' : '목록 보기';
            body.querySelectorAll('.hwd-section-view-toggle').forEach(function(b) {{
              b.innerHTML = nextIcon;
              b.title = nextTitle;
              b.setAttribute('aria-label', nextTitle);
            }});
          }});
        }});

        // 섹션 헤더 contextmenu (우클릭) — Open all / Close all 컨텍스트 메뉴
        // (Phase 5, 2026-05-24). 어느 카테고리 위에서 우클릭해도 동일 동작.
        body.querySelectorAll('.hwd-cat-section-header').forEach(function(hdr) {{
          hdr.addEventListener('contextmenu', function(e) {{
            e.preventDefault();
            _hwdShowCatContextMenu(e.clientX, e.clientY);
          }});
        }});

        // 섹션 헤더 click — 독립 토글:
        //   - 접힌 섹션 → 그 섹션만 펼침 (다른 펼친 섹션은 그대로 유지)
        //   - 펼친 섹션 재클릭 → 그 섹션만 접음 (비활성화)
        //   - 다른 메뉴(섹션 헤더)를 선택해도 현재 펼친 섹션들은 그대로 유지됨
        //   - 패널은 자동으로 닫지 않음. 패널 종료는 사이드바에서 펼친 카테고리 재클릭으로만.
        body.querySelectorAll('.hwd-cat-section-header').forEach(function(hdr) {{
          hdr.addEventListener('click', function(e) {{
            // 햄버거 토글 버튼 클릭이면 헤더 토글 skip
            if (e.target.closest && e.target.closest('.hwd-section-view-toggle')) return;
            var section = hdr.closest('.hwd-cat-section');
            if (!section) return;
            // 검색어가 있는 상태에서 헤더 클릭 → 키워드 검색 초기화 후 클릭한 섹션만 펼침
            var si = document.getElementById('hwd-panel-search');
            if (si && si.value) {{
              si.value = '';
              si.dispatchEvent(new Event('input', {{ bubbles: true }}));
              section.classList.remove('is-collapsed');
              if (typeof window._hwdSyncSidebarActive === 'function') window._hwdSyncSidebarActive();
              return;
            }}
            section.classList.toggle('is-collapsed');
            if (typeof window._hwdSyncSidebarActive === 'function') window._hwdSyncSidebarActive();
          }});
        }});

        // 클릭된 카테고리 섹션 활성 표시 + 스크롤
        body.querySelectorAll('.hwd-cat-section').forEach(function(s) {{
          if (s.getAttribute('data-cat-section') === catName) s.classList.add('is-active');
          else s.classList.remove('is-active');
        }});
        var targetSection = body.querySelector('.hwd-cat-section[data-cat-section="' + (window.CSS && CSS.escape ? CSS.escape(catName) : catName.replace(/"/g, '\\\\"')) + '"]');
        if (targetSection) {{
          // 패널이 처음 열리는 경우 (이전 transition 없음) 즉시 스크롤
          try {{ targetSection.scrollIntoView({{ behavior: 'auto', block: 'start' }}); }}
          catch(_) {{ body.scrollTop = targetSection.offsetTop; }}
        }} else {{
          body.scrollTop = 0;
        }}
      }}

      // 사이드바 active 상태 갱신
      document.querySelectorAll('#html-widget-dock .hwd-cat').forEach(function(el) {{
        if (el.dataset.catName === catName) el.classList.add('active');
        else el.classList.remove('active');
      }});
      panel.dataset.cat = catName;
      panel.classList.add('open');
      panel.setAttribute('aria-hidden', 'false');
    }}

    // 단계 3D: localStorage의 보기 모드를 #hwd-panel-body 에 클래스로 반영
    function _hwdApplyViewMode() {{
      var body = document.getElementById('hwd-panel-body');
      if (!body) return;
      var mode = (localStorage.getItem('hwd-view-mode') === 'grid') ? 'grid' : 'list';
      if (mode === 'grid') body.classList.add('view-grid');
      else body.classList.remove('view-grid');
    }}

    function _closeWidgetPanel() {{
      var panel = document.getElementById('hwd-panel');
      if (!panel) return;
      panel.classList.remove('open');
      panel.dataset.cat = '';
      panel.setAttribute('aria-hidden', 'true');
      document.querySelectorAll('#html-widget-dock .hwd-cat.active').forEach(function(el) {{
        el.classList.remove('active');
      }});
      // 검색어 초기화 (다음 열림 시 깨끗한 상태)
      var si = document.getElementById('hwd-panel-search');
      if (si) si.value = '';
      var sc = document.getElementById('hwd-panel-search-clear');
      if (sc) sc.classList.remove('show');
    }}

    /* 패널 상단 바 — 위젯 검색 필터 + 닫기 버튼 초기화 (1회 바인딩).
       검색: 모든 섹션의 .hwd-widget 을 위젯 '이름'으로만 필터 — 일치 위젯만 표시,
             일치 위젯이 있는 섹션은 펼치고, 없는 섹션은 숨김. 검색어 비우면 원복.
       (data-tip/설명 매칭은 제외 — 설명에 'data' 가 흔해 거의 모든 위젯이 걸림.
        네이티브 Orange3 검색과 동일하게 이름 기준으로 좁힌다.) */
    function _hwdInitPanelTopbar() {{
      var searchInput = document.getElementById('hwd-panel-search');
      var closeBtn    = document.getElementById('hwd-panel-close');
      var clearBtn    = document.getElementById('hwd-panel-search-clear');
      // 검색 결과 없음 메시지 — 언어별 분기 (ko/en/sl)
      var noResultEl = document.getElementById('hwd-panel-noresult');
      if (noResultEl) {{
        if (INIT_LANG === 'ko') {{
          noResultEl.textContent = '검색 결과가 없습니다. 카테고리명을 클릭하면 검색어가 초기화됩니다.';
        }} else if (INIT_LANG === 'sl') {{
          noResultEl.textContent = 'Ni ujemajočih se gradnikov. Kliknite ime kategorije za ponastavitev iskanja.';
        }} else {{
          noResultEl.textContent = 'No matching widgets. Click a category name to clear the search.';
        }}
      }}
      if (closeBtn) {{
        closeBtn.addEventListener('click', function() {{ _closeWidgetPanel(); }});
      }}
      if (clearBtn && searchInput) {{
        clearBtn.addEventListener('click', function() {{
          searchInput.value = '';
          searchInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
          searchInput.focus();
        }});
      }}
      if (searchInput) {{
        searchInput.addEventListener('input', function() {{
          var q = (this.value || '').toLowerCase().trim();
          // 초기화 버튼 표시 토글 — 입력값 있을 때만
          if (clearBtn) clearBtn.classList.toggle('show', !!this.value);
          var body = document.getElementById('hwd-panel-body');
          if (!body) return;
          var totalMatches = 0;
          body.querySelectorAll('.hwd-cat-section').forEach(function(section) {{
            var anyMatch = false;
            section.querySelectorAll('.hwd-widget').forEach(function(w) {{
              var nameEl = w.querySelector('.hwd-widget-name');
              var name = (nameEl ? nameEl.textContent : '') || '';
              var hit = !q || name.toLowerCase().indexOf(q) >= 0;
              w.style.display = hit ? '' : 'none';
              if (hit && q) {{ anyMatch = true; totalMatches++; }}
            }});
            if (q) {{
              // 검색 중 — 모든 섹션 헤더는 유지(네이티브 Orange3 참조).
              // 일치 위젯 있으면 펼치고, 없으면 헤더만 남기고 접음.
              section.style.display = '';
              if (anyMatch) section.classList.remove('is-collapsed');
              else section.classList.add('is-collapsed');
            }} else {{
              // 검색어 비움 — 섹션/위젯 표시 원복 (펼침 상태는 그대로 둠)
              section.style.display = '';
            }}
          }});
          // 검색 결과 없음 안내 메시지 토글
          var noResult = document.getElementById('hwd-panel-noresult');
          if (noResult) noResult.classList.toggle('show', !!q && totalMatches === 0);
        }});
      }}
    }}
    document.addEventListener('DOMContentLoaded', _hwdInitPanelTopbar);

    /* ── 단계 3C: drop zone 활성/비활성 + drop 처리 ── */
    function _hwdActivateDropZone() {{
      var zone = document.getElementById('hwd-drop-zone');
      if (!zone) return;
      var panel = document.getElementById('hwd-panel');
      // 패널 열린 상태면 패널 너비만큼 더 오른쪽부터 시작 (패널 영역 위로는 drop zone 안 띄움)
      zone.style.left = (panel && panel.classList.contains('open')) ? '343px' : '43px';
      zone.classList.add('active');
      zone.setAttribute('aria-hidden', 'false');
    }}
    function _hwdDeactivateDropZone() {{
      var zone = document.getElementById('hwd-drop-zone');
      if (!zone) return;
      zone.classList.remove('active');
      zone.classList.remove('over');
      zone.setAttribute('aria-hidden', 'true');
    }}

    // 단계 3C 공용 helper: drop과 click이 모두 호출
    // autoPlace=true면 (x,y) 무시하고 Orange3 nextPosition() — 마지막 노드 옆에 자동 배치
    async function _hwdPostAddWidget(qname, x, y, autoPlace) {{
      if (!qname || !/^[\w.]+$/.test(qname)) return;
      try {{
        var body = autoPlace
          ? {{ qualified_name: qname, x: 0, y: 0, auto_place: true }}
          : {{ qualified_name: qname, x: x, y: y, screen_coords: true }};
        var r = await fetch('/add-widget?sid=' + SID, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(body)
        }});
        var j = await r.json();
        if (j.ok) {{
          if (typeof showToast === 'function') showToast('위젯 추가됨', 1200);
          // 키보드 포커스를 noVNC iframe으로 — 추가 키 입력(예: 위젯 더블클릭 후 다이얼로그) 대비
          // Undo/Redo는 별도 부모 keydown 핸들러가 라우팅하므로 focus 의존 없이도 동작
          var frame = document.getElementById('vnc-frame');
          if (frame) frame.focus();
        }} else {{
          if (typeof showToast === 'function') showToast('위젯 추가 실패: ' + (j.error || '?'), 2000);
        }}
      }} catch(err) {{
        if (typeof showToast === 'function') showToast('위젯 추가 실패: ' + err.message, 2000);
      }}
    }}

    async function _hwdOnDrop(e) {{
      e.preventDefault();
      var zone = e.currentTarget;
      // dataTransfer 우선순위: 커스텀 → text/plain
      var qname = '';
      try {{ qname = e.dataTransfer.getData('application/x-hwd-qname') || ''; }} catch(_) {{}}
      if (!qname) {{
        try {{ qname = e.dataTransfer.getData('text/plain') || ''; }} catch(_) {{}}
      }}
      _hwdDeactivateDropZone();
      if (!qname) return;
      // iframe 영역 기준 좌표 — vnc-frame rect (drop zone과 동일 영역, X11 framebuffer 좌표와 1:1)
      var iframe = document.getElementById('vnc-frame');
      var rect = (iframe ? iframe.getBoundingClientRect() : zone.getBoundingClientRect());
      var x = Math.round(e.clientX - rect.left);
      var y = Math.round(e.clientY - rect.top);
      if (x < 0 || y < 0) return;
      _hwdPostAddWidget(qname, x, y);
    }}

    // drop zone listener 바인딩 (DOMContentLoaded 후)
    document.addEventListener('DOMContentLoaded', function() {{
      var zone = document.getElementById('hwd-drop-zone');
      if (!zone) return;
      zone.addEventListener('dragover', function(e) {{
        e.preventDefault();
        try {{ e.dataTransfer.dropEffect = 'copy'; }} catch(_) {{}}
        zone.classList.add('over');
      }});
      zone.addEventListener('dragleave', function(e) {{
        // dragleave는 자식 요소 진입/이탈 시에도 발생 — currentTarget 외부로 나갈 때만 처리
        if (!zone.contains(e.relatedTarget)) zone.classList.remove('over');
      }});
      zone.addEventListener('drop', _hwdOnDrop);
      // 드래그가 외부에서 취소(드롭 없음)될 때 안전망
      document.addEventListener('dragend', function() {{ _hwdDeactivateDropZone(); }});
    }});

    // 패널 외부 (사이드바·패널 자체 제외) 클릭 시 닫기
    // 주의: iframe 내부 클릭은 부모 document로 전파되지 않으므로 캔버스 클릭은 패널을 닫지 않음
    // 추가 예외: 카테고리 우클릭 컨텍스트 메뉴 (Open/Close Menu all) — body 에 붙어
    // 있어서 panel/dock 외부로 오인되어 클릭 시 패널이 닫히는 버그 방지.
    document.addEventListener('click', function(e) {{
      var panel = document.getElementById('hwd-panel');
      if (!panel || !panel.classList.contains('open')) return;
      var dock = document.getElementById('html-widget-dock');
      if (panel.contains(e.target)) return;
      if (dock && dock.contains(e.target)) return;
      var ctxMenu = document.getElementById('hwd-cat-ctx-menu');
      if (ctxMenu && ctxMenu.contains(e.target)) return;
      _closeWidgetPanel();
    }});

    /* info 버튼 — Workflow Info HTML 모달 열기 (Datasets 스타일) */
    async function ctShowInfo() {{
      const ov = document.getElementById('wf-info-overlay');
      if (!ov) return;
      // 이미 열려있으면 무시 (modal 토글이 아니라 중복 방지)
      if (ov.classList.contains('open')) return;
      // 현재 워크플로우 정보 로드 (실패해도 빈 값으로 진행)
      let title = '', desc = '';
      try {{
        const r = await fetch('/workflow-info?sid=' + SID);
        if (r.ok) {{
          const j = await r.json();
          if (j.ok) {{
            title = j.title || '';
            desc  = j.description || '';
          }}
        }}
      }} catch(_) {{}}
      document.getElementById('wf-title-input').value = title;
      document.getElementById('wf-desc-input').value = desc;
      ov.classList.add('open');
      // 자동 포커스 + 전체 선택 (Orange3 다이얼로그처럼)
      const inp = document.getElementById('wf-title-input');
      setTimeout(function() {{ inp.focus(); inp.select(); }}, 50);
    }}

    function ctCloseInfoModal() {{
      const ov = document.getElementById('wf-info-overlay');
      if (ov) ov.classList.remove('open');
    }}

    async function ctSaveInfoModal() {{
      const title = document.getElementById('wf-title-input').value;
      const desc  = document.getElementById('wf-desc-input').value;
      try {{
        await fetch('/workflow-info?sid=' + SID, {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{title: title, description: desc}})
        }});
      }} catch(_) {{}}
      ctCloseInfoModal();
    }}

    /* Esc 키로 모달 닫기 */
    document.addEventListener('keydown', function(e) {{
      if (e.key === 'Escape') {{
        const ov = document.getElementById('wf-info-overlay');
        if (ov && ov.classList.contains('open')) {{
          ctCloseInfoModal();
        }}
      }}
    }});

    /* ── 펜 버튼 롱프레스 → 화살표 색상 드롭다운 ── */
    let _ctPenColor = 'C1272D';  // Orange3 기본 색상 (빨강)
    let _ctPenPressTimer = null;
    let _ctPenLongPressed = false;

    function _ctOpenPenColorDrop() {{
      const drop = document.getElementById('ct-color-drop');
      if (drop) drop.classList.add('open');
    }}
    function _ctClosePenColorDrop() {{
      const drop = document.getElementById('ct-color-drop');
      if (drop) drop.classList.remove('open');
    }}
    function _ctClearPenPressTimer() {{
      if (_ctPenPressTimer) {{ clearTimeout(_ctPenPressTimer); _ctPenPressTimer = null; }}
    }}

    (function _ctInitPenBtn() {{
      const btn = document.getElementById('sb-pen-btn');
      if (!btn) return;
      btn.removeAttribute('onclick');  // 기존 onclick 제거 (long-press 처리 필요)
      btn.addEventListener('mousedown', function(e) {{
        if (e.button !== 0) return;
        _ctPenLongPressed = false;
        _ctClearPenPressTimer();
        _ctPenPressTimer = setTimeout(function() {{
          _ctPenLongPressed = true;
          _ctOpenPenColorDrop();
        }}, _CT_LONG_PRESS_MS);
      }});
      btn.addEventListener('mouseup', _ctClearPenPressTimer);
      btn.addEventListener('mouseleave', _ctClearPenPressTimer);
      btn.addEventListener('click', function(e) {{
        if (_ctPenLongPressed) {{
          e.preventDefault(); e.stopPropagation();
          _ctPenLongPressed = false;
          return;
        }}
        sbShortcut('pen');
      }});
      btn.addEventListener('contextmenu', function(e) {{ e.preventDefault(); }});
    }})();

    /* 색상 드롭다운 바깥 클릭 시 닫기 */
    document.addEventListener('click', function(e) {{
      const drop = document.getElementById('ct-color-drop');
      const btn  = document.getElementById('sb-pen-btn');
      if (!drop || !drop.classList.contains('open')) return;
      if (drop.contains(e.target) || (btn && btn.contains(e.target))) return;
      _ctClosePenColorDrop();
    }});

    /* 색상 선택 — 화살표 모드 활성화 + 색상 적용 */
    async function ctPickPenColor(color) {{
      _ctPenColor = color;
      document.querySelectorAll('.ct-color-item').forEach(function(it) {{
        it.classList.toggle('sel', it.dataset.color === color);
      }});
      _ctClosePenColorDrop();
      const textBtn = document.getElementById('sb-text-btn');
      const penBtn  = document.getElementById('sb-pen-btn');
      textBtn.classList.remove('sb-active');
      penBtn.classList.add('sb-active');
      try {{ await fetch('/tool?sid=' + SID + '&tool=pen:' + color); }} catch(_) {{}}
    }}

    /* 폰트 크기 선택 — 텍스트 모드 활성화 + 선택 사이즈 적용 */
    async function ctPickFontSize(size) {{
      _ctFontSize = size;
      // 선택 표시 갱신
      document.querySelectorAll('.ct-font-item').forEach(function(it) {{
        it.classList.toggle('sel', parseInt(it.dataset.size, 10) === size);
      }});
      _ctCloseFontDrop();
      // 텍스트 도구 활성 상태로 전환 (펜 비활성화)
      const textBtn = document.getElementById('sb-text-btn');
      const penBtn  = document.getElementById('sb-pen-btn');
      textBtn.classList.add('sb-active');
      penBtn.classList.remove('sb-active');
      try {{ await fetch('/tool?sid=' + SID + '&tool=text:' + size); }} catch(_) {{}}
    }}

    let sbMapOpen = false;  // Tier A3: 기본 접힘 (진단보고서 U3)
    let _mmTimer = null;
    let _mmAnalyzed = false;
    const _mmSid = '{sid}';

    /* 스크린샷을 canvas API로 분석해 뷰포트 표시기 자동 배치 */
    function analyzeMinimapImg(imgEl) {{
      var W = MINI_W, H = MINI_H;
      /* 헤더 영역(83px/1080px) 제외 */
      var skipTop = Math.round(83 / 1080 * H);
      var c = document.createElement('canvas');
      c.width = W; c.height = H;
      var ctx = c.getContext('2d');
      try {{
        ctx.drawImage(imgEl, 0, 0, W, H);
        var d = ctx.getImageData(0, skipTop, W, H - skipTop).data;
      }} catch(e) {{ return; }}
      var minX = W, maxX = 0, minY = H, maxY = 0, found = false;
      for (var y = 0; y < H - skipTop; y++) {{
        for (var x = 0; x < W; x++) {{
          var i4 = (y * W + x) * 4;
          var r = d[i4], g = d[i4+1], b = d[i4+2];
          /* 흰색/밝은 회색 이외의 픽셀 = 위젯 */
          if (!(r > 230 && g > 230 && b > 230)) {{
            if (x < minX) minX = x;
            if (x > maxX) maxX = x;
            var gy = y + skipTop;
            if (gy < minY) minY = gy;
            if (gy > maxY) maxY = gy;
            found = true;
          }}
        }}
      }}
      if (found && (maxX - minX) > 10 && (maxY - minY) > 5) {{
        /* 위젯 바운딩박스 중심으로 표시기 이동 */
        mapPanX = (minX + maxX) / 2 - W / 2;
        mapPanY = (minY + maxY) / 2 - H / 2;
      }} else {{
        /* 위젯 없음: 전체 캔버스 1/5 지점을 중심으로 */
        mapPanX = W / 5 - W / 2;
        mapPanY = H / 5 - H / 2;
      }}
      updateVpRect();
    }}

    async function sbFixView() {{
      /* 선택 위젯 중심 이동, 없으면 전체 보기 */
      const btn = document.getElementById('sb-fixview-btn');
      if (btn) btn.classList.add('sb-active');
      const f = document.getElementById('vnc-frame');
      const vW = f.offsetWidth  || window.innerWidth;
      const vH = f.offsetHeight || (window.innerHeight - 83);
      let found = false;
      try {{
        const resp = await fetch('/screenshot?sid=' + SID + '&t=' + Date.now());
        if (resp.ok) {{
          const blob = await resp.blob();
          const bmpImg = new Image();
          const objUrl = URL.createObjectURL(blob);
          await new Promise(function(res) {{ bmpImg.onload = res; bmpImg.onerror = res; bmpImg.src = objUrl; }});
          URL.revokeObjectURL(objUrl);
          const sw = bmpImg.naturalWidth, sh = bmpImg.naturalHeight;
          if (sw > 0 && sh > 0) {{
            const cv = document.createElement('canvas');
            cv.width = sw; cv.height = sh;
            const cx2 = cv.getContext('2d');
            cx2.drawImage(bmpImg, 0, 0);
            /* Orange3 툴바 영역(약 83px/1080) 건너뜀 */
            const skipY = Math.round(83 * sh / 1080);
            const d = cx2.getImageData(0, skipY, sw, sh - skipY).data;
            let minX = sw, maxX = 0, minY = sh, maxY = 0;
            for (var py = 0; py < sh - skipY; py++) {{
              for (var px2 = 0; px2 < sw; px2++) {{
                var i4 = (py * sw + px2) * 4;
                var r = d[i4], g = d[i4+1], b = d[i4+2];
                /* 오렌지 선택 색상: #F47B20 ≈ rgb(244,123,32) */
                if (r > 195 && g > 55 && g < 165 && b < 85) {{
                  if (px2 < minX) minX = px2;
                  if (px2 > maxX) maxX = px2;
                  var gy = py + skipY;
                  if (gy < minY) minY = gy;
                  if (gy > maxY) maxY = gy;
                  found = true;
                }}
              }}
            }}
            if (found && (maxX - minX) > 8 && (maxY - minY) > 8) {{
              var selCx = (minX + maxX) / 2;
              var selCy = (minY + maxY) / 2;
              /* 스크린샷 좌표 → iframe 좌표 변환 */
              var fx2 = Math.round(selCx * vW / sw);
              var fy2 = Math.round(selCy * vH / sh);
              var tx2 = Math.round(vW / 2);
              var ty2 = Math.round(vH / 2);
              await fetch('/pan?sid=' + SID + '&fx=' + fx2 + '&fy=' + fy2 + '&tx=' + tx2 + '&ty=' + ty2 + '&cur=select');
              _mmAnalyzed = false;
              setTimeout(_mmRefresh, 700);
            }} else {{
              found = false;
            }}
          }}
        }}
      }} catch(e) {{}}
      if (!found) sbFit();
      setTimeout(function() {{ if (btn) btn.classList.remove('sb-active'); }}, 400);
    }}

    function _mmRefresh() {{
      var img = document.getElementById('sb-minimap-img');
      if (!img) return;
      // ②(2026-05-22): 미니맵이 접혀 있으면 /screenshot(컨테이너 scrot exec) 폴링 중단.
      // 미니맵 기본 접힘 → 평상시 세션당 scrot 폴링 0회로 절감.
      if (!sbMapOpen) return;
      if (!_mmAnalyzed) {{
        img.onload = function() {{
          img.style.display = 'block';  // 첫 로드 성공 시 표시
          if (!_mmAnalyzed) {{
            _mmAnalyzed = true;
            analyzeMinimapImg(img);
          }}
        }};
      }}
      img.src = '/screenshot?sid=' + _mmSid + '&t=' + Date.now();
    }}
    function sbToggleMap() {{
      sbMapOpen = !sbMapOpen;
      document.getElementById('sb-minimap').style.display = sbMapOpen ? 'flex' : 'none';
      document.getElementById('sb-map-btn').classList.toggle('sb-active', sbMapOpen);
      if (sbMapOpen) {{
        _mmRefresh();
        if (!_mmTimer) _mmTimer = setInterval(_mmRefresh, 3000);
      }} else {{
        if (_mmTimer) {{ clearInterval(_mmTimer); _mmTimer = null; }}
      }}
    }}

    /* ── 한글 입력 도우미 (2026-05-22) ──────────────────────────────────────
     * 캔버스 IME 보조 — 래퍼 페이지의 실제 input(브라우저 IME 정상)에 한글을
     * 입력받아 /sendtext → 컨테이너 xdotool type 으로 Orange3 포커스 창에 입력. */
    let imeOpen = false;
    function sbToggleIme() {{
      imeOpen = !imeOpen;
      document.getElementById('sb-ime-panel').style.display = imeOpen ? 'flex' : 'none';
      document.getElementById('sb-ime-btn').classList.toggle('sb-active', imeOpen);
      if (imeOpen) {{
        setTimeout(function() {{ document.getElementById('sb-ime-input').focus(); }}, 50);
      }}
    }}
    (function() {{
      var inp = document.getElementById('sb-ime-input');
      if (!inp) return;
      inp.addEventListener('keydown', function(e) {{
        // IME 조합 확정용 Enter(isComposing/keyCode 229)는 무시 — 조합 완료 후의 Enter만 전송
        if (e.key !== 'Enter' || e.isComposing || e.keyCode === 229) return;
        e.preventDefault();
        var txt = inp.value;
        if (!txt) return;
        fetch('/sendtext?sid=' + encodeURIComponent(SID)
              + '&text=' + encodeURIComponent(txt))
          .then(function(r) {{ return r.json(); }})
          .then(function(d) {{
            if (d && d.ok) {{ inp.value = ''; showToast('✓ 입력: ' + txt, 1500); }}
            else showToast('입력 실패: ' + ((d && d.error) || ''), 2500);
          }})
          .catch(function() {{ showToast('입력 전송 오류', 2500); }});
      }});
    }})();
    // ②(2026-05-22): 미니맵 폴링은 sbToggleMap()에서 펼침 시에만 타이머 시작.
    // 기존엔 접힘 상태에서도 무조건 2초마다 /screenshot 폴링 → scrot exec 낭비.
    // 첫 갱신도 미니맵이 펼쳐져 있을 때만 수행.
    setTimeout(function() {{ if (sbMapOpen) _mmRefresh(); }}, 5000);

    // VNC iframe 클릭(위젯 실행 등) 감지 → 1초 후 즉시 갱신
    // window blur = 사용자가 VNC iframe 쪽으로 포커스 이동한 시점
    (function() {{
      var _mmClickTimer = null;
      window.addEventListener('blur', function() {{
        if (!sbMapOpen) return;
        if (_mmClickTimer) clearTimeout(_mmClickTimer);
        _mmClickTimer = setTimeout(function() {{
          _mmRefresh();
          // 위젯 창이 열리는 데 시간이 걸릴 수 있으므로 2초 후 한 번 더
          setTimeout(_mmRefresh, 2000);
          _mmClickTimer = null;
        }}, 1000);
      }});
    }})();

    /* 옵션(언어)·메뉴 드롭다운: 캔버스(iframe) 클릭 시 닫기.
       iframe 내부 클릭은 부모 document 의 click 으로 버블되지 않아 5685 의
       document click 핸들러가 못 잡는다. window blur 직후 activeElement 가
       vnc-frame 으로 확정된 시점을 보고 "iframe 으로 포커스 이동"을 감지해,
       document click 핸들러(5699~)와 동일하게 lang/menu/sb-drop 을 닫는다. */
    (function() {{
      window.addEventListener('blur', function() {{
        // 포커스가 부모 페이지를 벗어남 = 캔버스(iframe) 클릭·alt-tab 등.
        // iframe 내부 클릭은 document click 으로 버블되지 않아 5685 핸들러가 못 잡으므로
        // 여기서 열린 드롭다운/메뉴를 닫는다. (activeElement 게이트는 cross-origin
        // iframe 에서 신뢰 불가 — blur 자체가 iframe 포커스 이동 신호. closeLang/
        // closeMenu 는 idempotent 라 닫힌 상태에서 호출해도 무해.)
        closeLang();
        var saveModal = document.getElementById('save-confirm-overlay');
        if (!(saveModal && saveModal.classList.contains('open'))) closeMenu();
        document.querySelectorAll('.sb-drop').forEach(function(d) {{ d.classList.remove('sb-open'); }});
      }});
    }})();

    /* ── VNC 연결 상태 감시 → 미니맵 오버레이 제어 ── */
    /* /ready 엔드포인트 사용 (same-origin) — VNC URL 직접 fetch 시 HTTPS mixed content 차단 방지 */
    let _vncReachable = true;
    function _mmSetDisc(disc) {{
      var el = document.getElementById('sb-minimap-disc');
      if (el) el.style.display = disc ? 'flex' : 'none';
    }}
    async function _checkVncReachable() {{
      try {{
        var r = await fetch('/ready?sid=' + SID);
        var data = await r.json();
        var isReady = data.ready === true;
        if (isReady && !_vncReachable) {{ _vncReachable = true; _mmSetDisc(false); }}
        else if (!isReady && _vncReachable) {{ _vncReachable = false; _mmSetDisc(true); }}
      }} catch(e) {{}}
      setTimeout(_checkVncReachable, 8000);
    }}
    setTimeout(_checkVncReachable, 5000);

    /* ── 패닝 오버레이: 클릭&드래그로 캔버스 화면 중심 이동 ──
       mousedown 시 document 레벨 mousemove/mouseup 등록 → 빠른 드래그에도 이벤트 손실 없음
       mousemove (throttle) → 누적 이동분만큼 캔버스 드래그
       mouseup → 드래그 종료 + 리스너 해제 */
    (function() {{
      const overlay = document.getElementById('pan-overlay');
      let isDragging = false;
      let lastX = 0, lastY = 0;
      let panInFlight = false;
      let lastPanMs = 0;
      const PAN_INTERVAL = 80;

      function onMove(e) {{
        if (!isDragging) return;
        e.preventDefault();
        const now = Date.now();
        if (panInFlight || now - lastPanMs < PAN_INTERVAL) return;
        const frame = document.getElementById('vnc-frame');
        const rect  = frame.getBoundingClientRect();
        const mx = Math.round(e.clientX - rect.left);
        const my = Math.round(e.clientY - rect.top);
        if (Math.abs(mx - lastX) < 4 && Math.abs(my - lastY) < 4) return;
        const sx = lastX, sy = lastY;
        lastX = mx; lastY = my;
        panInFlight = true;
        lastPanMs = now;
        applyMapPan(sx, sy, mx, my);
        // Hand 드래그: 마우스 이동 방향과 반대로 viewport 스크롤 (콘텐츠가 마우스 따라옴)
        const dx = sx - mx;
        const dy = sy - my;
        fetch('/pan2?sid=' + SID + '&dx=' + dx + '&dy=' + dy)
          .then(function() {{ panInFlight = false; }})
          .catch(function() {{ panInFlight = false; }});
      }}

      function onUp(e) {{
        if (!isDragging) return;
        isDragging = false;
        overlay.style.cursor = 'grab';
        document.removeEventListener('mousemove', onMove, true);
        document.removeEventListener('mouseup',   onUp,   true);
      }}

      overlay.addEventListener('mousedown', function(e) {{
        if (e.button !== 0) return;
        e.preventDefault();
        isDragging = true;
        const frame = document.getElementById('vnc-frame');
        const rect  = frame.getBoundingClientRect();
        lastX = Math.round(e.clientX - rect.left);
        lastY = Math.round(e.clientY - rect.top);
        overlay.style.cursor = 'grabbing';
        document.addEventListener('mousemove', onMove, true);
        document.addEventListener('mouseup',   onUp,   true);
      }});
    }})();

    /* ── 미니맵 클릭/드래그 → 메인 뷰 패닝 (이벤트 완전 격리) ── */
    (function() {{
      const mOverlay = document.getElementById('sb-minimap-overlay');
      let isDragging  = false;
      let panInFlight = false;   // xdotool 시퀀스 진행 중 여부
      let lastPanMs   = 0;       // 마지막 pan 전송 시각
      const PAN_INTERVAL = 100;  // scroll 이벤트는 drag보다 가벼움

      function miniPan(mx, my) {{
        const now = Date.now();
        if (panInFlight || now - lastPanMs < PAN_INTERVAL) return;
        const f = document.getElementById('vnc-frame');
        const vW = f.offsetWidth  || window.innerWidth;
        const vH = f.offsetHeight || (window.innerHeight - 83);
        const dX = (mx - MINI_W / 2 - mapPanX) / MINI_W * vW;
        const dY = (my - MINI_H / 2 - mapPanY) / MINI_H * vH;
        const fx = Math.round(vW / 2 + dX);
        const fy = Math.round(vH / 2 + dY);
        const tx = Math.round(vW / 2);
        const ty = Math.round(vH / 2);
        if (Math.abs(fx - tx) < 4 && Math.abs(fy - ty) < 4) return;
        const cfx = Math.max(0, Math.min(4096, fx));
        const cfy = Math.max(0, Math.min(4096, fy));
        applyMapPan(cfx, cfy, tx, ty);
        panInFlight = true;
        lastPanMs   = now;
        fetch('/scroll?sid=' + SID + '&fx=' + cfx + '&fy=' + cfy + '&tx=' + tx + '&ty=' + ty)
          .then(function()  {{ panInFlight = false; }})
          .catch(function() {{ panInFlight = false; }});
      }}

      function stopDrag() {{
        if (!isDragging) return;
        isDragging = false;
        mOverlay.classList.remove('dragging');
        document.removeEventListener('mousemove', onMove, true);
        document.removeEventListener('mouseup',   onUp,   true);
      }}

      function onMove(e) {{
        e.stopPropagation(); e.preventDefault();
        const br = mOverlay.getBoundingClientRect();
        miniPan(e.clientX - br.left, e.clientY - br.top);
      }}
      function onUp(e) {{
        e.stopPropagation();
        stopDrag();
      }}

      mOverlay.addEventListener('mousedown', function(e) {{
        if (e.button !== 0) return;
        e.preventDefault(); e.stopPropagation();
        isDragging = true;
        mOverlay.classList.add('dragging');
        document.addEventListener('mousemove', onMove, true);
        document.addEventListener('mouseup',   onUp,   true);
        const br = mOverlay.getBoundingClientRect();
        miniPan(e.clientX - br.left, e.clientY - br.top);
      }});

      // 미니맵 내 다른 이벤트가 외부로 전파되지 않도록 차단
      ['click','dblclick','contextmenu','mouseup','mousemove'].forEach(function(t) {{
        mOverlay.addEventListener(t, function(e) {{ e.stopPropagation(); e.preventDefault(); }});
      }});

      // iframe 포커스 이동 시 드래그 상태 초기화
      window.addEventListener('blur', stopDrag);
    }})();

    // 초기 뷰포트 표시기 렌더링
    updateVpRect();

    /* ── 워크플로우 탭 바 (단일 세션 / save-load 방식) ── */
    (function() {{
      /* 빈 Orange3 워크플로우 XML */
      var EMPTY_OWS = '<?xml version="1.0" encoding="utf-8"?>' +
        '<scheme version="2.0" title="" description="">' +
        '<nodes /><links /><annotations /><thumbnail /></scheme>';

      var tabs      = [];   /* {{ title, blob }} */
      var active    = 0;
      var busy      = false;
      var wfCounter = 0;   /* 탭 생성 누적 카운터 */

      /* "Unsaved Workflow" / "Unsaved Workflow (n)" 레이블 */
      function tabLabel(n) {{
        return n === 1 ? 'Unsaved Workflow' : 'Unsaved Workflow (' + n + ')';
      }}

      /* 기본(미저장) 제목인지 판별 — 언어별 docTitle + 빈 문자열 */
      var _DEFAULT_TITLES = Object.keys(LANGS).map(function(k) {{ return LANGS[k].docTitle; }});
      function isDefaultTitle(t) {{
        return !t || _DEFAULT_TITLES.indexOf(t) >= 0;
      }}

      /* 탭 스크롤 화살표 + ··· overflow 버튼 표시/비활성화 갱신.
         사용자 요청: 탭이 7개 이상 구성되면 양옆 화살표 + 우측 ··· 메뉴 모두 표시. */
      function _wfUpdateScrollButtons() {{
        var inner = document.getElementById('wf-tabbar-inner');
        var left  = document.getElementById('wf-tab-scroll-left');
        var right = document.getElementById('wf-tab-scroll-right');
        var ovrf  = document.getElementById('wf-tab-overflow-btn');
        if (!inner || !left || !right) return;
        // 7개 이상 탭이 구성되면 화살표 + ··· 표시 (사용자 요구 — count 기반)
        var showArrows = tabs.length >= 7;
        left.classList.toggle('visible', showArrows);
        right.classList.toggle('visible', showArrows);
        if (ovrf) ovrf.classList.toggle('visible', showArrows);
        if (!showArrows) return;
        // 좌/우 끝 도달 여부 → disabled 클래스 (스크롤 가능할 때만 의미)
        var canScroll = inner.scrollWidth > inner.clientWidth + 1;
        var atStart = inner.scrollLeft <= 1;
        var atEnd   = !canScroll || (inner.scrollLeft + inner.clientWidth >= inner.scrollWidth - 1);
        left.classList.toggle('disabled', atStart);
        right.classList.toggle('disabled', atEnd);
      }}

      /* ··· 클릭 시 전체 탭 목록 팝업 토글 — 항목 클릭 시 그 탭으로 즉시 전환. */
      function _wfToggleOverflowMenu(anchorBtn) {{
        var menu = document.getElementById('wf-tab-overflow-menu');
        if (!menu) {{
          menu = document.createElement('div');
          menu.id = 'wf-tab-overflow-menu';
          document.body.appendChild(menu);
        }}
        // 이미 열려있으면 닫기
        if (menu.classList.contains('open')) {{
          menu.classList.remove('open');
          return;
        }}
        // 항목 채우기
        menu.innerHTML = '';
        tabs.forEach(function(tab, i) {{
          var item = document.createElement('div');
          item.className = 'wf-overflow-item' + (i === active ? ' active' : '');
          var check = document.createElement('span');
          check.className = 'wf-overflow-check';
          check.textContent = (i === active) ? '✓' : '';
          item.appendChild(check);
          var label = document.createElement('span');
          label.className = 'wf-overflow-label';
          label.textContent = tab.title || 'Unsaved Workflow';
          item.appendChild(label);
          item.addEventListener('click', (function(idx) {{
            return function() {{
              menu.classList.remove('open');
              wfSwitch(idx);
            }};
          }})(i));
          menu.appendChild(item);
        }});
        // 버튼 아래에 위치 (fixed 좌표)
        var rect = anchorBtn.getBoundingClientRect();
        menu.style.top  = (rect.bottom + 4) + 'px';
        // 메뉴가 화면 우측 경계 넘으면 anchor 우측에 맞춰 정렬
        menu.classList.add('open');  // 일단 표시해야 너비 측정 가능
        var menuRect = menu.getBoundingClientRect();
        var left = rect.left;
        if (left + menuRect.width > window.innerWidth - 10) {{
          left = Math.max(10, rect.right - menuRect.width);
        }}
        menu.style.left = left + 'px';
      }}

      /* 팝업 외부 클릭 시 닫기 */
      document.addEventListener('click', function(e) {{
        var menu = document.getElementById('wf-tab-overflow-menu');
        if (!menu || !menu.classList.contains('open')) return;
        var btn = document.getElementById('wf-tab-overflow-btn');
        if (menu.contains(e.target)) return;
        if (btn && btn.contains(e.target)) return;
        menu.classList.remove('open');
      }});

      function render() {{
        var bar = document.getElementById('wf-tabbar');
        bar.innerHTML = '';

        // 좌측 스크롤 버튼
        var leftBtn = document.createElement('button');
        leftBtn.id = 'wf-tab-scroll-left';
        leftBtn.className = 'wf-tab-scroll';
        leftBtn.title = '이전 탭으로 스크롤';
        leftBtn.textContent = '‹';  /* ‹ */
        leftBtn.addEventListener('click', function() {{
          var inner = document.getElementById('wf-tabbar-inner');
          if (inner) inner.scrollBy({{ left: -200, behavior: 'smooth' }});
        }});
        bar.appendChild(leftBtn);

        // 탭 컨테이너 (스크롤 가능)
        var inner = document.createElement('div');
        inner.id = 'wf-tabbar-inner';
        tabs.forEach(function(tab, i) {{
          var el = document.createElement('div');
          el.className = 'wf-tab' + (i === active ? ' wf-active' : '');
          if (busy && i === active) el.style.opacity = '0.6';

          var titleEl = document.createElement('span');
          titleEl.className = 'wf-tab-title';
          titleEl.textContent = tab.title || 'Unsaved Workflow';
          el.appendChild(titleEl);

          if (i === active) {{
            var closeEl = document.createElement('span');
            closeEl.className = 'wf-tab-close';
            closeEl.textContent = '✕';
            closeEl.addEventListener('click', (function(idx) {{
              return function(e) {{ e.stopPropagation(); wfConfirmClose(idx); }};
            }})(i));
            el.appendChild(closeEl);
          }} else {{
            var dotEl = document.createElement('span');
            dotEl.className = 'wf-tab-dot';
            dotEl.textContent = '·';
            el.appendChild(dotEl);
          }}

          el.addEventListener('click', (function(idx) {{
            return function() {{ wfSwitch(idx); }};
          }})(i));
          inner.appendChild(el);
        }});
        bar.appendChild(inner);

        // 우측 스크롤 버튼
        var rightBtn = document.createElement('button');
        rightBtn.id = 'wf-tab-scroll-right';
        rightBtn.className = 'wf-tab-scroll';
        rightBtn.title = '다음 탭으로 스크롤';
        rightBtn.textContent = '›';  /* › */
        rightBtn.addEventListener('click', function() {{
          var innerEl = document.getElementById('wf-tabbar-inner');
          if (innerEl) innerEl.scrollBy({{ left: 200, behavior: 'smooth' }});
        }});
        bar.appendChild(rightBtn);

        // ··· 전체 탭 목록 팝업 버튼 (우측 화살표 다음, + 버튼 앞에 위치)
        var overflowBtn = document.createElement('button');
        overflowBtn.id = 'wf-tab-overflow-btn';
        overflowBtn.className = 'wf-tab-scroll';  /* 동일한 스타일 베이스 사용 */
        overflowBtn.title = '전체 탭 목록';
        overflowBtn.textContent = '···';
        overflowBtn.addEventListener('click', function(e) {{
          e.stopPropagation();
          _wfToggleOverflowMenu(overflowBtn);
        }});
        bar.appendChild(overflowBtn);

        // + (새 탭) 버튼
        var addBtn = document.createElement('div');
        addBtn.className = 'wf-tab-add';
        addBtn.textContent = '+';
        addBtn.title = '새 워크플로우';
        addBtn.addEventListener('click', wfAddTab);
        bar.appendChild(addBtn);

        // 스크롤 위치/overflow 갱신 — DOM mount 이후 layout 안정화 위해 다음 tick
        // 활성 탭이 화면 밖이면 스크롤하여 가시 영역으로 이동
        setTimeout(function() {{
          var innerEl = document.getElementById('wf-tabbar-inner');
          if (innerEl) {{
            var activeEl = innerEl.children[active];
            if (activeEl && (activeEl.offsetLeft < innerEl.scrollLeft
                || activeEl.offsetLeft + activeEl.offsetWidth > innerEl.scrollLeft + innerEl.clientWidth)) {{
              activeEl.scrollIntoView({{ behavior: 'smooth', block: 'nearest', inline: 'nearest' }});
            }}
            innerEl.addEventListener('scroll', _wfUpdateScrollButtons, {{ passive: true }});
          }}
          _wfUpdateScrollButtons();
        }}, 0);
      }}

      /* 현재 탭 상태를 서버에서 저장해 blob에 보관
         서버가 최대 10초 대기하므로 타임아웃 없이 완료를 기다림 (데이터 유실 방지)
         busy 영구 잠금은 호출 측 try/finally 에서 보장 */
      async function saveCurrent() {{
        try {{
          var t = document.getElementById('doc-title').textContent;
          if (!isDefaultTitle(t)) tabs[active].title = t;
          var r = await fetch('/save-workflow?sid=' + SID);
          if (r && r.ok) tabs[active].blob = await r.blob();
        }} catch(e) {{}}
      }}

      /* blob 또는 빈 캔버스를 Orange3에 로드 */
      async function loadTab(tab) {{
        _mmAnalyzed = false; mapPanX = 0; mapPanY = 0; updateVpRect();
        var blob = tab.blob
          ? tab.blob
          : new Blob([EMPTY_OWS], {{type: 'text/xml'}});
        var fname = (tab.title || 'workflow').replace(/[^\w\-_. ]/g, '_') + '.ows';
        var fd = new FormData();
        fd.append('file', blob, fname);
        try {{
          await fetch('/open-workflow?sid=' + SID, {{method:'POST', body:fd}});
          /* 와처 주기 0.2s + Qt 처리 (load_scheme 자체는 빠름) — 900ms → 450ms 단축 (2026-05-28) */
          await new Promise(function(res) {{ setTimeout(res, 450); }});
          document.getElementById('doc-title').textContent = tab.title;
        }} catch(e) {{}}
        /* 탭 전환 직후 미니맵 즉시 갱신 (0.8s, 2.0s 두 번 연속) */
        setTimeout(_mmRefresh, 800);
        setTimeout(_mmRefresh, 2000);
      }}

      /* 탭 전환 — try/finally 로 busy 항상 해제 */
      async function wfSwitch(toIdx) {{
        if (busy || toIdx === active) return;
        busy = true; render();
        try {{
          await saveCurrent();
          active = toIdx; render();
          await loadTab(tabs[active]);
        }} finally {{
          busy = false; render();
        }}
      }}

      /* 새 탭 — try/finally 로 busy 항상 해제 */
      async function wfAddTab() {{
        if (busy) return;
        if (tabs.length >= 20) {{ showToast('탭은 최대 20개까지 사용할 수 있습니다.', 2500); return; }}
        busy = true; render();
        try {{
          await saveCurrent();
          wfCounter++;
          tabs.push({{ title: tabLabel(wfCounter), blob: null }});
          active = tabs.length - 1; render();
          await loadTab(tabs[active]);
        }} finally {{
          busy = false; render();
        }}
      }}

      /* 탭 닫기 확인 모달 */
      var _closeModalIdx = -1;

      function wfConfirmClose(idx) {{
        /* 탭이 1개일 때도 모달을 표시 — 저장 기능을 쓸 수 있어야 함 (2026-05-22).
           탭 1개는 저장만 하고 닫지 않음(modalSave/modalNo 에서 분기 처리). */
        if (busy) return;
        _closeModalIdx = idx;
        var name = tabs[idx].title || 'Unsaved Workflow';
        document.getElementById('close-modal-wf-name').textContent = name;
        document.getElementById('close-modal').classList.add('open');
      }}

      function modalCancel() {{
        document.getElementById('close-modal').classList.remove('open');
        _closeModalIdx = -1;
      }}

      async function modalSave() {{
        document.getElementById('close-modal').classList.remove('open');
        var idx = _closeModalIdx;
        _closeModalIdx = -1;
        if (idx < 0) return;
        /* X 버튼은 활성 탭에만 표시되므로 idx === active 가 보장됨.
           _doSaveWorkflow(): 실제 저장 대화상자 → 저장 완료까지 await, 성공 시 true 반환. */
        var saved = false;
        if (typeof window._doSaveWorkflow === 'function') {{
          saved = await window._doSaveWorkflow();
        }}
        /* 저장 성공 후 (2026-05-22):
           · 탭 2개 이상 → 해당 탭을 닫음
           · 탭 1개      → 닫지 않고 그대로 유지 (마지막 탭 보호) */
        if (saved && tabs.length > 1) {{
          await wfClose(idx, false);
        }}
      }}

      async function modalNo() {{
        document.getElementById('close-modal').classList.remove('open');
        var idx = _closeModalIdx;
        _closeModalIdx = -1;
        if (idx < 0) return;
        /* 저장 없이 탭 닫기 — 탭이 1개뿐이면 닫지 않음 (마지막 탭 보호, 2026-05-22). */
        if (tabs.length === 1) return;
        await wfClose(idx, false);
      }}

      /* 탭 닫기 — try/finally 로 busy 항상 해제 */
      async function wfClose(idx, doSave) {{
        if (busy || tabs.length === 1) return;
        busy = true; render();
        try {{
          if (idx === active) {{
            if (doSave) await saveCurrent();
            tabs.splice(idx, 1);
            active = Math.min(active, tabs.length - 1);
            render();
            await loadTab(tabs[active]);
          }} else {{
            tabs.splice(idx, 1);
            if (active > idx) active--;
            render();
          }}
        }} finally {{
          busy = false; render();
        }}
      }}

      /* doc-title 변경 → 활성 탭 제목 동기화 (실제 파일명일 때만 덮어씀) */
      var docTitleEl = document.getElementById('doc-title');
      new MutationObserver(function() {{
        if (!busy && tabs[active]) {{
          var t = docTitleEl.textContent;
          if (!isDefaultTitle(t)) {{
            tabs[active].title = t;
            render();
          }}
        }}
      }}).observe(docTitleEl, {{ childList:true, characterData:true, subtree:true }});

      /* 초기화 */
      wfCounter = 1;
      tabs = [{{ title: tabLabel(1), blob: null }}];
      render();

      /* 윈도우 resize 시 탭바 overflow 재계산 → 스크롤 화살표 표시 갱신 */
      window.addEventListener('resize', function() {{ _wfUpdateScrollButtons(); }});

      /* 베이직 템플릿을 새 탭으로 추가 — blob 을 컨테이너에서 fetch 후 탭에 적재
         성능 최적화 (2026-05-28):
         · 현재 탭이 미저장(default) + blob 없음 → saveCurrent 스킵 (~600ms 절약)
         · saveCurrent 와 /template_blob fetch 를 병렬 실행 (직렬 → 병렬, ~500ms 절약) */
      async function wfAddTemplateTab(path, title, filename) {{
        if (busy) return;
        if (tabs.length >= 20) {{ showToast('탭은 최대 20개까지 사용할 수 있습니다.', 2500); return; }}
        busy = true; render();
        try {{
          // 현재 탭이 비어있지 않을 때만 save (default title + blob 미보유 시 스킵)
          var curTitle = document.getElementById('doc-title').textContent;
          var skipSave = isDefaultTitle(curTitle) && !tabs[active].blob;
          var savePromise = skipSave ? Promise.resolve() : saveCurrent();
          var fetchPromise = fetch('/template_blob?sid=' + SID + '&path=' + encodeURIComponent(path));
          // 두 작업 병렬 실행 — fetch 는 save 와 독립적
          var results = await Promise.all([savePromise, fetchPromise]);
          var r = results[1];
          if (!r.ok) throw new Error('템플릿 로드 실패');
          var blob = await r.blob();
          // 파일명을 그대로 탭 타이틀로 사용 (확장자 제거)
          var tabTitle = title || (filename || 'workflow').replace(/\.ows$/i, '');
          tabs.push({{ title: tabTitle, blob: blob }});
          active = tabs.length - 1; render();
          await loadTab(tabs[active]);
        }} catch(e) {{
          showToast('템플릿 열기 실패: ' + (e.message || e), 3000);
        }} finally {{
          busy = false; render();
        }}
      }}

      /* 사용자 선택 파일(.ows)을 새 탭으로 추가 — Open 메뉴에서 사용 */
      async function wfAddFileTab(file) {{
        if (!file) return;
        if (busy) return;
        if (tabs.length >= 20) {{ showToast('탭은 최대 20개까지 사용할 수 있습니다.', 2500); return; }}
        busy = true; render();
        try {{
          await saveCurrent();
          var tabTitle = (file.name || 'workflow').replace(/\.ows$/i, '');
          tabs.push({{ title: tabTitle, blob: file }});
          active = tabs.length - 1; render();
          await loadTab(tabs[active]);
          showToast('✓ ' + file.name + ' 새 탭에서 열림', 2500);
        }} catch(e) {{
          showToast('파일 열기 실패: ' + (e.message || e), 3000);
        }} finally {{
          busy = false; render();
        }}
      }}

      /* 모달 함수 전역 노출 (onclick 속성에서 접근 가능하도록) */
      window.modalSave        = modalSave;
      window.modalNo          = modalNo;
      window.modalCancel      = modalCancel;
      window.wfAddTab         = wfAddTab;
      window.wfAddTemplateTab = wfAddTemplateTab;
      window.wfAddFileTab     = wfAddFileTab;
      /* 메뉴의 "닫기" 항목 전용: 현재 활성 탭의 X 클릭과 동일 동작 */
      window.wfCloseActive    = function() {{ wfConfirmClose(active); }};
      /* 활성 탭 이름 변경 — 저장 완료 후 파일명으로 탭 라벨 업데이트용.
         #doc-title 도 동시에 동기화 — 다음 탭 전환 시 saveCurrent() 가 stale doc-title 을
         읽어 새 파일명을 덮어쓰는 버그 방지 (display:none 이라도 textContent 는 정상 갱신됨). */
      window.wfRenameActive   = function(newTitle) {{
        if (!newTitle || typeof newTitle !== 'string') return;
        if (!tabs[active]) return;
        tabs[active].title = newTitle;
        try {{
          var docTitleEl = document.getElementById('doc-title');
          if (docTitleEl) docTitleEl.textContent = newTitle;
        }} catch(_) {{}}
        render();
      }};
    }})();
  </script>

  <!-- 언어 드롭다운: body 직속으로 루트 z-index 보장 -->
  <div id="lang-dropdown">
    <div class="li" onclick="setLang('ko')">한국어</div>
    <div class="li" onclick="setLang('en')">English</div>
    <div class="li" onclick="setLang('sl')">Slovenčina</div>
  </div>
  <!-- 언어 드롭다운 바깥(캔버스) 클릭 감지용 투명 백드롭: iframe 내부 클릭은 부모
       document 의 click 으로 버블되지 않으므로, 드롭다운이 열린 동안 캔버스 위를 덮어
       클릭을 잡아 닫는다. 헤더 영역은 덮지 않음(top 동적 = 헤더 아래). -->
  <div id="lang-backdrop" onclick="closeLang()"></div>

  <!-- 세션 메타 정보 패널 — 좌하단, 회색 10pt -->
  <style id="x-meta-info-style">
    #x-meta-info {{
      position: fixed; left: 47px; bottom: 22px; z-index: 50;
      font-family: -apple-system,BlinkMacSystemFont,"Segoe UI","Malgun Gothic",sans-serif;
      font-size: 10pt; color: #9ca3af; line-height: 1.55;
      /* 불투명 흰 박스가 좌하단 위젯을 가리던 문제 → 배경 제거하고 흰색 글로우
         그림자로 캔버스 위 가독성 유지(위젯이 그대로 보임). 클릭은 pointer-events:none */
      background: transparent;
      padding: 0; border-radius: 0;
      text-shadow: 0 0 3px #fff, 0 0 3px #fff, 0 0 6px #fff;
      pointer-events: none;
      display: grid; grid-template-columns: auto auto; column-gap: 22px; row-gap: 2px;
    }}
    #x-meta-info > div {{ white-space: nowrap; }}
  </style>
  <div id="x-meta-info">
    <div><span class="x-mi-lbl" data-key="ver">· Orange3 버전 정보 : </span><span id="x-mi-ver">—</span></div>
    <div><span class="x-mi-lbl" data-key="lng">· Lang : </span><span id="x-mi-lng">—</span></div>
    <div><span class="x-mi-lbl" data-key="cnt">· 위젯 개수 : </span><span id="x-mi-cnt">—</span></div>
    <div><span class="x-mi-lbl" data-key="eng">· 운영 방식 : </span><span id="x-mi-eng">—</span></div>
  </div>
  <script>
  (function() {{
    // 언어별 라벨 — 다른 UI 와 동일하게 INIT_LANG 따름. 비지원 언어는 영어 fallback.
    var LBLS = {{
      ko: {{ ver: '· Orange3 버전 정보 : ', cnt: '· 위젯 개수 : ',   eng: '· 운영 방식 : ',  lng: '· 언어 : ' }},
      en: {{ ver: '· Orange3 Version : ',   cnt: '· Widget Count : ', eng: '· Method : ',     lng: '· Lang : ' }},
      sl: {{ ver: '· Različica Orange3 : ', cnt: '· Število gradnikov : ', eng: '· Način : ', lng: '· Jezik : ' }}
    }};
    var _cur = (typeof INIT_LANG !== 'undefined' ? INIT_LANG : 'en');
    var L = LBLS[_cur] || LBLS.en;
    var lbls = document.querySelectorAll('.x-mi-lbl');
    for (var i = 0; i < lbls.length; i++) {{
      var k = lbls[i].getAttribute('data-key');
      if (L[k]) lbls[i].textContent = L[k];
    }}
    // 현재 언어 값 표시 — Korean / English / Slovenščina
    var LANG_NAMES = {{ ko: '한국어', en: 'English', sl: 'Slovenščina' }};
    document.getElementById('x-mi-lng').textContent = LANG_NAMES[_cur] || _cur;
    // 엔진 판정은 URL 마스킹 전에 결정된 window._isXpra 사용.
    // (마스킹 후 location.pathname 으로 재검사하면 항상 false 가 나옴.)
    var isPilot = (window._isXpra === true);
    var url = '/api/session/meta?engine=' + (isPilot ? 'pilot' : 'basic');
    document.getElementById('x-mi-eng').textContent = isPilot ? 'Pilot' : 'Basic';
    function fill(retry) {{
      fetch(url, {{cache:'no-store'}})
        .then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          var verEl = document.getElementById('x-mi-ver');
          var cntEl = document.getElementById('x-mi-cnt');
          if (d && d.version) verEl.textContent = d.version;
          if (d && (d.active_widgets || d.active_widgets === 0))
            cntEl.textContent = d.active_widgets;
          // version 이 "—" (워밍풀 아직 미준비) 면 한 번 더 시도
          if (retry > 0 && d && (d.version === '—' || !d.version)) {{
            setTimeout(function() {{ fill(retry - 1); }}, 5000);
          }}
        }})
        .catch(function() {{ /* 무시 — 패널은 빈 값 유지 */ }});
    }}
    fill(2);
  }})();
  </script>
</body>
</html>"""


NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}


def html_response(content: str, status_code: int = 200) -> HTMLResponse:
    resp = HTMLResponse(content=content, status_code=status_code)
    for k, v in NO_CACHE.items():
        resp.headers[k] = v
    return resp


# ── 라우트 ──

@app.get("/load", response_class=HTMLResponse)
async def load_index_page():
    """서비스 구성도 / 이동 페이지. nginx(8889) 뿐 아니라 session_manager(8888,
    GCE 방화벽 개방 포트)로도 서빙해 서버 외부에서도 접근 가능하게 함."""
    for _p in ("/app/load_index.html", "/load_index.html"):
        try:
            with open(_p, encoding="utf-8") as _f:
                return html_response(_f.read())
        except FileNotFoundError:
            continue
        except Exception as _e:
            return html_response(f"<h1>load 페이지 오류</h1><p>{_e}</p>", 500)
    return html_response("<h1>load_index.html 없음</h1>", 404)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, sid: str | None = None, lang: str | None = None,
                open_path: str | None = None, engine: str | None = None):
    # lang 파라미터 검증 — 미전달·잘못된 값은 admin default 사용 (env-hardcoded "en" 아님)
    _VALID_LANGS  = {"ko", "en", "sl"}
    _LANG_NAMES   = {"ko": "Korean", "en": "English", "sl": "Slovenian"}
    # admin_settings.languages.default 를 fallback 로 사용 — 미전달/잘못된 lang 일 때만.
    # 명시된 ?lang=ko 등은 그대로 우선. available 목록 검증도 동시 적용.
    try:
        _admin = _admin_load_settings()
        _avail   = _admin.get("languages", {}).get("available") or list(_VALID_LANGS)
        _default = _admin.get("languages", {}).get("default") or "en"
    except Exception:
        _avail, _default = list(_VALID_LANGS), "en"
    if lang in _VALID_LANGS and lang in _avail:
        lang_str = lang
    elif _default in _avail:
        lang_str = _default
    else:
        lang_str = _avail[0] if _avail else "en"
    lang = lang_str
    # open_path: 베이직 템플릿을 새 세션에서 자동으로 열기 위한 컨테이너 내 경로
    # 보안: 경로 검증 (.ows 끝나야 함, 상대 경로 금지)
    _open_path: str | None = None
    if open_path and open_path.endswith(".ows") and ".." not in open_path:
        _open_path = open_path

    if client is None:
        return html_response("<h1>Docker 연결 오류</h1>", 503)

    # Phase 5 (2026-05-23): engine 분기 — URL 파라미터(?engine=xpra) 우선,
    # 다음 환경변수 DEFAULT_ENGINE (기본 "novnc"). Xpra 분기는 /xpra-go 로 위임
    # (워밍풀 pop + wrapper redirect). lang/open_path 등은 분기에서 무시 (Xpra
    # wrapper 가 자체 처리).
    _DEFAULT_ENGINE = os.environ.get("DEFAULT_ENGINE", "novnc").lower()
    _engine = (engine or _DEFAULT_ENGINE).lower()
    if _engine == "xpra" and not sid:
        return RedirectResponse("/xpra-go", status_code=302)

    # ── sid 없음 → 탭별 sessionStorage 확인 dispatch 페이지 반환 ──────────────
    # 각 탭이 독립적인 sessionStorage를 가지지만, 탭 복제(duplicate)·북마크 등으로 인해
    # 같은 SID가 여러 탭에서 사용될 수 있음. PerformanceNavigationTiming.type 으로 구분:
    #  - 'reload' (F5/Ctrl+R): 같은 탭 새로고침 → 저장된 SID 재사용
    #  - 그 외 ('navigate', 'back_forward' 등): 새 탭/복제 → 새 세션 강제
    if not sid:
        # dispatch: sessionStorage 의 'orange3_lang' 우선 → admin 기본 → server lang
        # F5 새로고침 시 마지막 선택 언어 유지 (2026-05-27).
        valid_codes_js = "['ko','en','sl']"
        dispatch = (
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
            "<style>body{background:#fff;margin:0}</style></head><body>"
            "<script>(function(){"
            "var defaultLang='" + lang + "';"
            "var storedLang=sessionStorage.getItem('orange3_lang')||'';"
            "var valid=" + valid_codes_js + ";"
            "var lang=(storedLang && valid.indexOf(storedLang)>=0) ? storedLang : defaultLang;"
            "var stored=sessionStorage.getItem('orange3_sid');"
            "var navType='navigate';"
            "try{var n=performance.getEntriesByType('navigation');"
            "if(n&&n[0]&&n[0].type)navType=n[0].type;"
            "else if(performance.navigation&&performance.navigation.type===1)navType='reload';}catch(_){}"
            "if(stored && navType==='reload'){location.replace('/?sid='+stored+'&lang='+lang);}"
            "else{sessionStorage.removeItem('orange3_sid');location.replace('/?sid=new&lang='+lang);}"
            "})();</script></body></html>"
        )
        return html_response(dispatch)

    # ── sid == "new" → 새 세션 생성 ────────────────────────────────────────────
    if sid == "new":
        with _warm_lock:
            warm_sid = _warm_pool.pop(0) if _warm_pool else None

        if warm_sid:
            with _lock:
                if warm_sid in sessions:
                    sessions[warm_sid]["warm"] = False
                    sessions[warm_sid]["last_seen"] = time.time()
            if lang != "en":
                try:
                    w_dir = os.path.join(CONTAINER_SESSIONS_PATH, warm_sid)
                    with open(os.path.join(w_dir, ".lang_override"), "w") as _f:
                        _f.write(f"language={_LANG_NAMES[lang]}\nlast-used-language=English")
                    try:
                        os.remove(os.path.join(w_dir, ".app_ready"))
                    except FileNotFoundError:
                        pass
                    with open(os.path.join(w_dir, ".restart_language"), "w") as _f:
                        _f.write("1")
                    log.info(f"[{s8(warm_sid)}] warm 세션 언어 적용: {_LANG_NAMES[lang]}")
                except Exception as _e:
                    log.warning(f"[{s8(warm_sid)}] warm 언어 적용 실패: {_e}")
            asyncio.create_task(_replenish_pool())
            log.info(f"[{s8(warm_sid)}] 예열 풀에서 배정 (남은 풀: {len(_warm_pool)}) lang={lang}")
            new_sid = warm_sid
        else:
            # 예열 풀 비어있음 → 새 컨테이너 직접 생성.
            # Windows Hyper-V 동적 포트 예약 충돌 대응: 최대 6회 다른 포트로 재시도.
            new_sid = str(uuid.uuid4())
            container_session_dir = os.path.join(CONTAINER_SESSIONS_PATH, new_sid)
            os.makedirs(container_session_dir, exist_ok=True)
            if lang != "en":
                try:
                    with open(os.path.join(container_session_dir, ".lang_override"), "w") as _f:
                        _f.write(f"language={_LANG_NAMES[lang]}\nlast-used-language=English")
                    log.info(f"[{s8(new_sid)}] 컨테이너 기동 전 언어 사전 설정: {_LANG_NAMES[lang]}")
                except Exception as _e:
                    log.warning(f"[{s8(new_sid)}] 언어 사전 설정 실패: {_e}")
            host_session_dir = os.path.join(HOST_SESSIONS_PATH, new_sid)
            widget_vols = build_widget_override_volumes()
            container = None
            port = None
            last_err: Exception | None = None
            MAX_RETRIES = 6
            for attempt in range(MAX_RETRIES):
                try:
                    port = allocate_port()
                except RuntimeError as e:
                    return HTMLResponse(_friendly_error_page(
                        title="용량 초과",
                        message="현재 동시 접속 가능한 인원이 가득 찼습니다. 잠시 후 다시 시도해 주세요.",
                        hint=str(e),
                    ), status_code=503)
                try:
                    container = client.containers.run(
                        ORANGE3_IMAGE,
                        detach=True,
                        ports={"5800/tcp": ("0.0.0.0", port)},
                        volumes={
                            host_session_dir: {"bind": "/config", "mode": "rw"},
                            HOST_DATA_PATH:   {"bind": "/data",   "mode": "ro"},
                            **widget_vols,
                            **build_upload_ows_volume(),
                **build_shared_thumbs_volume(),
                            **build_launcher_volume(),
                        },
                        labels={"orange3.session": new_sid, "orange3.managed": "true"},
                        environment={"QT_STYLE_OVERRIDE": "Fusion", "ORANGE3_SPLASH_LOADING": _splash_loading_env_val()},
                        remove=False,
                        mem_limit=CONTAINER_MEM_LIMIT,
                        memswap_limit=CONTAINER_MEM_LIMIT,
                        cpu_quota=400000,
                        cpu_period=100000,
                        shm_size="536870912",
                    )
                    log.info(f"[{s8(new_sid)}] 컨테이너 {container.short_id} → 포트 {port} lang={lang} (attempt {attempt+1})")
                    break  # 성공
                except Exception as e:
                    last_err = e
                    msg = str(e).lower()
                    # Windows port conflict: 외부 요인이 점유 → 해당 포트 차단 후 다른 포트로 재시도.
                    is_port_conflict = (
                        "ports are not available" in msg
                        or "bind: only one usage" in msg
                        or "address already in use" in msg
                        or "bind: permission denied" in msg
                    )
                    if is_port_conflict and port is not None:
                        log.warning(f"[{s8(new_sid)}] 포트 {port} 충돌 (시도 {attempt+1}/{MAX_RETRIES}) — 차단 후 재할당")
                        block_port(port)
                        port = None
                        continue
                    # 다른 종류의 오류는 즉시 중단.
                    log.error(f"[{s8(new_sid)}] 컨테이너 생성 실패 (시도 {attempt+1}): {e}")
                    if port is not None:
                        release_port(port)
                    break
            if container is None:
                # 모든 재시도 실패 → 친화 에러 페이지 (이미지 2 스타일)
                hint = ""
                if last_err is not None:
                    hint = str(last_err)[:200]
                return HTMLResponse(_friendly_error_page(
                    title="접속이 원활하지 않습니다",
                    message="잠시 후 다시 시도해 주세요. 문제가 계속되면 관리자에게 문의하세요.",
                    hint=hint,
                ), status_code=503)
            with _lock:
                sessions[new_sid] = {
                    "container_id": container.id,
                    "port": port,
                    "last_seen": time.time(),
                }
            confirm_port(port)
            # noVNC HTML Delete 키 인터셉트 패치
            asyncio.create_task(_patch_novnc(container, s8(new_sid)))

        # 새 세션에서 베이직 템플릿 자동 열기 (open_path 가 지정된 경우)
        if _open_path:
            try:
                container = client.containers.get(str(sessions[new_sid]["container_id"]))
                fname = os.path.basename(_open_path)
                # 컨테이너 내 .ows 파일을 /tmp/ 로 복사 + open_workflow 신호 작성
                # 동일 파일명을 유지해 Orange3 가 그 이름으로 저장하도록 함
                copy_cmd = (
                    f"cp '{_open_path}' '/tmp/{fname}' && "
                    f"printf '%s' '/tmp/{fname}' > /config/.open_workflow"
                )
                container.exec_run(["sh", "-c", copy_cmd])
                log.info(f"[{s8(new_sid)}] open_path 자동 로드: {fname}")
            except Exception as _e:
                log.warning(f"[{s8(new_sid)}] open_path 자동 로드 실패: {_e}")
        # sessionStorage에 SID 저장 후 실제 세션 URL로 이동
        init_page = (
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
            "<style>body{background:#fff;margin:0}</style></head><body>"
            f"<script>sessionStorage.setItem('orange3_sid','{new_sid}');"
            f"location.replace('/?sid={new_sid}&lang={lang}');</script>"
            "</body></html>"
        )
        return html_response(init_page)

    # ── sid == UUID → 기존 세션 확인 ───────────────────────────────────────────
    with _lock:
        info = sessions.get(sid)

    if not info:
        # 세션 없음(만료·orphan) → dispatch 페이지로 새 세션 생성
        log.info(f"[{s8(sid)}] 세션 없음 → dispatch")
        dispatch = (
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
            "<style>body{background:#fff;margin:0}</style></head><body>"
            "<script>(function(){{"
            "sessionStorage.removeItem('orange3_sid');"
            f"location.replace('/?sid=new&lang={lang}');"
            "}})();</script></body></html>"
        )
        return html_response(dispatch)

    # xpra 세션은 noVNC 래퍼(WRAPPER_PAGE·novnc_url)로 처리하면 깨진다 — xpra-wrapped 로 보낸다.
    # (언어 변경 후 '/?sid=&lang' 재진입이 noVNC iframe 으로 가 무한 로딩되던 문제 수정. 2026-06-02)
    if (info.get("engine") or "novnc") == "xpra":
        log.info(f"[{s8(sid)}] xpra 세션 → xpra-wrapped 재진입 lang={lang}")
        return html_response(
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
            "<style>body{background:#fff;margin:0}</style></head><body>"
            f"<script>location.replace('/xpra-wrapped/{sid}?lang={lang}');</script>"
            "</body></html>"
        )

    host = request.headers.get("x-forwarded-host") or request.url.hostname
    app_ready_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".app_ready")

    # ── 빠른 경로: .app_ready 존재 → 즉시 래퍼 페이지 반환 ──
    if os.path.isfile(app_ready_path):
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        _base     = f"http://{host}:{info['port']}"
        novnc_url = f"{_base}/?resize=remote&scaling=local&quality=6&compression=6&logging=warn&reconnect=true&reconnect_delay=2000"
        log.info(f"[{s8(sid)}] 래퍼 페이지(fast) → 포트 {info['port']} lang={lang}")
        try:
            _html = WRAPPER_PAGE.format(novnc_url=novnc_url, sid=sid, init_lang=lang)
            # ready splash(로딩 완료 후 환영 카드) + loading splash 숨김 주입 —
            # xpra 와 동일하게 noVNC 에도 적용 (2026-05-31 버그 수정: 기존엔 xpra 만
            # 적용돼 Basic 모드에서 노출 토글이 안 먹던 문제)
            _inject = _loading_cover_hide_css() + _ready_splash_html(lang)
            if _inject:
                _html = _html.replace("</head>", _inject + "</head>", 1)
            return html_response(_html)
        except Exception as _we:
            # 래퍼 페이지 format() 실패 (escape 누락 등) → uvicorn plain text 500 대신
            # 친화 에러 페이지 표시. 새 세션 시작 / xpra 전환 옵션 제공.
            log.error(f"[{s8(sid)}] WRAPPER_PAGE.format 실패: {_we}", exc_info=True)
            return HTMLResponse(_friendly_error_page(
                title="페이지를 표시할 수 없습니다",
                message="래퍼 페이지 렌더 중 오류가 발생했습니다.<br>새 세션을 시작하거나 관리자에게 문의하세요.",
                hint=f"WRAPPER format error · {str(_we)[:60]}",
                retry_label="새 세션 시작",
                retry_action=f"/?sid=new&lang={lang}",
            ), status_code=500)

    # ── 일반 경로: 컨테이너 상태 확인 ──
    if container_running(info["container_id"]):
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        log.info(f"[{s8(sid)}] 로딩 페이지 lang={lang}")
        return html_response(LOADING_PAGE.format(sid=sid, lang=lang))
    else:
        log.info(f"[{s8(sid)}] 컨테이너 없음 → 새 세션으로 dispatch")
        remove_session(sid)
        dispatch = (
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
            "<style>body{background:#fff;margin:0}</style></head><body>"
            "<script>(function(){{"
            "sessionStorage.removeItem('orange3_sid');"
            f"location.replace('/?sid=new&lang={lang}');"
            "}})();</script></body></html>"
        )
        return html_response(dispatch)


@app.get("/ready")
async def ready(request: Request, sid: str | None = None):
    """LOADING_PAGE JS가 폴링 — 컨테이너가 실제로 응답하는지 확인."""
    if not sid:
        return JSONResponse({"ready": False, "not_found": True})
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ready": False, "not_found": True})
    # Phase 3D-1 (2026-05-23): Xpra 세션은 .app_ready 파일을 만들지 않으므로
    # 컨테이너 생존만 확인. ready=true 면 wrapper JS 의 minimap disconnect
    # 오버레이가 해제됨.
    if info.get("engine") == "xpra":
        if await container_running_async(info["container_id"]):
            return JSONResponse({"ready": True})
        return JSONResponse({"ready": False, "dead": True})
    # 1단계: .app_ready 먼저 확인 (파일 I/O, Docker API 불필요 — 가장 빠름)
    app_ready = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".app_ready")
    if os.path.isfile(app_ready):
        host = request.headers.get("x-forwarded-host") or request.url.hostname
        _base = f"http://{host}:{info['port']}"
        return JSONResponse({
            "ready": True,
            "novnc_url": f"{_base}/?resize=remote&scaling=local&quality=6&compression=6&logging=warn&reconnect=true&reconnect_delay=2000",
        })
    # 2단계: 컨테이너 생존 확인 (캐싱된 Docker API, non-blocking)
    if not await container_running_async(info["container_id"]):
        return JSONResponse({"ready": False, "dead": True})
    return JSONResponse({"ready": False})


@app.get("/ready-sse")
async def ready_sse(request: Request, sid: str | None = None):
    """LOADING_PAGE SSE 스트림 — 폴링 없이 서버 push로 준비 신호 전달."""
    import json as _json

    async def generate():
        if not sid:
            yield f"data: {_json.dumps({'ready': False, 'not_found': True})}\n\n"
            return

        started = time.time()
        MAX_WAIT = 150

        while True:
            if await request.is_disconnected():
                break

            elapsed = time.time() - started
            if elapsed >= MAX_WAIT:
                yield f"data: {_json.dumps({'ready': False, 'timeout': True})}\n\n"
                break

            with _lock:
                info = sessions.get(sid)
            if not info:
                yield f"data: {_json.dumps({'ready': False, 'not_found': True})}\n\n"
                break

            # .app_ready 파일 체크 (파일 I/O — 극히 빠름)
            app_ready = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".app_ready")
            if os.path.isfile(app_ready):
                host = request.headers.get("x-forwarded-host") or request.url.hostname
                _base = f"http://{host}:{info['port']}"
                yield f"data: {_json.dumps({'ready': True, 'novnc_url': f'{_base}/?resize=remote&scaling=local&quality=6&compression=6&logging=warn&reconnect=true&reconnect_delay=2000'})}\n\n"
                break

            # 컨테이너 생존 확인 (캐싱된 Docker API)
            is_running = await container_running_async(info["container_id"])
            if not is_running:
                yield f"data: {_json.dumps({'ready': False, 'dead': True})}\n\n"
                break

            yield f"data: {_json.dumps({'ready': False, 'elapsed': round(elapsed)})}\n\n"
            # 0.3s 폴링 — .app_ready 파일 stat은 마이크로초 단위, 응답 지연 최소화
            await asyncio.sleep(0.3)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/new-session")
async def new_session_api():
    """탭 추가용: 새 세션(Orange3 컨테이너)을 생성하고 sid를 반환."""
    if client is None:
        return JSONResponse({"error": "Docker 연결 오류"}, status_code=503)
    # 예열 풀 우선 사용
    with _warm_lock:
        warm_sid = _warm_pool.pop(0) if _warm_pool else None
    if warm_sid:
        with _lock:
            if warm_sid in sessions:
                sessions[warm_sid]["warm"] = False
                sessions[warm_sid]["last_seen"] = time.time()
        asyncio.create_task(_replenish_pool())
        return JSONResponse({"sid": warm_sid})
    # 풀 없으면 직접 생성
    new_sid = str(uuid.uuid4())
    try:
        port = allocate_port()
    except RuntimeError as e:
        return JSONResponse({"error": str(e)}, status_code=503)
    container_session_dir = os.path.join(CONTAINER_SESSIONS_PATH, new_sid)
    os.makedirs(container_session_dir, exist_ok=True)
    host_session_dir = os.path.join(HOST_SESSIONS_PATH, new_sid)
    widget_vols = build_widget_override_volumes()
    try:
        container = client.containers.run(
            ORANGE3_IMAGE, detach=True,
            ports={"5800/tcp": ("0.0.0.0", port)},
            volumes={
                host_session_dir: {"bind": "/config", "mode": "rw"},
                HOST_DATA_PATH:   {"bind": "/data",   "mode": "ro"},
                **widget_vols,
                **build_upload_ows_volume(),
                **build_shared_thumbs_volume(),
                **build_launcher_volume(),
            },
            labels={"orange3.session": new_sid, "orange3.managed": "true"},
            environment={"QT_STYLE_OVERRIDE": "Fusion", "ORANGE3_SPLASH_LOADING": _splash_loading_env_val()},
            remove=False, mem_limit=CONTAINER_MEM_LIMIT, memswap_limit=CONTAINER_MEM_LIMIT,
            cpu_quota=400000, cpu_period=100000, shm_size="536870912",
        )
    except Exception as e:
        release_port(port)
        return JSONResponse({"error": str(e)}, status_code=500)
    with _lock:
        sessions[new_sid] = {"container_id": container.id, "port": port, "last_seen": time.time()}
    confirm_port(port)
    return JSONResponse({"sid": new_sid})


# ── SSE 통합 이벤트 채널 (Phase 1 / 진단보고서 P1 — 폴링 통합) ──────────────────
# 11개 폴 엔드포인트(/upload-poll·/upload-poll-*·/dataset-poll)를 단일 SSE 채널로 통합.
# 설계 근거: _md_file_/sse_migration_plan.md
# Phase 1 은 기존 폴 엔드포인트 그대로 유지 — 클라이언트가 SSE 로 전환되기 전까지 병행 운영.
MARKER_MAP = {
    ".upload_request":            "upload-request",
    ".upload_request_model":      "upload-request-model",
    ".upload_request_images":     "upload-request-images",
    ".upload_request_corpus":     "upload-request-corpus",
    ".upload_request_documents":  "upload-request-documents",
    ".upload_request_distance":   "upload-request-distance",
    ".upload_request_network":    "upload-request-network",
    ".upload_request_sent_pos":   "upload-request-sent-pos",
    ".upload_request_sent_neg":   "upload-request-sent-neg",
    ".upload_request_stopwords":  "upload-request-stopwords",
    ".upload_request_lexicon":    "upload-request-lexicon",
    ".upload_request_sc_cell_anno": "upload-request-sc-cell-anno",
    ".upload_request_sc_gene_anno": "upload-request-sc-gene-anno",
    ".upload_request_spec_multifile": "upload-request-spec-multifile",
    ".upload_request_spec_tilefile": "upload-request-spec-tilefile",
    ".dataset_request":           "dataset-request",
}
SSE_POLL_INTERVAL_SEC = 0.5       # 서버 측 마커 검사 주기 — 클라이언트 폴 4s 대비 8배 빠른 반응
SSE_HEARTBEAT_SEC     = 25        # 중간 프록시 idle timeout(보통 30~60s) 회피
SSE_MAX_LIFETIME_SEC  = 3600      # 1시간 후 자동 재연결 유도 (메모리 누수·proxy 끊김 방지)


_orange_info_cache: dict | None = None
_orange_info_lock = threading.Lock()


def _get_orange_info() -> dict:
    """Orange3 버전 + 설치된 addon 목록을 컨테이너에서 추출, 모듈 전역 캐시.
    Phase 5 (2026-05-24): wrapper 좌하단 로딩 텍스트가 호출."""
    global _orange_info_cache
    with _orange_info_lock:
        if _orange_info_cache is not None:
            return _orange_info_cache
        try:
            target = None
            for c in client.containers.list():
                tags = (c.image.tags or [])
                if any(t.startswith("orange3-gui") or t.startswith("orange3-xpra")
                       for t in tags):
                    target = c
                    break
            if target is None:
                return {"version": "", "addons": [], "cached": False}
            code = (
                "import importlib.metadata as m\n"
                "try:\n"
                "    import Orange\n"
                "    print('VERSION', Orange.__version__)\n"
                "except Exception:\n"
                "    pass\n"
                "for d in m.distributions():\n"
                "    n = d.metadata.get('Name') or ''\n"
                "    if n.lower().startswith('orange'):\n"
                "        print('PKG', n, d.version)\n"
            )
            r = target.exec_run(["python3", "-c", code], demux=False)
            out = (r.output or b"").decode("utf-8", errors="replace")
            version = ""
            addons = []
            for line in out.splitlines():
                if line.startswith("VERSION "):
                    version = line.split(" ", 1)[1].strip()
                elif line.startswith("PKG "):
                    parts = line.split(" ", 2)
                    if len(parts) >= 3:
                        addons.append({"name": parts[1], "version": parts[2]})
            addons.sort(key=lambda a: (a["name"].lower() != "orange3", a["name"].lower()))
            _orange_info_cache = {"version": version, "addons": addons, "cached": True}
            return _orange_info_cache
        except Exception as e:
            log.warning(f"[orange-info] {e}")
            return {"version": "", "addons": [], "cached": False, "error": str(e)}


@app.get("/api/orange-info")
async def orange_info_route():
    """좌하단 로딩 텍스트가 fetch — Orange 버전 + addon 목록."""
    return JSONResponse(_get_orange_info(), headers=NO_CACHE)


# ─── Google Drive OAuth — OPEN 모달의 "LOGIN TO GOOGLE" 버튼 진입점 ───
# 환경변수:
#   GOOGLE_OAUTH_CLIENT_ID     : Google Cloud Console OAuth 클라이언트 ID
#   GOOGLE_OAUTH_REDIRECT_URI  : 콜백 URL (예: http://localhost:8888/api/gdrive/callback)
# 둘 다 설정된 경우에만 실제 Google 계정 선택 페이지 URL 반환.
# 미설정 시 안내 메시지 반환 → 프론트엔드에서 "곧 제공됩니다" 표시.
_gdrive_tokens: dict[str, dict] = {}   # sid → {access_token, refresh_token, expires_at}

@app.post("/api/gdrive/auth")
@limiter.limit("5/minute")
async def gdrive_auth(request: Request, sid: str | None = None):
    """Google OAuth 2.0 account chooser URL 생성.
    prompt=select_account → 이미 로그인된 사용자도 계정 선택 화면을 보게 함 (이미지 1 참조)."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    redirect_uri = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI", "").strip()
    if not client_id or not redirect_uri:
        # 환경변수 미설정 → 사용자에게는 친화적 메시지, 운영자용 상세 정보는 detail 에.
        log.warning("[gdrive_auth] OAuth 환경변수 미설정 — Google Drive 로그인 비활성")
        return JSONResponse({
            "ok": False,
            "configured": False,
            "error": "Google Drive 연동은 아직 준비 중입니다.",
        })
    from urllib.parse import urlencode as _urlencode
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "https://www.googleapis.com/auth/drive.readonly "
                 "https://www.googleapis.com/auth/drive.file",
        "access_type": "offline",
        "prompt": "select_account",  # 계정 선택 화면 (이미지 1) 강제 표시
        "state": sid,                # 콜백에서 어느 세션인지 식별
        "include_granted_scopes": "true",
    }
    url = f"https://accounts.google.com/o/oauth2/v2/auth?{_urlencode(params)}"
    return JSONResponse({"ok": True, "url": url})


@app.get("/api/gdrive/callback")
async def gdrive_callback(request: Request):
    """Google OAuth 콜백 — code 를 access_token 으로 교환 후 sid 별 저장.
    팝업 창에서 호출됨 → 완료 후 자동 닫기."""
    code = request.query_params.get("code")
    state_sid = request.query_params.get("state")
    error = request.query_params.get("error")
    if error:
        return HTMLResponse(
            f"<html><body style='font-family:sans-serif;padding:40px;'>"
            f"<h3>Google 로그인 취소/오류</h3><p>{error}</p>"
            f"<script>setTimeout(function(){{window.close();}},2000);</script>"
            f"</body></html>"
        )
    if not code or not state_sid:
        return HTMLResponse(
            "<html><body style='font-family:sans-serif;padding:40px;'>"
            "<h3>잘못된 콜백 요청</h3>"
            "<script>setTimeout(function(){window.close();},2000);</script>"
            "</body></html>"
        )
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
    redirect_uri = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI", "").strip()
    if not (client_id and client_secret and redirect_uri):
        return HTMLResponse(
            "<html><body style='font-family:sans-serif;padding:40px;'>"
            "<h3>서버 OAuth 설정 누락</h3>"
            "<p>GOOGLE_OAUTH_CLIENT_SECRET 환경변수가 필요합니다.</p>"
            "</body></html>"
        )
    # access_token 교환 (httpx 사용 — 이미 의존성 포함)
    try:
        import httpx as _httpx
        async with _httpx.AsyncClient(timeout=10.0) as cli:
            r = await cli.post("https://oauth2.googleapis.com/token", data={
                "code": code, "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri, "grant_type": "authorization_code",
            })
            tok = r.json()
        if "access_token" not in tok:
            return HTMLResponse(
                f"<html><body style='font-family:sans-serif;padding:40px;'>"
                f"<h3>토큰 교환 실패</h3><pre>{tok}</pre></body></html>"
            )
        _gdrive_tokens[state_sid] = {
            "access_token": tok["access_token"],
            "refresh_token": tok.get("refresh_token", ""),
            "expires_at": time.time() + int(tok.get("expires_in", 3600)),
        }
    except Exception as e:
        return HTMLResponse(
            f"<html><body style='font-family:sans-serif;padding:40px;'>"
            f"<h3>토큰 교환 오류</h3><pre>{e}</pre></body></html>"
        )
    return HTMLResponse(
        "<html><body style='font-family:sans-serif;padding:40px;text-align:center;'>"
        "<h3>✓ Google 로그인 완료</h3>"
        "<p>이 창을 닫고 원래 화면으로 돌아가세요.</p>"
        "<script>setTimeout(function(){window.close();},1500);"
        "if(window.opener){try{window.opener.postMessage({type:'gdrive-auth-ok'},'*');}catch(_){}}</script>"
        "</body></html>"
    )


@app.get("/api/gdrive/status")
async def gdrive_status(sid: str | None = None):
    """현재 sid 의 Google 로그인 상태 — 프론트엔드에서 토큰 보유 여부 확인."""
    if not sid:
        return JSONResponse({"ok": False, "logged_in": False})
    tok = _gdrive_tokens.get(sid)
    logged_in = bool(tok and tok.get("expires_at", 0) > time.time())
    return JSONResponse({"ok": True, "logged_in": logged_in})


@app.get("/api/events")
async def event_stream(request: Request, sid: str | None = None):
    """통합 SSE 이벤트 채널 — 11개 폴 엔드포인트 통합 대체 (Phase 1: 병행).

    이벤트 종류 (data 는 JSON):
      hello              초기 연결 확인  {sid_short}
      upload-request*    위젯 업로드 요청 마커 출현
      dataset-request    Dataset 카탈로그 요청 마커 출현 ({category})
      reconnect          SSE_MAX_LIFETIME 초과 → 클라이언트가 재연결
      session-gone       세션 만료/삭제 → 클라이언트가 새 세션 시작
      (코멘트 `: ping`)  heartbeat — 클라이언트 onmessage 발화 안 함
    """
    if not sid:
        return JSONResponse({"error": "sid 없음"}, status_code=400)
    import json as _json

    async def gen():
        started = time.time()
        last_heartbeat = started
        sess_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)

        # 세션 존재 확인 후 hello (클라이언트가 채널 활성화 판단)
        with _lock:
            sess = sessions.get(sid)
        if sess is None:
            yield f"event: session-gone\ndata: {_json.dumps({})}\n\n"
            return
        yield f"event: hello\ndata: {_json.dumps({'sid_short': s8(sid)})}\n\n"

        while True:
            # 클라이언트 연결 종료 감지
            if await request.is_disconnected():
                break

            # 수명 한도 — 클라이언트 재연결 유도
            if time.time() - started > SSE_MAX_LIFETIME_SEC:
                yield f"event: reconnect\ndata: {_json.dumps({})}\n\n"
                break

            # 세션 유효성 + last_seen 갱신 (SSE 활성 = keepalive 역할)
            with _lock:
                sess = sessions.get(sid)
                if sess is None:
                    yield f"event: session-gone\ndata: {_json.dumps({})}\n\n"
                    break
                sess["last_seen"] = time.time()

            # 마커 파일 10종 검사 + 발견 시 이벤트 송출
            for marker_name, event_name in MARKER_MAP.items():
                path = os.path.join(sess_dir, marker_name)
                if not os.path.isfile(path):
                    continue
                payload = {}
                if marker_name == ".dataset_request":
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            content = f.read().strip()
                        if content.startswith("cat="):
                            payload["category"] = content[4:].split("\n", 1)[0].strip()
                    except OSError:
                        pass
                try:
                    os.remove(path)
                except OSError:
                    pass
                yield f"event: {event_name}\ndata: {_json.dumps(payload)}\n\n"

            # /pc_download/check 통합은 Phase 4 보류 — 컨테이너 내부 마커라 docker exec 비용 큼

            # Heartbeat (코멘트 라인 — 클라이언트에는 전달 안 됨, keep-alive 만 유지)
            now = time.time()
            if now - last_heartbeat >= SSE_HEARTBEAT_SEC:
                yield ": ping\n\n"
                last_heartbeat = now

            await asyncio.sleep(SSE_POLL_INTERVAL_SEC)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",   # nginx/proxy 응답 버퍼링 차단
            "Connection": "keep-alive",
            # Hotfix (2026-05-21): GZipMiddleware 가 SSE 스트림을 압축 버퍼링해
            # hello 이벤트가 브라우저에 도달하지 못하는 문제 차단.
            # identity = HTTP 표준 "no encoding" → 미들웨어가 압축 건너뜀.
            "Content-Encoding": "identity",
        },
    )


# 공용 HTML 페이지 폴더 (docker-compose.yml 에서 ./html → /app/html 마운트)
HTML_DIR = "/app/html"


@app.get("/datasets-catalog")
async def datasets_catalog():
    """공용 데이터셋 카탈로그 페이지 서빙 (orange3_datasets_compact.html)."""
    catalog_path = os.path.join(HTML_DIR, "orange3_datasets_compact.html")
    if not os.path.isfile(catalog_path):
        return JSONResponse(
            {"error": f"카탈로그 파일 없음: {catalog_path}"}, status_code=404)
    with open(catalog_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/analysis-datasets")
async def analysis_datasets():
    """헤더의 '분석데이터셋' 버튼이 호출하는 카탈로그 페이지.
    카드 형태 + 카테고리 탭 + 모달/standalone 양쪽 모드 지원."""
    page_path = os.path.join(HTML_DIR, "orange3_analysis_datasets.html")
    if not os.path.isfile(page_path):
        return JSONResponse(
            {"error": f"카탈로그 파일 없음: {page_path}"}, status_code=404)
    with open(page_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/dataset-file")
async def dataset_file(folder: str, file: str):
    """데이터셋 파일 다운로드 — /data/{folder}/{file} 반환.
    Phase 5 (2026-05-24): 분석 데이터셋 상세 모달의 "다운로드" 버튼이 호출.
    경로 traversal 방지: folder·file 각각 단일 세그먼트 + 영숫자/_-./ 만 허용."""
    import re as _re
    name_re = _re.compile(r"^[A-Za-z0-9._-]+$")
    if not (name_re.match(folder) and name_re.match(file)):
        return JSONResponse({"error": "invalid name"}, status_code=400)
    path = os.path.join("/data", folder, file)
    if not os.path.isfile(path):
        return JSONResponse({"error": "not found", "path": path},
                            status_code=404)
    with open(path, "rb") as f:
        data = f.read()
    # latin-1 안전: filename 은 ASCII 만 (영숫자/_-./)
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file}"',
            "Cache-Control": "public, max-age=3600",
        },
    )


@app.get("/datasets-classification")
async def datasets_classification():
    """분류(Classification) 전용 모달 페이지 서빙."""
    modal_path = os.path.join(HTML_DIR, "orange3_datasets_classification_modal.html")
    if not os.path.isfile(modal_path):
        return JSONResponse(
            {"error": f"모달 파일 없음: {modal_path}"}, status_code=404)
    with open(modal_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.post("/upload-spec-multifile")
@limiter.limit("10/minute")
async def upload_spec_multifile(
    request: Request,
    sid: str | None = None,
    files: list[UploadFile] = File(...),  # type: ignore[name-defined]
):
    """Spectroscopy · Multifile 위젯 — 다중 파일 일괄 업로드 (2026-05-28).
    /tmp/spec_multifile_<timestamp>/<filename> 에 저장 후 /config/.upload_path_spec_multifile
    에 줄바꿈 구분 파일 경로 목록 기록."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "세션 없음"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "Docker 연결 없음"}, status_code=503)
    if not files:
        return JSONResponse({"ok": False, "error": "파일 없음"}, status_code=400)
    if len(files) > MAX_FILES_PER_UPLOAD:
        return JSONResponse({"ok": False, "error": f"파일 개수 초과 (최대 {MAX_FILES_PER_UPLOAD}개)"}, status_code=413)
    import time as _time
    root_dir = f"/tmp/spec_multifile_{int(_time.time())}"
    total_size = 0
    saved_paths = []
    try:
        container = client.containers.get(str(info["container_id"]))
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            for f in files:
                safe_name = os.path.basename(f.filename or "file")
                if not safe_name or ".." in safe_name:
                    continue
                content = await f.read()
                if not content:
                    continue
                total_size += len(content)
                if total_size > MAX_UPLOAD_BYTES * 50:
                    return JSONResponse({"ok": False, "error": "총 크기 초과"}, status_code=413)
                tinfo = tarfile.TarInfo(name=safe_name)
                tinfo.size = len(content)
                tar.addfile(tinfo, io.BytesIO(content))
                saved_paths.append(f"{root_dir}/{safe_name}")
        tar_buf.seek(0)
        container.exec_run(["mkdir", "-p", root_dir])
        container.put_archive(root_dir, tar_buf)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"업로드 실패: {e}"}, status_code=500)

    signal_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".upload_path_spec_multifile")
    try:
        with open(signal_path, "w") as f:
            f.write("\n".join(saved_paths))
    except OSError as e:
        return JSONResponse({"ok": False, "error": f"신호 파일 오류: {e}"}, status_code=500)
    # 트리거 신호 파일 정리
    try:
        os.remove(os.path.join(CONTAINER_SESSIONS_PATH, sid, ".upload_request_spec_multifile"))
    except OSError:
        pass
    log.info(f"[{s8(sid)}] Spectroscopy Multifile 업로드 {len(saved_paths)}개 → {root_dir} ({total_size} bytes)")
    return JSONResponse({"ok": True, "count": len(saved_paths), "dir": root_dir})


@app.post("/upload-documents")
@limiter.limit("10/minute")
async def upload_documents(
    request: Request,
    sid: str | None = None,
    files: list[UploadFile] = File(...),  # type: ignore[name-defined]
    relpaths: list[str] = Form(...),       # type: ignore[name-defined]
):
    """Import Documents 위젯 — 폴더 일괄 업로드 (webkitdirectory).
    files[i] 와 relpaths[i] 가 1:1 매핑. 컨테이너의 /tmp/imported_documents_<timestamp>/<relpath>
    에 폴더 구조 보존하여 저장 후 /config/.upload_path_documents 에 루트 경로 기록."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "세션 없음"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "Docker 연결 없음"}, status_code=503)
    if not files or len(files) != len(relpaths):
        return JSONResponse({"ok": False, "error": "files/relpaths 개수 불일치"}, status_code=400)
    if len(files) > MAX_FILES_PER_UPLOAD:
        return JSONResponse({"ok": False, "error": f"파일 개수 초과 (최대 {MAX_FILES_PER_UPLOAD}개)"}, status_code=413)
    import time as _time
    root_dir = f"/tmp/imported_documents_{int(_time.time())}"
    total_size = 0
    try:
        container = client.containers.get(str(info["container_id"]))
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            for f, relpath in zip(files, relpaths):
                safe_relpath = relpath.replace("\\", "/").lstrip("/")
                if ".." in safe_relpath.split("/"):
                    continue
                content = await f.read()
                if not content:
                    continue
                total_size += len(content)
                if total_size > MAX_UPLOAD_BYTES * 50:
                    return JSONResponse({"ok": False, "error": "총 크기 초과"}, status_code=413)
                tinfo = tarfile.TarInfo(name=safe_relpath)
                tinfo.size = len(content)
                tar.addfile(tinfo, io.BytesIO(content))
        tar_buf.seek(0)
        container.exec_run(["mkdir", "-p", root_dir])
        container.put_archive(root_dir, tar_buf)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"업로드 실패: {e}"}, status_code=500)

    signal_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".upload_path_documents")
    try:
        with open(signal_path, "w") as f:
            f.write(root_dir)
    except OSError as e:
        return JSONResponse({"ok": False, "error": f"신호 파일 오류: {e}"}, status_code=500)

    log.info(f"[{s8(sid)}] 문서 폴더 업로드 {len(files)}개 → {root_dir} ({total_size} bytes)")
    return JSONResponse({"ok": True, "count": len(files), "dir": root_dir})


@app.post("/upload-images")
@limiter.limit("10/minute")
async def upload_images(
    request: Request,
    sid: str | None = None,
    files: list[UploadFile] = File(...),  # type: ignore[name-defined]
    relpaths: list[str] = Form(...),       # type: ignore[name-defined]
):
    """Import Images 위젯 — 폴더 일괄 업로드 (webkitdirectory).
    files[i] 와 relpaths[i] 가 1:1 매핑. 컨테이너의 /tmp/imported_images_<timestamp>/<relpath>
    에 폴더 구조 보존하여 저장 후 /config/.upload_path_images 에 루트 경로 기록."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "세션 없음"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "Docker 연결 없음"}, status_code=503)
    if not files or len(files) != len(relpaths):
        return JSONResponse({"ok": False, "error": "files/relpaths 개수 불일치"}, status_code=400)
    if len(files) > MAX_FILES_PER_UPLOAD:
        return JSONResponse({"ok": False, "error": f"파일 개수 초과 (최대 {MAX_FILES_PER_UPLOAD}개)"}, status_code=413)
    import time as _time
    root_dir = f"/tmp/imported_images_{int(_time.time())}"
    total_size = 0
    try:
        container = client.containers.get(str(info["container_id"]))
        # 단일 tar 묶음으로 효율적 업로드
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            for f, relpath in zip(files, relpaths):
                # 보안: 경로 탈출(.., 절대경로) 차단
                safe_relpath = relpath.replace("\\", "/").lstrip("/")
                if ".." in safe_relpath.split("/"):
                    continue
                content = await f.read()
                if not content:
                    continue
                total_size += len(content)
                if total_size > MAX_UPLOAD_BYTES * 50:  # 폴더 업로드 한도 = 50배
                    return JSONResponse({"ok": False, "error": "총 크기 초과"}, status_code=413)
                tinfo = tarfile.TarInfo(name=safe_relpath)
                tinfo.size = len(content)
                tar.addfile(tinfo, io.BytesIO(content))
        tar_buf.seek(0)
        # 컨테이너 내 root_dir 생성 후 풀기
        container.exec_run(["mkdir", "-p", root_dir])
        container.put_archive(root_dir, tar_buf)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"업로드 실패: {e}"}, status_code=500)

    # 신호 파일 작성 — 위젯이 폴링해 setCurrentPath 호출
    signal_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".upload_path_images")
    try:
        with open(signal_path, "w") as f:
            f.write(root_dir)
    except OSError as e:
        return JSONResponse({"ok": False, "error": f"신호 파일 오류: {e}"}, status_code=500)

    log.info(f"[{s8(sid)}] 이미지 폴더 업로드 {len(files)}개 → {root_dir} ({total_size} bytes)")
    return JSONResponse({"ok": True, "count": len(files), "dir": root_dir})


@app.post("/dataset-select")
async def dataset_select(sid: str | None = None, path: str | None = None,
                          kind: str | None = None):
    """모달에서 선택된 데이터셋 경로를 컨테이너의 신호 파일에 기록.
    kind 미지정/'data' → /config/.upload_path        (File 위젯이 소비)
    kind='corpus'      → /config/.upload_path_corpus (Corpus 위젯이 소비)"""
    if not sid or not path:
        return JSONResponse({"error": "sid 와 path 필수"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"error": "세션 없음"}, status_code=401)
    # 보안: /data/ 경로만 허용 (디렉터리 탈출 방지)
    if not path.startswith("/data/") or ".." in path:
        return JSONResponse({"error": "허용되지 않은 경로"}, status_code=400)
    # kind 별 신호 파일 분기 (Corpus 위젯은 별도 신호 사용)
    signal_name = ".upload_path_corpus" if kind == "corpus" else ".upload_path"
    target = os.path.join(CONTAINER_SESSIONS_PATH, sid, signal_name)
    try:
        with open(target, "w", encoding="utf-8") as f:
            f.write(path)
    except OSError as e:
        return JSONResponse({"error": f"쓰기 실패: {e}"}, status_code=500)
    return JSONResponse({"ok": True, "path": path, "kind": kind or "data"})


@app.post("/upload")
@limiter.limit("10/minute")
async def upload_file(request: Request, sid: str | None = None,
                      file: UploadFile = File(...), kind: str = "data"):
    """파일 업로드. kind 파라미터로 결과 신호 파일을 분리:
       kind="data"  (기본) → /config/.upload_path        (File 위젯 소비)
       kind="model"          → /config/.upload_path_model (Load Model 위젯 소비)
    """
    if not sid:
        return JSONResponse({"error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"error": "세션 없음"}, status_code=401)

    # 파일을 메모리에 읽기
    content = b""
    try:
        while True:
            chunk: bytes = await file.read(1024 * 1024)
            if not chunk:
                break
            content += chunk
            if len(content) > MAX_UPLOAD_BYTES:
                return JSONResponse({"error": "파일 크기 초과"}, status_code=413)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    safe_name = os.path.basename(file.filename or "file") or "file"

    # Docker API로 orange3-gui 컨테이너 /tmp/ 에 직접 복사 (호스트 디스크 저장 없음)
    if client is None:
        return JSONResponse({"error": "Docker 연결 없음"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            tinfo = tarfile.TarInfo(name=safe_name)
            tinfo.size = len(content)
            tar.addfile(tinfo, io.BytesIO(content))
        tar_buf.seek(0)
        container.put_archive("/tmp/", tar_buf)
    except Exception as e:
        return JSONResponse({"error": f"컨테이너 복사 실패: {e}"}, status_code=500)

    # 로드 경로 신호 파일 기록 → orange3-gui 위젯이 폴링해 소비
    #   kind="data"      → .upload_path            (File 위젯)
    #   kind="model"     → .upload_path_model      (Load Model 위젯)
    #   kind="corpus"    → .upload_path_corpus     (Corpus 위젯)
    #   kind="distance"  → .upload_path_distance   (Distance File 위젯)
    #   kind="network"   → .upload_path_network    (Network File 위젯)
    #   kind="sent_pos"  → .upload_path_sent_pos   (Sentiment Custom Pos)
    #   kind="sent_neg"  → .upload_path_sent_neg   (Sentiment Custom Neg)
    if kind == "model":
        signal_name = ".upload_path_model"
        request_name = ".upload_request_model"
    elif kind == "corpus":
        signal_name = ".upload_path_corpus"
        request_name = ".upload_request_corpus"
    elif kind == "distance":
        signal_name = ".upload_path_distance"
        request_name = ".upload_request_distance"
    elif kind == "network":
        signal_name = ".upload_path_network"
        request_name = ".upload_request_network"
    elif kind == "sent_pos":
        signal_name = ".upload_path_sent_pos"
        request_name = ".upload_request_sent_pos"
    elif kind == "sent_neg":
        signal_name = ".upload_path_sent_neg"
        request_name = ".upload_request_sent_neg"
    elif kind == "stopwords":
        signal_name = ".upload_path_stopwords"
        request_name = ".upload_request_stopwords"
    elif kind == "lexicon":
        signal_name = ".upload_path_lexicon"
        request_name = ".upload_request_lexicon"
    elif kind == "sc_cell_anno":
        signal_name = ".upload_path_sc_cell_anno"
        request_name = ".upload_request_sc_cell_anno"
    elif kind == "sc_gene_anno":
        signal_name = ".upload_path_sc_gene_anno"
        request_name = ".upload_request_sc_gene_anno"
    elif kind == "spec_tilefile":
        signal_name = ".upload_path_spec_tilefile"
        request_name = ".upload_request_spec_tilefile"
    else:
        signal_name = ".upload_path"
        request_name = ".upload_request"
    signal_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, signal_name)
    try:
        with open(signal_path, "w") as f:
            f.write(f"/tmp/{safe_name}")
    except OSError as e:
        return JSONResponse({"error": f"신호 파일 오류: {e}"}, status_code=500)

    # 브라우저 트리거 신호 파일 삭제
    try:
        os.remove(os.path.join(CONTAINER_SESSIONS_PATH, sid, request_name))
    except OSError:
        pass

    log.info(f"[{s8(sid)}] 메모리→컨테이너: {safe_name} ({len(content)} bytes)")
    return JSONResponse({"filename": safe_name})


@app.post("/open-workflow")
@limiter.limit("30/minute")
async def open_workflow(request: Request, sid: str | None = None, file: UploadFile = File(...)):
    """.ows 파일 → 컨테이너 /tmp/ 복사 → 신호 파일 → launcher 가 open_scheme_file() 호출"""
    if not sid:
        return JSONResponse({"error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"error": "세션 없음"}, status_code=401)

    fname = os.path.basename(file.filename or "workflow.ows")
    if not fname.lower().endswith(".ows"):
        return JSONResponse({"error": ".ows 파일만 허용"}, status_code=400)

    content: bytes = await file.read()  # type: ignore[assignment]
    if len(content) > 50 * 1024 * 1024:
        return JSONResponse({"error": "파일 크기 초과 (50 MB)"}, status_code=413)
    if client is None:
        return JSONResponse({"error": "Docker 연결 없음"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        # 컨테이너 /tmp/ 에 파일 복사
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            ti = tarfile.TarInfo(name=fname)
            ti.size = len(content)
            tar.addfile(ti, io.BytesIO(content))
        buf.seek(0)
        container.put_archive("/tmp/", buf)
        # docker exec 으로 컨테이너 내부에 직접 신호 파일 기록 (볼륨 마운트 방향 문제 우회)
        result = container.exec_run(
            ["sh", "-c", f"printf '%s' '/tmp/{fname}' > /config/.open_workflow"],
        )
        if result.exit_code != 0:
            log.warning(f"[{s8(sid)}] 신호 파일 기록 실패: {result.output}")
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        log.info(f"[{s8(sid)}] open-workflow: {fname}")
        return JSONResponse({"ok": True, "filename": fname})
    except Exception as e:
        log.warning(f"[{s8(sid)}] open-workflow 오류: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/screenshot")
async def screenshot_route(sid: str | None = None):
    """scrot으로 컨테이너 X11 화면 캡처 → PNG 반환 (미니맵용).
    --thumb 15: 1920×1080 → 288×162 (CSS 표시 크기 280×158 과 거의 일치, ~93% 페이로드 절감)."""
    if not sid:
        return Response(status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return Response(status_code=404)
    if client is None:
        return Response(status_code=503)
    if not container_running(str(info["container_id"])):
        return Response(status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        # Phase 3D-1 (2026-05-23): Xpra 세션은 X11 :100 사용 — info.display 분기.
        display = info.get("display", ":0")
        r = container.exec_run(
            ["bash", "-c",
             f"DISPLAY={display} scrot /tmp/_mm.png -o --thumb 15 && cat /tmp/_mm-thumb.png"],
        )
        if r.exit_code == 0 and r.output:
            return Response(
                content=r.output,
                media_type="image/png",
                headers={"Cache-Control": "no-store"},
            )
        return Response(status_code=500)
    except Exception as e:
        log.warning(f"screenshot 오류: {e}")
        return Response(status_code=500)


@app.get("/save-workflow")
@limiter.limit("30/minute")
async def save_workflow_route(request: Request, sid: str | None = None):
    """launcher 에 저장 신호 → /tmp/ 파일 → 브라우저 다운로드"""
    if not sid:
        return JSONResponse({"error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"error": "세션 없음"}, status_code=401)
    if client is None:
        return JSONResponse({"error": "Docker 연결 없음"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        # 이전 done 파일 제거 후 저장 신호 전달
        container.exec_run(["sh", "-c", "rm -f /config/.save_done && printf '1' > /config/.save_workflow"])
        # launcher 가 저장 완료할 때까지 폴링 (최대 10 초)
        done_content = None
        for _ in range(50):
            await asyncio.sleep(0.2)
            r = container.exec_run(["cat", "/config/.save_done"])
            if r.exit_code == 0:
                done_content = r.output.decode().strip()
                break
        if done_content is None:
            return JSONResponse({"error": "저장 시간 초과"}, status_code=504)
        if done_content.startswith("ERROR:"):
            return JSONResponse({"error": done_content[6:]}, status_code=500)
        parts = done_content.split("|", 1)
        save_path = parts[0]
        title = parts[1] if len(parts) > 1 else "workflow"
        # 컨테이너에서 파일 추출
        raw, _ = container.get_archive(save_path)
        buf = io.BytesIO()
        for chunk in raw:
            buf.write(chunk)
        buf.seek(0)
        with tarfile.open(fileobj=buf) as tar:
            member = tar.getmembers()[0]
            file_content = tar.extractfile(member).read()  # type: ignore[union-attr]
        safe_title = re.sub(r'[^\w\-_. ]', '_', title).strip() or "workflow"
        fname = f"{safe_title}.ows"
        # ASCII fallback — 헤더는 latin-1만 허용하므로 한국어 등 non-ASCII 글자는 _ 로 대체
        ascii_fname = re.sub(r'[^\x20-\x7E]', '_', fname).strip(' _')
        if not ascii_fname or ascii_fname == ".ows":
            ascii_fname = "workflow.ows"
        # RFC 5987: filename* 으로 UTF-8 인코딩된 진짜 이름 함께 전달 (브라우저가 우선 사용)
        from urllib.parse import quote as _q
        cd = f"attachment; filename=\"{ascii_fname}\"; filename*=UTF-8''{_q(fname)}"
        log.info(f"[{s8(sid)}] save-workflow: {fname}")
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        return Response(
            content=file_content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": cd},
        )
    except Exception as e:
        log.warning(f"[{s8(sid)}] save-workflow 오류: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# xdotool 허용 키 화이트리스트 (injection 방지)
_SENDKEY_RE = re.compile(
    r'^(ctrl\+)?(shift\+)?(alt\+)?'
    r'([a-z]|[0-9]|F[0-9]{1,2}|equal|minus|plus|space|'
    r'Return|Escape|Tab|BackSpace|Delete|Insert|Home|End|'
    r'Prior|Next|Up|Down|Left|Right)$'
)

# 카테고리 아이콘 캐시 (런타임에 GUI 컨테이너에서 동적 추출, 메모리 보관)
_CATEGORY_ICON_PATHS = {
    "data":           "/usr/local/lib/python3.10/dist-packages/Orange/widgets/data/icons/Category-Data.svg",
    "visualize":      "/usr/local/lib/python3.10/dist-packages/Orange/widgets/visualize/icons/Category-Visualize.svg",
    "model":          "/usr/local/lib/python3.10/dist-packages/Orange/widgets/model/icons/Category-Model.svg",
    "evaluate":       "/usr/local/lib/python3.10/dist-packages/Orange/widgets/evaluate/icons/Category-Evaluate.svg",
    "unsupervised":   "/usr/local/lib/python3.10/dist-packages/Orange/widgets/unsupervised/icons/Category-Unsupervised.svg",
    "text":           "/usr/local/lib/python3.10/dist-packages/orangecontrib/text/widgets/icons/category.svg",
    "imageanalytics": "/usr/local/lib/python3.10/dist-packages/orangecontrib/imageanalytics/widgets/icons/Category-ImageAnalytics.svg",
    "network":        "/usr/local/lib/python3.10/dist-packages/orangecontrib/network/widgets/icons/Category-Network.svg",
    "geo":            "/usr/local/lib/python3.10/dist-packages/orangecontrib/geo/widgets/icons/category.svg",
    # Time Series는 패키지 __init__.py 에서 ICON = "icons/LineChart.svg" 로 명시
    "timeseries":     "/usr/local/lib/python3.10/dist-packages/orangecontrib/timeseries/widgets/icons/LineChart.svg",
    # Transform 카테고리는 Orange3 자체 SVG 없음 → 위젯 아이콘 Transform.svg 재사용 (원형 화살표)
    "transform":      "/usr/local/lib/python3.10/dist-packages/Orange/widgets/data/icons/Transform.svg",
}
_category_icon_cache: dict = {}  # {cat_name: bytes}


@app.get("/logo")
async def logo():
    """사이드바 메뉴 버튼용 로고 PNG (docker-compose에서 컨테이너에 마운트)."""
    path = "/app/orange_logo.png"
    if not os.path.isfile(path):
        return Response(status_code=404)
    with open(path, "rb") as f:
        data = f.read()
    return Response(
        content=data,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/splash-image")
async def splash_image():
    """vnc-cover 중앙 splash 이미지 — Orange 마스코트 + 위젯 풍선.
    파일 위치: html/orange-splash.png (우선), 없으면 orange-splash-02.png
    fallback. 파일 모두 없으면 404 → 프론트엔드가 자동 숨김(img onerror).
    Phase 5 (2026-05-24)."""
    candidates = [
        ("/app/html/orange-splash.png", "image/png"),
        ("/app/html/orange-splash-02.png", "image/png"),
        ("/app/html/orange-splash-01.png", "image/png"),
        ("/app/html/orange-splash-03.png", "image/png"),
    ]
    for path, mime in candidates:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()
            return Response(
                content=data,
                media_type=mime,
                headers={"Cache-Control": "public, max-age=3600"},
            )
    return Response(status_code=404)


@app.get("/footer-logo")
async def footer_logo():
    """캔버스 왼쪽 하단 footer 로고. 파일 없으면 404 → 프론트엔드가 자동 숨김.
       지원 포맷: PNG, JPG, SVG. 우선순위: png > svg > jpg.
       파일 위치: html/footer_logo.{png,svg,jpg} (이미 docker-compose 로 마운트된 폴더)"""
    candidates = [
        ("/app/html/footer_logo.png", "image/png"),
        ("/app/html/footer_logo.svg", "image/svg+xml"),
        ("/app/html/footer_logo.jpg", "image/jpeg"),
    ]
    for path, mime in candidates:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()
            return Response(
                content=data,
                media_type=mime,
                headers={"Cache-Control": "public, max-age=3600"},
            )
    return Response(status_code=404)


@app.get("/splash-mascot")
async def splash_mascot():
    """첫 로딩 시 1회 표시되는 마스코트 이미지 (2026-05-25)."""
    candidates = [
        ("/app/html/splash-mascot.png", "image/png"),
        ("/app/html/splash-mascot.svg", "image/svg+xml"),
    ]
    for path, mime in candidates:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()
            return Response(
                content=data,
                media_type=mime,
                headers={"Cache-Control": "public, max-age=3600"},
            )
    return Response(status_code=404)


_category_icon_locks: dict = {}  # {cat_name: asyncio.Lock} — 동시 요청 deduplication


@app.get("/category-icon/{cat}")
async def category_icon(cat: str):
    """카테고리 SVG 아이콘을 GUI 컨테이너에서 동적으로 추출 (메모리 캐시).

    소스 코드에 SVG 내용을 직접 embed하지 않고 런타임에 워밍 컨테이너 중 하나에서 cat 명령으로
    파일을 읽어 캐싱. 다음 요청부터는 캐시에서 즉시 반환.

    Lock per cat — 동일 카테고리에 대한 동시 요청 시 한 번만 exec_run 하고 나머지는 대기.
    (이전 버그: 모든 동시 요청이 각자 exec_run → 컨테이너 부하 + 일부 요청 timeout.)
    """
    if cat not in _CATEGORY_ICON_PATHS:
        return Response(status_code=404)
    if cat in _category_icon_cache:
        return Response(
            content=_category_icon_cache[cat],
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=3600"},
        )
    # 동시 요청 deduplication — 같은 cat 의 진행 중인 요청이 있으면 그 결과 대기
    lock = _category_icon_locks.setdefault(cat, asyncio.Lock())
    async with lock:
        # 락 획득 후 캐시 재확인 (다른 코루틴이 이미 채웠을 수 있음)
        if cat in _category_icon_cache:
            return Response(
                content=_category_icon_cache[cat],
                media_type="image/svg+xml",
                headers={"Cache-Control": "public, max-age=3600"},
            )
        if client is None:
            return Response(status_code=503)
        try:
            gui_containers = client.containers.list(filters={"label": "orange3.managed=true"})
            if not gui_containers:
                return Response(status_code=503)
            cont = gui_containers[0]
            result = cont.exec_run(["cat", _CATEGORY_ICON_PATHS[cat]])
            if result.exit_code != 0:
                return Response(status_code=404)
            _category_icon_cache[cat] = result.output
            return Response(
                content=result.output,
                media_type="image/svg+xml",
                headers={"Cache-Control": "public, max-age=3600"},
            )
        except Exception as e:
            log.warning(f"category-icon {cat} 추출 실패: {e}")
            return Response(status_code=500)


# ── widget-catalog 캐시 (2026-05-31, 진단보고서 #3) ──────────────────────────
# launcher 왕복(컨테이너 신호→Orange 레지스트리 생성→파일 폴링)은 ~1.2s TTFB.
# raw 카탈로그는 언어별로 동일(같은 레지스트리)하므로 언어 키로 캐싱해 왕복을 제거한다.
# admin 메뉴/위젯 필터는 캐시된 raw 에 매 요청 live 로 적용(설정 변경 즉시 반영).
# addon 설치 등 레지스트리 변경 시에만 /api/admin/widgets/refresh 에서 무효화.
_wcat_raw_cache: dict = {}
_wcat_cache_lock = threading.Lock()
_WCAT_DISK_PREFIX = ".wcat_cache_"   # CONTAINER_SESSIONS_PATH 하위 언어별 영속 파일


def _wcat_disk_path(lang: str) -> str:
    safe = "".join(ch for ch in (lang or "") if ch.isalnum() or ch in "-_")[:16] or "x"
    return os.path.join(CONTAINER_SESSIONS_PATH, _WCAT_DISK_PREFIX + safe + ".json")


def _wcat_save_disk(lang: str, data: dict) -> None:
    """raw 카탈로그를 디스크에 영속화 — 재시작에도 캐시 유지(언어별 1회만 생성)."""
    try:
        import json as _j
        p = _wcat_disk_path(lang); tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _j.dump(data, f, ensure_ascii=False)
        os.replace(tmp, p)
    except Exception as _e:
        log.warning(f"[widget-catalog] 캐시 디스크 저장 실패({lang}): {_e}")


def _wcat_load_disk() -> int:
    """시작 시 디스크의 언어별 카탈로그 캐시를 메모리로 로드. 로드 개수 반환."""
    import glob as _g, json as _j
    n = 0
    try:
        for p in _g.glob(os.path.join(CONTAINER_SESSIONS_PATH, _WCAT_DISK_PREFIX + "*.json")):
            try:
                lang = os.path.basename(p)[len(_WCAT_DISK_PREFIX):-5]
                with open(p, "r", encoding="utf-8") as f:
                    d = _j.load(f)
                with _wcat_cache_lock:
                    _wcat_raw_cache[lang] = d
                n += 1
            except Exception:
                pass
    except Exception:
        pass
    return n


def _wcat_clear_all() -> None:
    """메모리 + 디스크 캐시 전체 무효화 (addon 변경/레지스트리 갱신 시)."""
    import glob as _g
    with _wcat_cache_lock:
        _wcat_raw_cache.clear()
    try:
        for p in _g.glob(os.path.join(CONTAINER_SESSIONS_PATH, _WCAT_DISK_PREFIX + "*.json")):
            try:
                os.remove(p)
            except OSError:
                pass
    except Exception:
        pass


def _session_lang_code(sid: str) -> str:
    """세션 Orange.ini 의 현재 언어 코드(ko/en/sl). 마운트 파일 직접 읽기, 없으면 'en'."""
    _m = {"Korean": "ko", "English": "en", "Slovenian": "sl", "Slovenčina": "sl"}
    p = os.path.join(CONTAINER_SESSIONS_PATH, sid, "xdg", "config", "biolab.si", "Orange.ini")
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("language="):
                    return _m.get(line.split("=", 1)[1].strip(), "en")
    except OSError:
        pass
    return "en"


def _apply_catalog_admin_filter(data: dict) -> None:
    """raw 위젯 카탈로그(data)에 admin 메뉴/위젯 visibility + phase 정렬을 in-place 적용.
       widget_catalog 의 캐시/신규 경로 공용 (2026-05-31 추출)."""
    try:
        _admin_set = _admin_load_settings()
        _menu = _admin_set.get("menu", {})
        _widgets_vis = _admin_set.get("widgets") or {}
        _qname_to_en_name: dict = {}
        try:
            _en_cat = _load_admin_widget_catalog()
            if _en_cat:
                for _ec in (_en_cat.get("categories") or []):
                    for _ew in (_ec.get("widgets") or []):
                        _eq = _ew.get("qualified_name", "")
                        _en = _ew.get("name", "")
                        if _eq and _en:
                            _qname_to_en_name[_eq] = _en
        except Exception as _qe:
            log.warning(f"[widget-catalog] en-name map 빌드 실패: {_qe}")
        cats_in = data.get("categories") or []
        _by_canon: dict = {}
        _no_canon: list = []
        for c in cats_in:
            cn = c.get("name", "")
            canon = _ADMIN_CAT_ALIASES.get(cn)
            if canon is None:
                _no_canon.append(c)
                continue
            wc = len(c.get("widgets") or [])
            prev = _by_canon.get(canon)
            if prev is None or wc > len(prev.get("widgets") or []):
                _by_canon[canon] = c
        cats_in = list(_by_canon.values()) + _no_canon
        cats_out = []
        for c in cats_in:
            cname = c.get("name", "")
            canon = _ADMIN_CAT_ALIASES.get(cname, cname)
            if not _menu.get(canon, True):
                continue
            if not (c.get("widgets") or []):
                continue
            wmap = _widgets_vis.get(canon) or {}
            if wmap:
                new_widgets = []
                for w in (c.get("widgets") or []):
                    wname = w.get("name", "")
                    qname = w.get("qualified_name", "")
                    lookup_name = _qname_to_en_name.get(qname, wname)
                    if wmap.get(lookup_name, True):
                        new_widgets.append(w)
                    else:
                        new_widgets.append({**w, "disabled": True})
                c = {**c, "widgets": new_widgets}
            cats_out.append(c)
        _phase_idx: dict = {}
        for _ph in _ADMIN_CATEGORY_PHASES:
            for _i, _nm in enumerate(_ph["categories"]):
                _phase_idx[_nm] = (_ph["phase"], _i)
        def _cat_key(c):
            cn = c.get("name", "")
            canon = _ADMIN_CAT_ALIASES.get(cn, cn)
            if canon in _phase_idx:
                ph, idx = _phase_idx[canon]
                c["phase"] = ph
                return (0, ph, idx)
            c["phase"] = 0
            return (1, 0, cn.lower())
        cats_out.sort(key=_cat_key)
        data["categories"] = cats_out
    except Exception as _fe:
        log.warning(f"[widget-catalog] admin filter 실패: {_fe}")


@app.get("/widget-catalog")
@limiter.limit("20/minute")
async def widget_catalog(request: Request, sid: str | None = None):
    """단계 1: Orange3 WidgetRegistry 메타데이터 JSON 반환.

    흐름:
      1. 이전 응답 파일(.widget_catalog.json) stale 제거
      2. 신호 파일(.widget_catalog_query) 작성 → launcher watcher가 감지
      3. 응답 파일 폴링 (100ms 간격, 최대 8s)
      4. JSON 로드하여 응답

    응답 스키마: { ok, language, categories: [{name, color, priority, widgets: [...]}, ...] }
    """
    import json as _json
    if not sid:
        return JSONResponse({"ok": False, "error": "no sid"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    import copy as _copy
    lang = _session_lang_code(sid)
    # 캐시 적중 → launcher 왕복(~1.2s) 생략, raw 복사본에 admin 필터만 live 적용 (#3).
    # 주의: 카탈로그 위젯명·카테고리명은 '언어 의존'이다. 과거엔 '언어 비의존' 전제로
    # 요청 언어 캐시가 없으면 '다른 언어 캐시라도' 폴백 반환했으나, 그 탓에 ① 요청 언어(ko)
    # 캐시가 영영 채워지지 않고(launcher 생성 경로로 못 감) ② 영어 사이드바가 고착됐다.
    # 폴백을 제거 → 캐시 미스 시 아래 launcher 생성으로 '정확한 언어'를 만들어 캐싱한다
    # (첫 요청만 ~수초, 이후 디스크 영속 캐시로 즉시).
    with _wcat_cache_lock:
        _cached = _wcat_raw_cache.get(lang)
    if _cached is not None:
        with _lock:
            if sid in sessions:
                sessions[sid]["last_seen"] = time.time()
        data = _copy.deepcopy(_cached)
        _apply_catalog_admin_filter(data)
        return JSONResponse({"ok": True, **data})
    sess_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)
    query_path    = os.path.join(sess_dir, ".widget_catalog_query")
    response_path = os.path.join(sess_dir, ".widget_catalog.json")
    # stale 응답 파일 정리
    try:
        if os.path.isfile(response_path):
            os.remove(response_path)
    except OSError:
        pass
    # 신호 작성
    try:
        with open(query_path, "w") as f:
            f.write("1")
    except OSError as e:
        return JSONResponse({"ok": False, "error": f"signal write failed: {e}"}, status_code=500)
    # 응답 대기 (최대 30s — thumbnail 생성 등 부팅 직후 main thread busy 상황 대비)
    deadline = time.time() + 75.0   # 언어 변경 후 새 언어 레지스트리 재생성이 30s+ 걸릴 수 있어 상향
    _last_parse_err = None
    while time.time() < deadline:
        if os.path.isfile(response_path):
            # partial JSON race 보호 (2026-05-26): launcher 의 비원자 write 가
            # 끝나기 전 읽으면 ValueError → 100ms 대기 후 재시도. atomic rename 으로
            # 변경된 launcher 와 함께 거의 발생 안 함.
            try:
                with open(response_path, "r", encoding="utf-8") as f:
                    data = _json.load(f)
                with _lock:
                    sessions[sid]["last_seen"] = time.time()
                # raw 카탈로그 캐싱 → 다음 요청부터 launcher 왕복 생략 (#3).
                # 캐시 키는 응답 '내용'으로 판정한 실제 언어. 과거엔 세션 의도 언어(lang)로
                # 키했으나, 언어 변경 재시작 '전이 중'에는 Orange.ini=Korean(QSettings·lang=ko)
                # 인데 구 registry 가 아직 영어라 → 영어 데이터가 ko 키로 저장되고 디스크 영속으로
                # 영구 오염(사이드바 영어 고착)됐다. data["language"](QSettings 기반)도 같은 이유로
                # registry 와 불일치할 수 있다. 카테고리명 번역 자체가 registry 의 정확한 언어
                # 신호이므로 그것으로 판정 — 영어 응답은 en 키로만 가서 ko/sl 을 오염시키지 않는다.
                try:
                    _cat_names = {(_c.get("name") or "") for _c in (data.get("categories") or [])}
                    if "데이터" in _cat_names:
                        _real_lang = "ko"
                    elif "Podatki" in _cat_names:
                        _real_lang = "sl"
                    elif "Data" in _cat_names:
                        _real_lang = "en"
                    else:
                        _real_lang = None   # 판정 불가 → 캐시하지 않음 (오염 방지)
                    if _real_lang:
                        with _wcat_cache_lock:
                            _wcat_raw_cache[_real_lang] = _copy.deepcopy(data)
                        _wcat_save_disk(_real_lang, data)   # 디스크 영속 → 재시작에도 유지
                except Exception:
                    pass
                # admin_settings.menu 적용 — 숨김 카테고리는 사이드바에서 제외
                try:
                    _admin_set = _admin_load_settings()
                    _menu = _admin_set.get("menu", {})
                    _widgets_vis = _admin_set.get("widgets") or {}
                    # 한국어 카탈로그에선 위젯 name 이 한국어로 옴 → admin 의 영문 키와
                    # 매칭 불가. admin 영문 카탈로그(_admin_widget_catalog.json) 에서
                    # qualified_name → 영문 name 매핑 빌드 후 그것으로 visibility 검사.
                    _qname_to_en_name: dict[str, str] = {}
                    try:
                        _en_cat = _load_admin_widget_catalog()
                        if _en_cat:
                            for _ec in (_en_cat.get("categories") or []):
                                for _ew in (_ec.get("widgets") or []):
                                    _eq = _ew.get("qualified_name", "")
                                    _en = _ew.get("name", "")
                                    if _eq and _en:
                                        _qname_to_en_name[_eq] = _en
                    except Exception as _qe:
                        log.warning(f"[widget-catalog] en-name map 빌드 실패: {_qe}")
                    cats_in = data.get("categories") or []
                    # 2026-05-29: 영어/한국어 듀플 카테고리 정리.
                    # 컨테이너 일부 환경에서 같은 카테고리가 영어(빈, 0 widgets) +
                    # 한국어(실제 위젯) 두 번 등장 → canonical 키 기준으로 위젯이 더
                    # 많은 쪽을 우선 채택. _ADMIN_CAT_ALIASES 가 양쪽을 같은 canonical 로
                    # 매핑하므로 그룹화 후 가장 위젯 많은 것 1개만 남김.
                    _by_canon: dict[str, dict] = {}
                    _no_canon: list[dict] = []
                    for c in cats_in:
                        cn = c.get("name", "")
                        canon = _ADMIN_CAT_ALIASES.get(cn)
                        if canon is None:
                            # admin 알려진 카테고리 외 (예: Orange Obsolete) — 별도 보존
                            _no_canon.append(c)
                            continue
                        wc = len(c.get("widgets") or [])
                        prev = _by_canon.get(canon)
                        if prev is None or wc > len(prev.get("widgets") or []):
                            _by_canon[canon] = c
                    cats_in = list(_by_canon.values()) + _no_canon
                    cats_out = []
                    for c in cats_in:
                        cname = c.get("name", "")
                        canon = _ADMIN_CAT_ALIASES.get(cname, cname)
                        # 1) 카테고리 자체가 꺼져있으면 카테고리 통째 제외 (메뉴 관리 기준)
                        if not _menu.get(canon, True):
                            continue
                        # 1b) 위젯이 0개인 카테고리는 표시 안 함 (빈 placeholder 제거)
                        if not (c.get("widgets") or []):
                            continue
                        # 2) 위젯 단위: admin/widgets 에서 false 로 마크된 위젯은
                        #    제거하지 말고 `disabled:true` 로 표시 — 프론트가 회색
                        #    + 클릭 비활성으로 렌더 (사용자가 위치 인식하되 사용 불가).
                        wmap = _widgets_vis.get(canon) or {}
                        if wmap:
                            new_widgets = []
                            for w in (c.get("widgets") or []):
                                wname = w.get("name", "")
                                qname = w.get("qualified_name", "")
                                # admin 키(영문 name) 매칭: qname 으로 영문명 lookup,
                                # 못 찾으면 현재 wname 그대로 사용 (영문 catalog 인 경우).
                                lookup_name = _qname_to_en_name.get(qname, wname)
                                if wmap.get(lookup_name, True):
                                    new_widgets.append(w)
                                else:
                                    nw = {**w, "disabled": True}
                                    new_widgets.append(nw)
                            c = {**c, "widgets": new_widgets}
                        cats_out.append(c)
                    # 3) admin phase 정의 기반 정렬 + 각 카테고리에 phase 필드 부여
                    # (2026-05-25). 프론트가 phase 변화 시점에 divider 자동 삽입.
                    _phase_idx: dict[str, tuple[int, int]] = {}
                    for _ph in _ADMIN_CATEGORY_PHASES:
                        for _i, _nm in enumerate(_ph["categories"]):
                            _phase_idx[_nm] = (_ph["phase"], _i)
                    def _cat_key(c):
                        cn = c.get("name", "")
                        canon = _ADMIN_CAT_ALIASES.get(cn, cn)
                        if canon in _phase_idx:
                            ph, idx = _phase_idx[canon]
                            c["phase"] = ph
                            return (0, ph, idx)
                        # phase 미정의 (Orange Obsolete 등) — 맨 뒤
                        c["phase"] = 0
                        return (1, 0, cn.lower())
                    cats_out.sort(key=_cat_key)
                    data["categories"] = cats_out
                except Exception as _fe:
                    log.warning(f"[widget-catalog] admin filter 실패: {_fe}")
                return JSONResponse({"ok": True, **data})
            except (ValueError, _json.JSONDecodeError) as e:
                # partial JSON — 다음 폴링에서 재시도. 처음 한번만 로그.
                if _last_parse_err is None:
                    _last_parse_err = str(e)
                    log.info(f"[widget-catalog] partial JSON, retry: {e}")
            except Exception as e:
                log.warning(f"[widget-catalog] parse exception: {e}")
                return JSONResponse({"ok": False, "error": f"parse failed: {e}"}, status_code=500)
        await asyncio.sleep(0.1)
    return JSONResponse({"ok": False, "error": "timeout", "timeout": True}, status_code=504)


@app.post("/add-widget")
async def add_widget(sid: str | None = None, request: Request = None):
    """단계 3A: HTML 사이드바에서 위젯 드래그-드롭(또는 클릭) 시 캔버스에 노드 추가.

    요청 body: {"qualified_name": "Orange.widgets.data.owfile.OWFile",
                "x": 100.0, "y": 200.0}

    동작:
      1. 세션 검증 + qualified_name 안전 검증 (영문자·숫자·점·언더스코어만)
      2. x/y float 변환 (실패 시 400)
      3. `.add_widget.json` 신호 파일 작성 → launcher watcher (단계 3B)가 감지
         → SchemeNode 생성 + scheme.add_node + Undo macro
    """
    import json as _json
    if not sid or request is None:
        return JSONResponse({"ok": False, "error": "no sid"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid json: {e}"}, status_code=400)
    # 안전 검증: qualified_name은 Python 모듈 경로 형식만 허용
    qname = str(body.get("qualified_name", ""))
    if not qname or not re.match(r'^[\w.]+$', qname) or len(qname) > 200:
        return JSONResponse({"ok": False, "error": "invalid qualified_name"}, status_code=400)
    try:
        x = float(body.get("x", 0))
        y = float(body.get("y", 0))
    except (TypeError, ValueError):
        return JSONResponse({"ok": False, "error": "invalid x/y"}, status_code=400)
    # screen_coords: True면 (x,y)는 X11 framebuffer 좌표 → launcher가 view.mapToScene으로 변환
    screen_coords = bool(body.get("screen_coords", False))
    # auto_place: True면 (x,y) 무시하고 Orange3 nextPosition() — 마지막 노드 오른쪽 150px 위치
    auto_place = bool(body.get("auto_place", False))
    sess_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)
    signal_path = os.path.join(sess_dir, ".add_widget.json")
    payload = {"qualified_name": qname, "x": x, "y": y,
               "screen_coords": screen_coords, "auto_place": auto_place}
    try:
        with open(signal_path, "w", encoding="utf-8") as f:
            _json.dump(payload, f, ensure_ascii=False)
    except OSError as e:
        return JSONResponse({"ok": False, "error": f"signal write failed: {e}"}, status_code=500)
    with _lock:
        sessions[sid]["last_seen"] = time.time()
    log.info(f"[{s8(sid)}] add-widget: {qname} at ({x:.1f}, {y:.1f})")
    return JSONResponse({"ok": True})


@app.get("/workflow-info")
async def workflow_info_get(sid: str | None = None):
    """현재 Orange3 scheme의 title/description/showAtNewScheme 조회.

    동작: 컨테이너에 `.workflow_info_query` 신호 작성 → launcher가 scheme 정보를 읽어
    `.workflow_info_response.json` 작성 → 그 파일을 읽어 응답.
    최대 3초 대기 (Orange3 main thread가 busy면 타임아웃 → 빈 응답 반환).
    """
    import json as _json
    if not sid:
        return JSONResponse({"ok": False, "error": "no sid"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    sess_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)
    query_path    = os.path.join(sess_dir, ".workflow_info_query")
    response_path = os.path.join(sess_dir, ".workflow_info_response.json")
    # 이전 응답 파일 정리
    try:
        if os.path.isfile(response_path):
            os.remove(response_path)
    except OSError:
        pass
    # 신호 작성
    try:
        with open(query_path, "w") as f:
            f.write("1")
    except OSError as e:
        return JSONResponse({"ok": False, "error": f"signal write failed: {e}"}, status_code=500)
    # 응답 대기 (최대 3초, 100ms 폴링)
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if os.path.isfile(response_path):
            try:
                with open(response_path, "r", encoding="utf-8") as f:
                    data = _json.load(f)
                os.remove(response_path)
                with _lock:
                    sessions[sid]["last_seen"] = time.time()
                return JSONResponse({"ok": True, **data})
            except Exception as e:
                return JSONResponse({"ok": False, "error": f"response parse failed: {e}"})
        await asyncio.sleep(0.1)
    # 타임아웃 — 빈 값 반환 (사용자가 새로 입력 가능)
    return JSONResponse({"ok": True, "title": "", "description": "", "showAtNewScheme": False, "timeout": True})


@app.post("/workflow-info")
async def workflow_info_post(sid: str | None = None, request: Request = None):
    """Orange3 scheme의 title/description 업데이트.

    동작: 요청 body의 JSON을 `.workflow_info_update.json`에 작성 → launcher가 읽어 적용.
    """
    import json as _json
    if not sid or request is None:
        return JSONResponse({"ok": False, "error": "no sid"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid json: {e}"}, status_code=400)
    # 안전 검증: title/description 길이 제한 + 타입 체크
    title = str(body.get("title", ""))[:200]
    desc  = str(body.get("description", ""))[:5000]
    show  = bool(body.get("showAtNewScheme", False))
    payload = {"title": title, "description": desc, "showAtNewScheme": show}
    sess_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)
    update_path = os.path.join(sess_dir, ".workflow_info_update.json")
    try:
        with open(update_path, "w", encoding="utf-8") as f:
            _json.dump(payload, f, ensure_ascii=False)
    except OSError as e:
        return JSONResponse({"ok": False, "error": f"write failed: {e}"}, status_code=500)
    with _lock:
        sessions[sid]["last_seen"] = time.time()
    log.info(f"[{s8(sid)}] workflow-info 업데이트 요청: title={title!r}")
    return JSONResponse({"ok": True})


@app.get("/tool")
async def tool_route(sid: str | None = None, tool: str | None = None):
    """Orange3 도구 활성화 — signal 파일로 Qt QAction 트리거.

    허용 tool 값:
      - 단순 도구: text, pen, delete, pause, zoomin, zoomout, zoomreset, selectall
      - 텍스트 + 폰트 크기: text:NN (NN은 12~99)
    """
    _SIMPLE = ("text", "pen", "delete", "pause", "zoomin", "zoomout", "zoomreset", "selectall",
               "workflow-info", "undo", "redo")
    if not sid or not tool:
        return JSONResponse({"ok": False, "error": "invalid params"}, status_code=400)
    # text:NN, pen:<hex> 패턴 검증 — injection 방지 (shell에 따옴표로 들어가므로 안전 문자만)
    is_text  = bool(re.match(r"^text:\d{1,2}$", tool))
    is_pen_c = bool(re.match(r"^pen:[0-9A-Fa-f]{3,6}$", tool))  # 3 or 6 hex digits
    if tool not in _SIMPLE and not is_text and not is_pen_c:
        return JSONResponse({"ok": False, "error": "invalid params"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    # Phase 3D-3 fix v4 (2026-05-23): Xpra 컨테이너에도 orange3_launcher.py 를
    # 설치 (Dockerfile.xpra) → 운영 noVNC 와 동일하게 launcher 가 signal 파일을
    # polling 해 Qt QAction 을 직접 trigger 한다. engine 분기 불필요 — 모든 도구가
    # /config/.tool_activate 경유로 통일 (focus/keymap 무관).
    try:
        container = client.containers.get(str(info["container_id"]))
        container.exec_run(["sh", "-c", f"echo '{tool}' > /config/.tool_activate"])
        return JSONResponse({"ok": True, "tool": tool})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/pc_download/check")
async def pc_download_check(sid: str | None = None):
    """OWSave 내 PC 저장 신호 확인 — 사용 가능한 모든 포맷 목록 반환"""
    if not sid:
        return JSONResponse({"ok": False, "ready": False}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "ready": False})
    # 성능(2026-05-31): docker exec 대신 마운트된 신호 파일 직접 읽기 (비차단, ~ms).
    ready_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".pc_download_ready")
    try:
        try:
            with open(ready_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except OSError:
            return JSONResponse({"ok": True, "ready": False})
        if not raw:
            return JSONResponse({"ok": True, "ready": False})
        import json as _json
        try:
            data = _json.loads(raw)
            return JSONResponse({"ok": True, "ready": True,
                                 "basename": data.get("basename", "data"),
                                 "files": data.get("files", []),
                                 "force_new": bool(data.get("force_new", False)),
                                 "widget_id": data.get("widget_id")})
        except _json.JSONDecodeError:
            # 구버전 호환: 단일 파일명만 있는 경우
            return JSONResponse({"ok": True, "ready": True,
                                 "basename": raw, "files": [{"label": raw, "filename": raw}]})
    except Exception:
        return JSONResponse({"ok": False, "ready": False})


@app.get("/pc_download/get")
async def pc_download_get(sid: str | None = None, fname: str | None = None,
                          cleanup: int | None = None):
    """OWSave 내 PC 저장 — 지정된 파일 스트리밍. cleanup=1 이면 신호+임시파일 삭제"""
    if not sid or not fname:
        return JSONResponse({"ok": False, "error": "sid/fname 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        # 파일명 sanitize (path traversal 방지)
        import os.path as _osp
        safe_fname = _osp.basename(fname)
        # 컨테이너에서 파일 추출 (tar 스트림)
        bits, stat = container.get_archive(f"/config/.pc_download/{safe_fname}")
        import io, tarfile
        buf = io.BytesIO()
        for chunk in bits:
            buf.write(chunk)
        buf.seek(0)
        with tarfile.open(fileobj=buf) as tf:
            member = tf.getmember(safe_fname)
            f = tf.extractfile(member)
            data = f.read() if f else b""
        # 정리 옵션
        if cleanup:
            container.exec_run(["sh", "-c",
                "rm -f /config/.pc_download_ready /config/.pc_download/* 2>/dev/null; true"])
        from urllib.parse import quote as _q
        cd = f"attachment; filename=\"{safe_fname}\"; filename*=UTF-8''{_q(safe_fname)}"
        return Response(content=data, media_type="application/octet-stream",
                        headers={"Content-Disposition": cd})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/pc_download/notify_saved")
async def pc_download_notify_saved(sid: str | None = None, name: str | None = None):
    """브라우저에서 저장 완료 후 파일명 알림 → 위젯 버튼 텍스트 갱신용"""
    if not sid or not name:
        return JSONResponse({"ok": False}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False})
    try:
        container = client.containers.get(str(info["container_id"]))
        # 2026-05-28 보안 패치: shlex.quote 로 셸 메타문자 완전 escape.
        # 기존 replace("'","") 는 $, `, ;, \\ 미처리 → 부분적 sanitize.
        import os.path as _osp
        safe_name = _osp.basename(name)
        # 추가 안전성: 파일명 길이 + 화이트리스트 검증 (외부 사용자가 임의 문자 주입 차단)
        if len(safe_name) > 255 or not re.fullmatch(r"[^\x00-\x1f\x7f]+", safe_name):
            return JSONResponse({"ok": False, "error": "invalid name"}, status_code=400)
        container.exec_run([
            "sh", "-c", f"printf %s {shlex.quote(safe_name)} > /config/.pc_save_name"
        ])
        return JSONResponse({"ok": True})
    except Exception:
        return JSONResponse({"ok": False})


@app.get("/pc_download/cleanup")
async def pc_download_cleanup(sid: str | None = None):
    """다운로드 후 컨테이너 임시 파일 + 신호 삭제 (취소 시에도 호출)"""
    if not sid:
        return JSONResponse({"ok": False}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False})
    try:
        container = client.containers.get(str(info["container_id"]))
        container.exec_run(["sh", "-c",
            "rm -f /config/.pc_download_ready /config/.pc_download/* 2>/dev/null; true"])
        return JSONResponse({"ok": True})
    except Exception:
        return JSONResponse({"ok": False})


@app.get("/winlist")
async def winlist_route(sid: str | None = None):
    """X11 가시 창 ID + 현재 활성 창 반환 — 위젯 전체창 감지용"""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        display = info.get("display", ":0")   # Phase 3D-2 (2026-05-23): Xpra=:100
        _, out = container.exec_run(
            ["sh", "-c",
             "xdotool search --onlyvisible . 2>/dev/null; "
             "echo '---'; "
             "xdotool getactivewindow 2>/dev/null || echo ''"],
            environment={"DISPLAY": display},
        )
        raw = (out or b"").decode()
        parts = raw.split("---\n", 1)
        ids    = [x for x in parts[0].split() if x.strip()]
        active = parts[1].strip() if len(parts) > 1 else ""
        return JSONResponse({"ok": True, "ids": ids, "active": active})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/sendkey")
async def sendkey_route(sid: str | None = None, key: str | None = None):
    """xdotool key 를 컨테이너 DISPLAY=:0 에서 실행 — Orange3 메뉴/단축키 전달용"""
    if not sid or not key:
        return JSONResponse({"ok": False, "error": "missing params"}, status_code=400)
    if not _SENDKEY_RE.match(key or ""):
        return JSONResponse({"ok": False, "error": "invalid key"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        display = info.get("display", ":0")   # Phase 3D-2: Xpra=:100
        exit_code, _ = container.exec_run(
            ["sh", "-c",
             # 메인 캔버스 창 검색: PID로 전체 창 목록 조회 후 면적 최대 창 선택.
             # Phase 3D-2: launcher 없는 Xpra 컨테이너에선 orange-canvas 로 fallback.
             # Phase 3D-3 (2026-05-23): `pgrep -f orange-canvas` 가 Xpra start-desktop
             # 명령행("--start-child=orange-canvas") 도 잡아 PID 1 (xpra 자체) 을
             # 잘못 반환 → 잘못된 창에 키가 들어간다. 정밀 패턴으로 수정 + 윈도우 이름
             # ("Orange") 기반 추가 fallback 으로 어떤 경로로든 메인 캔버스를 잡는다.
             # Phase 3D-3 fix v4 (2026-05-23): `pgrep -f orange3_launcher.py` 가
             # Xpra `--start-child="python3 /app/orange3_launcher.py"` cmdline 까지
             # 매칭해 PID 1 (xpra wrapper) 을 head -1 로 반환 → xpra 자체 root
             # 윈도우에 focus → BadMatch. `pgrep -fx` 로 cmdline 정확 매칭.
             "PID=$(pgrep -fx 'python3 /app/orange3_launcher.py' | head -1);"
             " [ -z \"$PID\" ] && PID=$(pgrep -f orange3_launcher.py | grep -v '^1$' | head -1);"
             " [ -z \"$PID\" ] && PID=$(pgrep -f 'python3 /usr/local/bin/orange-canvas' | head -1);"
             " WIN=''; MAXAREA=0;"
             " for w in $(xdotool search --pid \"$PID\" 2>/dev/null); do"
             "   GEOM=$(xdotool getwindowgeometry \"$w\" 2>/dev/null | grep Geometry | awk '{print $2}');"
             "   W=${GEOM%x*}; H=${GEOM#*x};"
             "   [ -n \"$W\" ] && [ -n \"$H\" ] && AREA=$((W * H))"
             "   && [ \"$AREA\" -gt \"$MAXAREA\" ] && MAXAREA=$AREA && WIN=$w;"
             " done;"
             # 이름 기반 fallback (Xpra·노VNC 공통): Orange3 메인 캔버스는 항상
             # 윈도우 타이틀에 "Orange" 가 들어간다 ("Untitled — Orange" 등).
             # 이름 기반 fallback (maximize_orange3.sh 와 동일 패턴): 단독 "Orange"
             # 와 Selection/Clipboard/Requestor 헬퍼 창은 InputHint=false 라
             # windowfocus 가 BadMatch 로 실패한다. 메인 캔버스는 "Untitled — Orange"
             # 처럼 항상 "Orange" 외에 다른 토큰이 붙어 있으므로 길이 > 6 필터로
             # 헬퍼를 제외한다.
             " [ -z \"$WIN\" ] && for w in $(xdotool search --name Orange 2>/dev/null); do"
             "   n=$(xdotool getwindowname \"$w\" 2>/dev/null);"
             "   case \"$n\" in"
             "     \"\"|\"Orange\"|*Selection*|*Clipboard*|*Requestor*) continue ;;"
             "     *Untitled*Orange*) WIN=$w; break ;;"
             "     *Orange*) [ ${#n} -gt 6 ] && { WIN=$w; break; } ;;"
             "   esac;"
             " done;"
             " [ -z \"$WIN\" ] && WIN=$(xdotool search --onlyvisible . 2>/dev/null | head -1);"
             # Phase 3D-3 fix v2 (2026-05-23): `xdotool key --window $WIN` 는 X
             # SendEvent 로 합성된 KeyPress 를 보내는데 Qt5 가 보안상 send_event=true
             # 이벤트를 무시한다 → Orange3 캔버스가 Delete 를 안 받음. windowactivate
             # + windowfocus 로 포커스를 메인 캔버스에 옮겨두고 `xdotool key` 를
             # --window 없이(=XTEST 입력) 호출 → 실제 키보드 이벤트로 합성되어 Qt 가
             # 정상 처리한다. windowactivate 가 _NET_WM_STATE 미지원 창에서 BadMatch
             # 떨굴 수 있어 2>/dev/null + 실패 무시, focus 만 &&-체이닝.
             f" if [ -n \"$WIN\" ]; then"
             f"   xdotool windowactivate --sync \"$WIN\" 2>/dev/null;"
             f"   xdotool windowfocus --sync \"$WIN\" &&"
             f"   xdotool key --clearmodifiers {key};"
             f" else xdotool key --clearmodifiers {key}; fi"],
            environment={"DISPLAY": display},
        )
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        log.info(f"[{s8(sid)}] sendkey: {key} (exit={exit_code})")
        return JSONResponse({"ok": exit_code == 0})
    except Exception as e:
        log.warning(f"[{s8(sid)}] sendkey 오류: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/sendtext")
async def sendtext_route(sid: str | None = None, text: str | None = None):
    """xdotool type 으로 임의 텍스트(한글 포함)를 Orange3 포커스 창에 입력 (2026-05-22).

    캔버스 한글 입력 도우미용. 보안: text 는 환경변수로 전달 — 셸 보간(injection)
    차단. "$ORANGE_TEXT" 는 쉘이 값을 재파싱하지 않으므로 메타문자가 들어와도 안전.
    """
    if not sid or not text:
        return JSONResponse({"ok": False, "error": "missing params"}, status_code=400)
    if len(text) > 500:
        return JSONResponse({"ok": False, "error": "too long"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        display = info.get("display", ":0")   # Phase 3D-2: Xpra=:100
        exit_code, _ = container.exec_run(
            ["sh", "-c",
             # /sendkey 와 동일한 메인 캔버스 창 검색 로직 (Phase 3D-3 fix 포함).
             # 1) PID 기반 검색 — 운영 noVNC launcher 케이스. Xpra 컨테이너엔
             # launcher 미설치라 이 단계는 빈 결과로 끝나고 곧장 이름 검색으로 폴백.
             # (`pgrep -f orange-canvas` 는 신뢰 못 함: sh wrapper cmdline 에 그
             #  문자열이 들어가 PID 1/wrapper PID 가 잘못 잡힘 + Qt5 가 _NET_WM_PID
             #  를 set 안 해 `xdotool search --pid` 가 어차피 빈 결과.)
             # Phase 3D-3 fix v4 (2026-05-23): `pgrep -f orange3_launcher.py` 가
             # Xpra `--start-child="python3 /app/orange3_launcher.py"` cmdline 까지
             # 매칭해 PID 1 (xpra wrapper) 을 head -1 로 반환 → xpra 자체 root
             # 윈도우에 focus → BadMatch. `pgrep -fx` 로 cmdline 정확 매칭.
             "PID=$(pgrep -fx 'python3 /app/orange3_launcher.py' | head -1);"
             " [ -z \"$PID\" ] && PID=$(pgrep -f orange3_launcher.py | grep -v '^1$' | head -1);"
             " WIN=''; MAXAREA=0;"
             " if [ -n \"$PID\" ]; then"
             "   for w in $(xdotool search --pid \"$PID\" 2>/dev/null); do"
             "     GEOM=$(xdotool getwindowgeometry \"$w\" 2>/dev/null | grep Geometry | awk '{print $2}');"
             "     W=${GEOM%x*}; H=${GEOM#*x};"
             "     [ -n \"$W\" ] && [ -n \"$H\" ] && AREA=$((W * H))"
             "     && [ \"$AREA\" -gt \"$MAXAREA\" ] && MAXAREA=$AREA && WIN=$w;"
             "   done;"
             " fi;"
             # 2) 이름 기반 검색 (maximize_orange3.sh 와 동일 패턴) — Xpra 컨테이너
             # 또는 PID-search 실패 시. xdotool `--name` 옵션은 WM_NAME 만 보지만
             # Qt5 는 _NET_WM_NAME 만 set → 메인 캔버스 매칭 실패. 따라서
             # `--onlyvisible \"\"` 로 모든 가시 창을 가져온 뒤 `getwindowname`
             # (_NET_WM_NAME 도 봄) 으로 직접 이름 비교한다.
             # 단독 \"Orange\" 와 Selection/Clipboard/Requestor 헬퍼는 InputHint=false
             # 라 windowfocus 가 BadMatch 로 실패 — 길이/패턴 필터로 제외.
             " [ -z \"$WIN\" ] && for w in $(xdotool search --onlyvisible \"\" 2>/dev/null); do"
             "   n=$(xdotool getwindowname \"$w\" 2>/dev/null);"
             "   case \"$n\" in"
             "     \"\"|\"Orange\"|*Selection*|*Clipboard*|*Requestor*) continue ;;"
             "     *Untitled*Orange*) WIN=$w; break ;;"
             "     *Orange*) [ ${#n} -gt 6 ] && { WIN=$w; break; } ;;"
             "   esac;"
             " done;"
             " [ -z \"$WIN\" ] && WIN=$(xdotool search --onlyvisible . 2>/dev/null | head -1);"
             # Phase 3D-3 fix v2: --window SendEvent 가 Qt5 에서 무시됨 → XTEST 입력.
             " if [ -n \"$WIN\" ]; then"
             "   xdotool windowactivate --sync \"$WIN\" 2>/dev/null;"
             "   xdotool windowfocus --sync \"$WIN\" &&"
             "   xdotool type --clearmodifiers -- \"$ORANGE_TEXT\";"
             " else xdotool type --clearmodifiers -- \"$ORANGE_TEXT\"; fi"],
            environment={"DISPLAY": display, "ORANGE_TEXT": text},
        )
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        log.info(f"[{s8(sid)}] sendtext: {len(text)}자 (exit={exit_code})")
        return JSONResponse({"ok": exit_code == 0})
    except Exception as e:
        log.warning(f"[{s8(sid)}] sendtext 오류: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/scroll")
async def scroll_route(
    sid: str | None = None,
    fx: int = 0, fy: int = 0,
    tx: int = 0, ty: int = 0,
):
    """미니맵 패닝 전용 — xdotool scroll 이벤트(버튼 4/5/6/7)로 캔버스 스크롤.
    도구 전환 없음 → 깜박임·검은 화살표 없음, 위젯 선택/이동 영향 없음."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    for v in (fx, fy, tx, ty):
        if not (0 <= v <= 4096):
            return JSONResponse({"ok": False, "error": "invalid coords"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)

    STEP      = 40   # VNC px per scroll click (100% 줌 기준 근사값)
    MAX_CLICK = 25

    dx = fx - tx   # 양수 = 오른쪽 스크롤
    dy = fy - ty   # 양수 = 아래쪽 스크롤

    v_n = min(MAX_CLICK, max(0, round(abs(dy) / STEP)))
    h_n = min(MAX_CLICK, max(0, round(abs(dx) / STEP)))

    if v_n == 0 and h_n == 0:
        return JSONResponse({"ok": True})

    v_btn = 5 if dy > 0 else 4   # 5=아래, 4=위
    h_btn = 7 if dx > 0 else 6   # 7=오른쪽, 6=왼쪽

    # 커서를 캔버스 중앙으로 이동 후 스크롤 이벤트 전송 (도구 변경 없음)
    parts = [f"xdotool mousemove --sync {tx} {ty}"]
    if v_n > 0:
        parts.append(f"xdotool click --clearmodifiers --repeat {v_n} {v_btn}")
    if h_n > 0:
        parts.append(f"xdotool click --clearmodifiers --repeat {h_n} {h_btn}")
    cmd = " && ".join(parts)

    try:
        container = client.containers.get(str(info["container_id"]))
        container.exec_run(["sh", "-c", cmd], environment={"DISPLAY": ":0"}, detach=True)
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        return JSONResponse({"ok": True})
    except Exception as e:
        log.warning(f"[{s8(sid)}] scroll 오류: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/ping")
async def ping_route(sid: str | None = None):
    """클라이언트 keepalive — last_seen 갱신만 수행"""
    if not sid:
        return JSONResponse({"ok": False}, status_code=400)
    with _lock:
        if sid in sessions:
            sessions[sid]["last_seen"] = time.time()
            return JSONResponse({"ok": True})
    return JSONResponse({"ok": False}, status_code=401)


@app.get("/api/metrics")
async def metrics_route():
    """관측성 SLI — 워밍풀·세션 현황 (④ 2026-05-22).
    모니터링·부하 점검용 경량 지표. 외부 RUM 도입 전 단계로 제공."""
    with _lock:
        total = len(sessions)
        warm = sum(1 for v in sessions.values() if v.get("warm"))
    with _warm_lock:
        pool = len(_warm_pool)
    # Phase 5 모니터링 확장 — 운영 noVNC vs Xpra 사용 비율 + 워밍풀.
    with _xpra_lock:
        xpra_total = len(xpra_sessions)
        xpra_warm  = len(_xpra_warm_pool)
        xpra_inflight = _xpra_warm_inflight
    xpra_active = xpra_total - xpra_warm
    novnc_active = total - warm
    grand = novnc_active + xpra_active
    return JSONResponse({
        # 운영 noVNC
        "warm_pool": pool,
        "warm_pool_target": _effective_pool_size(),
        "active_sessions": novnc_active,
        "total_sessions": total,
        # Xpra (Phase 5)
        "xpra_active_sessions": xpra_active,
        "xpra_warm_pool": xpra_warm,
        "xpra_warm_target": _xpra_effective_pool_size(),
        "xpra_warm_inflight": xpra_inflight,
        "xpra_total_sessions": xpra_total,
        # 비율 (Phase 5 운영 적용 추적)
        "xpra_share_pct": round(100.0 * xpra_active / grand, 1) if grand else 0.0,
        "default_engine": os.environ.get("DEFAULT_ENGINE", "novnc").lower(),
        "uptime_sec": int(time.time() - _START_TIME),
    })


# ── Xpra 전환 실험 라우트 (Phase 2, 2026-05-23) ─────────────────────────────
# 운영 noVNC(/?sid=...) 와 별개 경로. /xpra 호출 시 즉시 Xpra 컨테이너 1개 기동.
@app.get("/xpra")
async def xpra_route(request: Request):
    """Xpra HTML5 세션 신규 기동 + iframe 래퍼 반환 (실험용)."""
    if client is None:
        return JSONResponse({"error": "docker 없음"}, status_code=503)
    # Phase 5 준비 (2026-05-23): 워밍풀 우선 pop → 즉시 응답 (부팅 10s 대기 0초).
    warm_sid = _xpra_pop_warm()
    if warm_sid:
        sid = warm_sid
        with _xpra_lock:
            info = xpra_sessions.get(sid, {})
        cid = info.get("container_id"); port = info.get("port"); cname = info.get("container_name")
        log.info(f"[xpra] 워밍풀 pop sid={sid[:8]} (즉시 응답)")
        # 비어진 자리 백그라운드 보충
        asyncio.create_task(_xpra_replenish_pool())
    else:
        # 워밍풀 비활성 또는 모두 소진 — 즉시 spawn (10s 부팅 대기)
        sid = uuid.uuid4().hex[:16]
        res = _spawn_xpra_container(sid)
        if not res:
            return JSONResponse({"error": "Xpra 컨테이너 생성 실패 (포트 부족 또는 docker 오류)"},
                                status_code=503)
        cid, port, cname = res
        _xpra_register(sid, cid, port, cname, warm=False)
        log.info(f"[xpra] 세션 생성 sid={sid[:8]} container={cid[:12]} port={port}")
    host = request.headers.get("x-forwarded-host") or request.url.hostname
    xpra_url = f"http://{host}:{port}/"
    proxy_url = f"/xpra-proxy/{sid}/"   # Phase 3C-1 same-origin 프록시 URL
    # iframe 대신 컨트롤 패널 + 새 탭으로 Xpra 열기.
    # Xpra HTML5 가 cross-origin iframe 안에서 내부 리다이렉트(window.location)
    # 처리에 실패하는 문제를 회피 (2026-05-23 Phase 2 PoC).
    page = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">
<title>Xpra 세션 (PoC)</title>
<style>
 body{{font-family:-apple-system,"Malgun Gothic",sans-serif;
       background:#fafafa;padding:40px;text-align:center;color:#222}}
 .panel{{max-width:540px;margin:60px auto;background:#fff;
         padding:34px 40px;border-radius:10px;
         box-shadow:0 2px 10px rgba(0,0,0,.08)}}
 h2{{color:#F47B20;margin:0 0 8px}}
 .sub{{color:#666;font-size:13px;margin:6px 0 22px}}
 .info{{font-family:Consolas,monospace;color:#444;font-size:12.5px;
        background:#f5f5f7;padding:10px 14px;border-radius:6px;
        margin:16px 0 22px;text-align:left}}
 .btn{{display:inline-block;padding:11px 22px;margin:5px;
       border-radius:6px;text-decoration:none;font-weight:600;
       font-size:13.5px}}
 .btn-primary{{background:#F47B20;color:#fff}}
 .btn-primary:hover{{background:#d96b10}}
 .btn-end{{background:#fff;color:#666;border:1px solid #ddd}}
 .btn-end:hover{{background:#f5f5f7}}
 .note{{margin-top:24px;color:#888;font-size:12px;line-height:1.55}}
</style></head><body>
<div class="panel">
  <h2>Xpra 세션 준비됨</h2>
  <div class="sub">신규 Xpra 컨테이너가 기동되어 Orange3 를 노출합니다.</div>
  <div class="info">
    port: <b>{port}</b><br>
    sid : <b>{sid[:8]}</b>...<br>
    image: <b>{XPRA_IMAGE}</b>
  </div>
  <a class="btn btn-primary" href="{xpra_url}" target="_blank" rel="noopener">
    Orange3 세션 열기 ↗
  </a>
  <a class="btn btn-primary" href="{proxy_url}" target="_blank" rel="noopener"
     style="background:#1e3a8a">
    프록시 경로로 열기 (3C-1) ↗
  </a>
  <a class="btn btn-primary" href="/xpra-wrapped/{sid}" target="_blank" rel="noopener"
     style="background:#16a34a">
    운영 UI로 열기 (3C-3) ↗
  </a>
  <a class="btn btn-end" href="/xpra-end?sid={sid}">세션 종료</a>
  <div class="note">
    "Orange3 세션 열기" — 새 탭에서 Xpra HTML5 (host port 직접).<br>
    "프록시 경로로 열기" — same-origin 프록시 단독 (3C-1·3C-2 검증용).<br>
    "운영 UI로 열기" — 운영 헤더·사이드바·툴바 안에 Xpra 임베드 (3C-3).<br>
    작업 끝나면 "세션 종료" 클릭.
  </div>
</div>
</body></html>"""
    return HTMLResponse(page)


# ── Xpra HTTP 프록시 (Phase 3C-1, 2026-05-23) ────────────────────────────────
# 운영 noVNC 래퍼의 iframe 차단 우회를 위해 same-origin 으로 Xpra 콘텐츠 노출.
# 같은 docker network 안의 xpra 컨테이너에 container_name 으로 직접 접근.
# WebSocket 은 3C-2 에서 별도 처리. 본 라우트는 HTTP 자산만 중계.
import httpx as _httpx

_HOP_HEADERS = {
    "host", "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "transfer-encoding",
    "upgrade", "content-length",
    # httpx 가 응답을 자동 decompress 하므로 content-encoding 도 제거해야
    # 브라우저가 평문 본문을 다시 decompress 시도 → 깨짐을 막는다 (3C-1 fix).
    "content-encoding",
}

@app.api_route(
    "/xpra-proxy/{sid}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def xpra_http_proxy(sid: str, path: str, request: Request):
    """Xpra 컨테이너로 HTTP 프록시 (Phase 3C-1).
    원본 응답을 그대로 중계 — Content-Type·body 보존. hop-by-hop 헤더는 제거."""
    with _xpra_lock:
        info = xpra_sessions.get(sid)
    if not info:
        return HTMLResponse(_xpra_session_error_page(), status_code=404)
    cname = info.get("container_name")
    if not cname:
        return JSONResponse({"error": "container_name missing"}, status_code=500)
    # docker network DNS — container_name 으로 컨테이너 내부 10000 포트 접근
    target_url = f"http://{cname}:10000/{path}"
    if request.url.query:
        target_url += "?" + request.url.query
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in _HOP_HEADERS}
    body = await request.body() if request.method not in ("GET", "HEAD") else None
    # 컨테이너 부팅 race 대응 — Xpra HTML5 서버가 뜰 때까지 짧게 재시도.
    # Xpra 부팅 ~2~3s 라 첫 호출이 race 로 실패 가능. 최대 ~4s 폴링 (3C-1 fix).
    last_err = None
    for attempt in range(8):
        try:
            async with _httpx.AsyncClient(timeout=10.0, follow_redirects=False) as ac:
                r = await ac.request(
                    request.method, target_url,
                    headers=headers, content=body,
                )
            resp_headers = {k: v for k, v in r.headers.items()
                            if k.lower() not in _HOP_HEADERS}
            # 클립보드 권한 프롬프트 차단 — 프록시 origin(localhost:8888) 에서
            # Xpra HTML5 가 navigator.clipboard API 호출 시 브라우저 권한
            # 프롬프트를 띄우므로 Permissions-Policy 로 차단.
            resp_headers["Permissions-Policy"] = (
                "clipboard-read=(), clipboard-write=()"
            )
            # 진행 오버레이(#progress*) 숨김 + 배경 흰색 강제
            # (Phase 5, 2026-05-24).
            #   1) Xpra HTML5 connection_progress 가 #progress-details 에 ws://
            #      풀 URL(세션ID 포함) 노출 → CSS 한 줄로 차단.
            #   2) client.css 의 html,body{background:#021d3a;background-image:
            #      url(background.png)} 다크 네이비가 리프레시·로딩 중 노출됨
            #      → 운영 톤(흰색) 으로 통일.
            content = r.content
            ctype = (r.headers.get("content-type") or "").lower()
            if "text/html" in ctype and b"</head>" in content:
                # body.desktop {background:#555} 는 클래스 선택자라 단순
                # `body` 보다 우선순위 높음 → 명시 override 필요. 추가로
                # .spinneroverlay (재로딩 시 검은 반투명 오버레이) 도 차단.
                inject = (b'<style id="x-hide-xpra-progress">'
                          b'#progress{display:none !important}'
                          b'html,body,body.desktop{background:#ffffff !important;'
                          b'background-image:none !important}'
                          # Xpra 알림(Network Performance Issue 등) UI 차단 —
                          # 서버측 bandwidth_warnings=False 패치의 클라이언트
                          # safety net. 모든 notify 토스트 비노출.
                          b'.notifications,.notification,.alert'
                          b'{display:none !important}'
                          # 재로딩 시 검은 반투명 .spinneroverlay 비노출 —
                          # 캔버스 영역에 회색/검은 배경처럼 보이는 원인.
                          b'.spinneroverlay{display:none !important}'
                          # Xpra 정보 모달(#about·#sessioninfo·#bugreport) —
                          # jQuery UI 초기화 race 실패 시 default flow 로
                          # 인라인 노출되는 케이스 차단. dialog open 은 별도
                          # 인라인 style 로 처리되므로 영향 없음 (어차피
                          # #float_menu 차단으로 트리거 경로도 없음).
                          b'#about,#sessioninfo,#bugreport{display:none !important}'
                          # iframe 스크롤바 차단 — Xpra 초기 로딩 시 #screen
                          # /.desktop div 가 iframe 보다 1~수 px 크면 가로/세로
                          # 스크롤바 표출. --resize-display 가 첫 interaction
                          # 후 정합 → 그 전까지 노출. 시각적으로만 숨김
                          # (실제 overflow 동작은 유지하지만 scrollbar UI 비표시).
                          b'html,body{overflow:hidden !important}'
                          b'*::-webkit-scrollbar{width:0 !important;height:0 !important;'
                          b'display:none !important}'
                          b'*{scrollbar-width:none !important}'
                          b'</style>')
                content = content.replace(b"</head>", inject + b"</head>", 1)
            return Response(content=content, status_code=r.status_code,
                            headers=resp_headers,
                            media_type=r.headers.get("content-type"))
        except _httpx.TransportError as e:
            # ConnectError / ReadError / RemoteProtocolError / ReadTimeout 포함.
            # Xpra HTML5 가 부팅 직후 TCP accept 는 되지만 HTTP 응답을 못 보내는
            # 짧은 구간이 있어 "Server disconnected without sending a response"
            # 가 나옴. spawn 의 readiness probe 가 대부분 잡지만 안전망으로 재시도.
            last_err = e
            await asyncio.sleep(0.5)
        except Exception as e:
            last_err = e
            break
    log.warning(f"[xpra-proxy] sid={sid[:8]} {request.method} {path} → {last_err}")
    # iframe(HTML 요청) 으로 들어왔을 때 JSON raw 가 사용자에 노출되는 것 차단
    # — Xpra 컨테이너가 중지/제거된 경우 DNS 미해결("[Errno -5] No address
    # associated with hostname") 등으로 proxy 실패. 친화 페이지로 대체.
    # (XHR 등 명시 JSON 요청은 Accept 헤더로 분기) (Phase 5, 2026-05-24)
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept and "text/html" not in accept:
        return JSONResponse(
            {"error": "proxy failed", "detail": str(last_err)},
            status_code=502,
        )
    return HTMLResponse(_xpra_session_error_page(), status_code=502)


# ── Xpra WebSocket 프록시 (Phase 3C-2, 2026-05-23) ───────────────────────────
# Xpra HTML5 클라이언트는 정적 자산을 받은 후 `ws://<origin>/xpra-proxy/<sid>/`
# 로 WebSocket 연결을 시도한다. 같은 docker network 의 xpra 컨테이너
# (`<container_name>:10000`) 와 양방향 중계한다.
@app.websocket("/xpra-proxy/{sid}/")
async def xpra_ws_proxy(websocket: WebSocket, sid: str):
    with _xpra_lock:
        info = xpra_sessions.get(sid)
    if not info:
        await websocket.close(code=4004)
        return
    cname = info.get("container_name")
    if not cname:
        await websocket.close(code=4005)
        return

    # subprotocol negotiation — Xpra HTML5 는 "binary" 사용
    client_protos = websocket.headers.get("sec-websocket-protocol", "")
    chosen = None
    for p in (s.strip() for s in client_protos.split(",")):
        if p in ("binary", "wss-binary"):
            chosen = p
            break

    await websocket.accept(subprotocol=chosen)

    import websockets as _ws_lib
    upstream_url = f"ws://{cname}:10000/"
    try:
        upstream = await _ws_lib.connect(
            upstream_url,
            subprotocols=["binary"] if chosen else None,
            max_size=None,        # Xpra 큰 프레임 (전체 framebuffer 등) 대비
            ping_interval=None,   # Xpra 가 자체 keepalive 처리
        )
    except Exception as e:
        log.warning(f"[xpra-ws] sid={sid[:8]} upstream connect 실패: {e}")
        try: await websocket.close(code=1011)
        except Exception: pass
        return

    log.info(f"[xpra-ws] sid={sid[:8]} → {cname}:10000 connected (subproto={chosen})")

    msg_c2u = msg_u2c = 0
    async def c2u():
        nonlocal msg_c2u
        try:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    return
                if msg.get("bytes") is not None:
                    await upstream.send(msg["bytes"]); msg_c2u += 1
                elif msg.get("text") is not None:
                    await upstream.send(msg["text"]); msg_c2u += 1
        except Exception as e:
            log.info(f"[xpra-ws] c2u {sid[:8]} ended after {msg_c2u} msgs: "
                     f"{type(e).__name__}: {e}")
            return

    async def u2c():
        nonlocal msg_u2c
        try:
            async for m in upstream:
                if isinstance(m, bytes):
                    await websocket.send_bytes(m); msg_u2c += 1
                else:
                    await websocket.send_text(m); msg_u2c += 1
        except Exception as e:
            log.info(f"[xpra-ws] u2c {sid[:8]} ended after {msg_u2c} msgs: "
                     f"{type(e).__name__}: {e}")
            return

    try:
        t1 = asyncio.create_task(c2u())
        t2 = asyncio.create_task(u2c())
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in (t1, t2):
            if not t.done():
                t.cancel()
    finally:
        try: await upstream.close()
        except Exception: pass
        try: await websocket.close()
        except Exception: pass
        log.info(f"[xpra-ws] sid={sid[:8]} closed | c2u={msg_c2u} u2c={msg_u2c}")


# ── /xpra-wrapped dispatch — URL 바에서 SID 마스킹 후 새로고침 케이스 처리 ──
# WRAPPER_PAGE 가 history.replaceState 로 URL 을 `/xpra-wrapped` 까지만 노출.
# 사용자가 새로고침하거나 URL 바에서 Enter 누르면 여기로 진입.
# sessionStorage 의 'orange3_xpra_sid' 가 살아있고 그 sid 가 유효하면 복원,
# 아니면 /xpra-go 로 보내 신규 xpra 세션 발급.
@app.get("/xpra-wrapped")
async def xpra_wrapped_dispatch():
    # F5 새로고침 시 마지막 선택 언어 복원 (2026-05-27)
    return HTMLResponse("""<!DOCTYPE html><html><head><meta charset='UTF-8'>
<style>body{background:#fff;margin:0}</style></head><body><script>
(function(){
  var valid=['ko','en','sl'];
  var storedLang=sessionStorage.getItem('orange3_lang')||'';
  var langQS = (storedLang && valid.indexOf(storedLang)>=0) ? ('?lang='+storedLang) : '';
  try {
    var sid = sessionStorage.getItem('orange3_xpra_sid') || '';
    if (sid && /^[0-9a-f]{16,}$/i.test(sid)) {
      // 유효 형식 — 직접 wrapper 로. wrapper 가 sid 무효면 자체 에러 페이지 노출.
      location.replace('/xpra-wrapped/' + sid + langQS);
      return;
    }
  } catch(_) {}
  // 저장된 sid 가 없거나 형식 비정상 → 신규 발급
  location.replace('/xpra-go' + langQS);
})();
</script></body></html>""")


def _loading_cover_hide_css() -> str:
    """① Loading splash 노출=False 시 vnc-cover 로딩 커튼의 splash 콘텐츠
    (마스코트 + Orange 버전 + addon 리스트)를 숨긴다. 흰 배경 스켈레톤 커튼 자체는
    유지해 연결 중 iframe 을 가림 — 즉 내부 로딩은 그대로, '노출만' 차단.
    (2026-05-31: 기존엔 Orange 내부 boot splash env 만 제어해 워밍 세션에서
    사용자가 보는 로딩 splash 토글이 안 먹던 문제 수정. noVNC·xpra 공통.)"""
    try:
        _sp = _admin_load_settings().get("splashes", {}) or {}
        if _sp.get("loading", True):
            return ""
    except Exception:
        return ""
    # splash 이미지(마스코트 + 버전 + addon 리스트)는 숨기되, 원형 로딩 스피너는
    # 표시해 "로딩 중" 피드백은 유지(빈 화면 방지). 내부 로딩은 그대로 진행.
    return ('<style id="x-hide-loading-splash">'
            '#vnc-cover .sk-splash-wrap,'
            '#vnc-cover #sk-load-info{display:none !important}'
            '#vnc-cover #sk-fallback-spinner{display:block !important}'
            '</style>')


def _ready_splash_html(init_lang: str) -> str:
    """로딩 완료 후(ready) 환영 splash inject 문자열.
    admin_settings.splashes.ready.enabled=False 또는 해당 언어 메시지가 비면 "".
    noVNC·xpra 래퍼 공통 사용 (vnc-frame iframe + .hwd-cat 사이드바 감지 기반).
    2026-05-31: 기존 xpra 라우트 인라인 코드를 헬퍼로 추출 — noVNC 에도 적용."""
    try:
        _sp_cfg = _admin_load_settings().get("splashes", {}) or {}
        _ready_cfg = _sp_cfg.get("ready") or {}
        if not isinstance(_ready_cfg, dict):
            _ready_cfg = {}
    except Exception:
        _ready_cfg = {}
    _ready_enabled = bool(_ready_cfg.get("enabled", True))
    # 단순 토글 (2026-05-31): enabled 면 메시지가 비어 있어도 환영 카드(마스코트)를
    # 표시한다. 언어별 메시지는 선택적 커스터마이즈 — 비면 메시지 영역만 숨김(:empty).
    if not _ready_enabled:
        return ""
    _splash_msg = str(_ready_cfg.get(init_lang, "") or "").strip()
    _splash_msg_js = (_splash_msg.replace("\\", "\\\\")
                                  .replace("'", "\\'")
                                  .replace("<", "\\x3c"))
    return (
        '<style id="x-splash-style">'
        '#x-splash-overlay{'
            'position:fixed;inset:0;z-index:99999;'
            'background:rgba(255,255,255,0.92);'
            'display:flex;align-items:center;justify-content:center;'
            'transition:opacity .4s ease-in-out;'
            'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Malgun Gothic","맑은 고딕",sans-serif;'
        '}'
        '#x-splash-overlay.x-splash-out{opacity:0;pointer-events:none;}'
        '#x-splash-card{'
            'display:flex;flex-direction:column;align-items:center;gap:12px;'
            'background:#ffffff;border-radius:14px;'
            'box-shadow:0 10px 32px rgba(0,0,0,0.10),0 1px 4px rgba(0,0,0,0.05);'
            'padding:20px 24px;max-width:600px;width:72vw;'
        '}'
        '#x-splash-msg-card{'
            'width:100%;box-sizing:border-box;'
            'background:transparent;border-radius:8px;'
            'padding:10px 14px;color:#1a1a1c;'
            'font-size:13.5px;font-weight:600;line-height:1.5;'
            'letter-spacing:-0.2px;text-align:left;'
        '}'
        '#x-splash-msg-card:empty{display:none !important}'
        '#x-splash-mascot-area{'
            'display:flex;align-items:center;justify-content:center;'
            'width:100%;max-width:380px;'
        '}'
        '#x-splash-mascot-area img{'
            'width:100%;height:auto;display:block;max-width:100%;'
        '}'
        '#x-splash-btn-wrap{display:flex;justify-content:flex-end;width:100%;}'
        '#x-splash-ok-btn{'
            'background:#ffffff;color:#1a1a1c;'
            'border:1px solid #e5e7eb;border-radius:7px;'
            'padding:8px 22px;font-size:13.5px;font-weight:600;'
            'cursor:pointer;'
            'transition:background .12s,border-color .12s;'
            'font-family:inherit;'
        '}'
        '#x-splash-ok-btn:hover{background:#f5f5f7;border-color:#d1d5db;}'
        '#x-splash-ok-btn:active{background:#ececef;border-color:#c5c8cd;}'
        '@media (max-width:720px){'
            '#x-splash-card{flex-direction:column;padding:24px;gap:20px;}'
            '#x-splash-mascot-area{min-height:200px;}'
        '}'
        '</style>'
        '<script id="x-splash-script">'
        '(function(){'
        'try{'
        '  var shown=false;'
        '  function showSplash(){'
        '    if(shown) return; shown=true;'
        '    if(document.getElementById("x-splash-overlay")) return;'
        '    var ov=document.createElement("div");ov.id="x-splash-overlay";'
        '    ov.innerHTML='
        '      \'<div id="x-splash-card">\'+'
        '      \'  <div id="x-splash-msg-card">__SPLASH_WELCOME_MSG__</div>\'+'
        '      \'  <div id="x-splash-mascot-area"><img src="/splash-mascot" alt=""></div>\'+'
        '      \'  <div id="x-splash-btn-wrap"><button id="x-splash-ok-btn" type="button">확인</button></div>\'+'
        '      \'</div>\';'
        '    document.body.appendChild(ov);'
        '    function hide(){ov.classList.add("x-splash-out");'
        '      setTimeout(function(){if(ov.parentNode)ov.parentNode.removeChild(ov);},500);}'
        '    var okBtn=document.getElementById("x-splash-ok-btn");'
        '    if(okBtn){okBtn.addEventListener("click",function(e){e.stopPropagation();hide();});}'
        '  }'
        '  function countCats(){'
        '    try{'
        '      var fr=document.getElementById("vnc-frame");'
        '      var doc=fr&&fr.contentDocument;'
        '      if(!doc) return -1;'
        '      return doc.querySelectorAll("#html-widget-dock .hwd-cat").length;'
        '    }catch(e){return -1;}'
        '  }'
        '  function waitSidebarThenShow(){'
        '    if(shown) return;'
        '    var tries=0, stable=0, lastN=-1;'
        '    var iv=setInterval(function(){'
        '      if(shown){clearInterval(iv);return;}'
        '      tries++;'
        '      var n=countCats();'
        '      if(n>0 && n===lastN){'
        '        stable++;'
        '        if(stable>=5){clearInterval(iv);showSplash();return;}'
        '      } else {stable=0;lastN=n;}'
        '      if(tries>=75){clearInterval(iv);showSplash();}'
        '    },200);'
        '  }'
        '  document.addEventListener("DOMContentLoaded",function(){'
        '    var f=document.getElementById("vnc-frame");'
        '    if(f){f.addEventListener("load",function(){setTimeout(waitSidebarThenShow,500);});}'
        '    setTimeout(waitSidebarThenShow,6000);'
        '  });'
        '}catch(e){}'
        '})();'
        '</script>'
    ).replace("__SPLASH_WELCOME_MSG__", _splash_msg_js)


# ── Phase 3C-3 (2026-05-23): 운영 WRAPPER_PAGE 안에 Xpra 임베드 ───────────────
# iframe src 를 same-origin 프록시(`/xpra-proxy/<sid>/`)로 지정 → cross-origin
# 차단 회피 → 운영 헤더·사이드바·툴바 안에 Orange3(Xpra) 가 보임.
# 로딩 커튼은 /screenshot 폴링 의존인데 xpra sid 는 noVNC sessions 에 없으므로
# 커튼 제거 우회 스크립트를 주입한다 (3D 에서 정식 통합 예정).
@app.get("/xpra-wrapped/{xpra_sid}")
async def xpra_wrapped_route(xpra_sid: str, request: Request, lang: str | None = None):
    # Phase 5 (2026-05-24): Xpra 이미지의 Orange.ini 는 language=English 로
    # 시작 — Dockerfile.xpra:111. 옵션 드롭다운 active 표기가 실제 Orange3
    # 로딩 언어와 일치하도록 lang 디폴트 ko → en. 명시 `?lang=ko` 호출은
    # 그대로 한국어로 init.
    # admin_settings.languages.default 로 초기 언어 결정 (명시 ?lang= 시 우선).
    # admin_settings.languages.available 로 옵션 드롭다운 필터.
    with _xpra_lock:
        info = xpra_sessions.get(xpra_sid)
    if not info:
        return HTMLResponse(_xpra_session_error_page(), status_code=404)
    novnc_url = f"/xpra-proxy/{xpra_sid}/"
    # admin 설정 로드 + lang 결정
    _admin = _admin_load_settings()
    _avail = _admin.get("languages", {}).get("available") or ["ko", "en", "sl"]
    _default = _admin.get("languages", {}).get("default") or "en"
    if lang and lang in _avail:
        _init_lang = lang
    elif _default in _avail:
        _init_lang = _default
    else:
        _init_lang = _avail[0] if _avail else "en"
    html = WRAPPER_PAGE.format(novnc_url=novnc_url, sid=xpra_sid, init_lang=_init_lang)
    # admin available 언어 외 드롭다운 항목 제거 (단순 문자열 치환 — 라인 단위)
    _ALL_LANG_LINES = {
        "ko": "    <div class=\"li\" onclick=\"setLang('ko')\">한국어</div>",
        "en": "    <div class=\"li\" onclick=\"setLang('en')\">English</div>",
        "sl": "    <div class=\"li\" onclick=\"setLang('sl')\">Slovenčina</div>",
    }
    for _code, _line in _ALL_LANG_LINES.items():
        if _code not in _avail:
            html = html.replace(_line + "\n", "")
    # 로딩 커튼 우회 (Phase 5, 2026-05-24 hardening):
    #   1) iframe load 후 1.5s — 정상 케이스 우선
    #   2) DOMContentLoaded 후 7s — iframe load 가 안 들어오는 케이스(프록시
    #      hang·HTTP 응답 지연·WebSocket 미연결) safety net. 사용자 시각으로
    #      커튼이 영구 멈춤 방지.
    # 두 트리거 중 먼저 발화하는 쪽이 cover 제거. 중복 호출은 자동 무시.
    inject = ("<script id=\"x-xpra-cover-bypass\">"
              "(function(){"
              "var _removed=false;"
              "function rm(){"
              "if(_removed)return;_removed=true;"
              "var c=document.getElementById('vnc-cover');"
              "if(!c)return;"
              "c.style.opacity=0;"
              "setTimeout(function(){if(c.parentNode)c.parentNode.removeChild(c);},600);"
              "}"
              "document.addEventListener('DOMContentLoaded',function(){"
              "var f=document.getElementById('vnc-frame');"
              # iframe load +3200ms: post-load nudgeResize(+1500ms) 의 프레임버퍼
              # 재정렬 정착 이후에 커버 제거 — 그 전에 제거하면 리사이즈 정착 중
              # 캔버스 경계가 검은 라인으로 노출됨(언어 변경 후 로딩, 2026-06-02).
              "if(f){f.addEventListener('load',function(){setTimeout(rm,3200);});}"
              "setTimeout(rm,7000);"
              "});"
              "})();</script>")
    # Phase 5 (2026-05-24): 한/영 토글 버튼 inject 제거 — 한국어 키보드의
    # Hangul 키 또는 Shift+Space 로 직접 전환 가능. /ibus-toggle 라우트 자체는
    # 유지 (필요 시 외부에서 명시 호출 가능).
    # ── Splash overlay (2026-05-25) ─────────────────────────────────────────
    # 관리자가 설정한 언어별 환영 메시지를 표시. 사용자 언어의 메시지가 비어 있으면
    # inject 자체 skip → 완전 비노출. 사이드바 카테고리 로드 안정 후 표시.
    try:
        _sp_cfg = _admin_load_settings().get("splashes", {}) or {}
        _ready_cfg = _sp_cfg.get("ready") or {}
        if not isinstance(_ready_cfg, dict):
            _ready_cfg = {}
    except Exception:
        _ready_cfg = {}
    # enabled 가 False 면 메시지 무관하게 inject skip
    _ready_enabled = bool(_ready_cfg.get("enabled", True))
    _splash_msg = "" if not _ready_enabled else \
                  str(_ready_cfg.get(_init_lang, "") or "").strip()
    # JS string 안전 escape (' 와 \ 만 escape; HTML 은 텍스트로 들어가므로 < 도 escape)
    _splash_msg_js = (_splash_msg.replace("\\", "\\\\")
                                  .replace("'", "\\'")
                                  .replace("<", "\\x3c"))
    splash = "" if not _splash_msg else (
        '<style id="x-splash-style">'
        # 애니메이션 완전 제거 (2026-05-25 v7) — 정적 카드 레이아웃
        '#x-splash-overlay{'
            'position:fixed;inset:0;z-index:99999;'
            'background:rgba(255,255,255,0.92);'
            'display:flex;align-items:center;justify-content:center;'
            'transition:opacity .4s ease-in-out;'
            'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Malgun Gothic","맑은 고딕",sans-serif;'
        '}'
        '#x-splash-overlay.x-splash-out{opacity:0;pointer-events:none;}'
        # 카드 사이즈 축소 + 확인 버튼 우측 정렬 + 메시지 배경 제거 (2026-05-25 v9)
        '#x-splash-card{'
            'display:flex;flex-direction:column;align-items:center;gap:12px;'
            'background:#ffffff;border-radius:14px;'
            'box-shadow:0 10px 32px rgba(0,0,0,0.10),0 1px 4px rgba(0,0,0,0.05);'
            'padding:20px 24px;max-width:600px;width:72vw;'
        '}'
        '#x-splash-msg-card{'
            'width:100%;box-sizing:border-box;'
            'background:transparent;border-radius:8px;'
            'padding:10px 14px;color:#1a1a1c;'
            'font-size:13.5px;font-weight:600;line-height:1.5;'
            'letter-spacing:-0.2px;text-align:left;'
        '}'
        '#x-splash-msg-card:empty{display:none !important}'
        '#x-splash-mascot-area{'
            'display:flex;align-items:center;justify-content:center;'
            'width:100%;max-width:380px;'
        '}'
        '#x-splash-mascot-area img{'
            'width:100%;height:auto;display:block;max-width:100%;'
        '}'
        '#x-splash-btn-wrap{display:flex;justify-content:flex-end;width:100%;}'
        # 확인 버튼: 카드 스타일 (admin 의 "되돌리기/저장" 톤)
        '#x-splash-ok-btn{'
            'background:#ffffff;color:#1a1a1c;'
            'border:1px solid #e5e7eb;border-radius:7px;'
            'padding:8px 22px;font-size:13.5px;font-weight:600;'
            'cursor:pointer;'
            'transition:background .12s,border-color .12s;'
            'font-family:inherit;'
        '}'
        '#x-splash-ok-btn:hover{background:#f5f5f7;border-color:#d1d5db;}'
        '#x-splash-ok-btn:active{background:#ececef;border-color:#c5c8cd;}'
        '@media (max-width:720px){'
            '#x-splash-card{flex-direction:column;padding:24px;gap:20px;}'
            '#x-splash-mascot-area{min-height:200px;}'
        '}'
        '</style>'
        '<script id="x-splash-script">'
        '(function(){'
        'try{'
        # 페이지 lifetime 동안 1회만 표시 — 확인 버튼 닫은 뒤 safety net 으로
        # 재표시되는 문제 방지. (admin 설정으로 노출 자체를 끄는 건 별개)
        '  var shown=false;'
        '  function showSplash(){'
        '    if(shown) return; shown=true;'
        '    if(document.getElementById("x-splash-overlay")) return;'
        '    var ov=document.createElement("div");ov.id="x-splash-overlay";'
        '    ov.innerHTML='
        '      \'<div id="x-splash-card">\'+'
        '      \'  <div id="x-splash-msg-card">__SPLASH_WELCOME_MSG__</div>\'+'
        '      \'  <div id="x-splash-mascot-area"><img src="/splash-mascot" alt=""></div>\'+'
        '      \'  <div id="x-splash-btn-wrap"><button id="x-splash-ok-btn" type="button">확인</button></div>\'+'
        '      \'</div>\';'
        '    document.body.appendChild(ov);'
        '    function hide(){ov.classList.add("x-splash-out");'
        '      setTimeout(function(){if(ov.parentNode)ov.parentNode.removeChild(ov);},500);}'
        '    var okBtn=document.getElementById("x-splash-ok-btn");'
        '    if(okBtn){okBtn.addEventListener("click",function(e){e.stopPropagation();hide();});}'
        '  }'
        # 사이드바 카테고리 로드 안정 감지 — same-origin iframe (`/xpra-proxy/`,
        # noVNC) 의 contentDocument 에서 `.hwd-cat` 개수가 1초간 변화 없으면 완료.
        # 200ms 폴링, 최대 15초 safety net.
        '  function countCats(){'
        '    try{'
        '      var fr=document.getElementById("vnc-frame");'
        '      var doc=fr&&fr.contentDocument;'
        '      if(!doc) return -1;'
        '      return doc.querySelectorAll("#html-widget-dock .hwd-cat").length;'
        '    }catch(e){return -1;}'
        '  }'
        '  function waitSidebarThenShow(){'
        '    if(shown) return;'
        '    var tries=0, stable=0, lastN=-1;'
        '    var iv=setInterval(function(){'
        '      if(shown){clearInterval(iv);return;}'
        '      tries++;'
        '      var n=countCats();'
        '      if(n>0 && n===lastN){'
        '        stable++;'
        '        if(stable>=5){clearInterval(iv);showSplash();return;}'
        '      } else {stable=0;lastN=n;}'
        '      if(tries>=75){clearInterval(iv);showSplash();}'
        '    },200);'
        '  }'
        '  document.addEventListener("DOMContentLoaded",function(){'
        '    var f=document.getElementById("vnc-frame");'
        '    if(f){f.addEventListener("load",function(){setTimeout(waitSidebarThenShow,500);});}'
        '    setTimeout(waitSidebarThenShow,6000);'  # safety net (gated by `shown`)
        '  });'
        '}catch(e){}'
        '})();'
        '</script>'
    ).replace("__SPLASH_WELCOME_MSG__", _splash_msg_js)
    # ready splash 는 _ready_splash_html() 헬퍼로 일원화 (noVNC 와 동일 동작 보장,
    # ② 단순 토글 로직 한 곳에서 관리). 위 인라인 splash 계산은 미사용. (2026-05-31)
    splash = _ready_splash_html(_init_lang)
    html = html.replace("</head>", _loading_cover_hide_css() + inject + splash + "</head>", 1)
    return html_response(html)


@app.get("/xpra-end")
async def xpra_end_route(sid: str | None = None):
    """Xpra 실험 세션 명시 종료."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 필요"}, status_code=400)
    with _xpra_lock:
        info = xpra_sessions.pop(sid, None)
    # Phase 3D-1: sessions[] 미러도 제거
    with _lock:
        sessions.pop(sid, None)
    if not info:
        return JSONResponse({"ok": False, "error": "세션 없음"}, status_code=404)
    try:
        c = client.containers.get(info["container_id"])
        c.stop(timeout=3)
        c.remove()
        log.info(f"[xpra] 세션 종료 sid={sid[:8]} port={info['port']}")
    except Exception as e:
        log.warning(f"[xpra] 종료 오류 sid={sid[:8]}: {e}")
    return HTMLResponse(_friendly_error_page(
        title="Xpra 세션이 종료되었습니다",
        message="새 세션을 시작하려면 다시 시도해 주세요.",
        hint=f"session ended · {sid[:8]}",
        retry_label="새 세션 시작",
        retry_action="/?engine=xpra",
    ))


# ── 친화 에러 페이지 — 모든 에러 공통 (Phase 5, 2026-05-24) ──────────────────
# 디자인: vnc-cover 의 _showCoverError 와 동일 톤 — ⚠ + 제목 + 본문 + 단일
# "다시 시도" 버튼. 운영·Xpra·404·프록시 실패 등 모든 사용자 노출 에러를
# 동일 포맷으로 통일.
def _friendly_error_page(title: str, message: str, hint: str = "",
                         retry_label: str = "다시 시도",
                         retry_action: str = "reload") -> str:
    """이미지 2 형식 단일 에러 페이지.
    retry_action: 'reload' → top.location.reload(), 그 외 → top.location.href = retry_action

    중첩 방지 (2026-05-29): 이 페이지가 noVNC iframe 안에서 렌더될 수 있음.
    그 상태에서 location.href 로 navigate 하면 iframe 만 바뀌어 WRAPPER_PAGE 가
    iframe 안에 또 로드되고, 그 안에 또 iframe 이 생겨 Orange3 가 자기 자신
    안에 중첩되어 나타남. (top || self).location.href 로 최상위 윈도우 기준으로
    navigate 해서 iframe 컨텍스트를 벗어나도록 한다.
    또한 body 에 sandbox-aware 가드를 두어 안전한 호환성 유지.
    """
    if retry_action == "reload":
        onclick = (
            "var w=window; try{w=window.top||window;}catch(_){w=window;} "
            "w.location.reload();"
        )
    else:
        safe = retry_action.replace("'", "%27")
        onclick = (
            f"var w=window; try{{w=window.top||window;}}catch(_){{w=window;}} "
            f"w.location.href='{safe}';"
        )
    hint_html = f'<div class="hint">({hint})</div>' if hint else ''
    return f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">
<title>{title}</title>
<style>
html,body{{height:100%}}
body{{margin:0;padding:0;font-family:-apple-system,"Malgun Gothic",sans-serif;
     background:#fafafa;display:flex;align-items:center;justify-content:center;
     color:#222}}
.box{{text-align:center;max-width:520px;padding:40px 20px}}
.icon{{font-size:54px;color:#F47B20;line-height:1;margin-bottom:18px}}
.title{{font-size:17px;color:#222;font-weight:600;margin-bottom:14px}}
.msg{{font-size:13px;color:#888;line-height:1.6;margin-bottom:14px}}
.hint{{font-size:11px;color:#aaa;opacity:0.7;margin-bottom:22px;
       font-family:Consolas,monospace}}
button{{margin-top:6px;padding:10px 28px;border-radius:6px;border:0;
       background:#F47B20;color:#fff;font-size:14px;cursor:pointer;font-weight:600}}
button:hover{{background:#d96b10}}
</style></head><body>
<script>
/* 중첩 방지 가드 (2026-05-29) — 이 에러 페이지가 iframe 안에서 렌더되면
   최상위 윈도우를 같은 URL 로 즉시 redirect 해서 WRAPPER_PAGE 가 자기 자신
   안에 중복 로드되는 현상 차단. */
(function() {{
  try {{
    if (window.top && window.top !== window.self) {{
      window.top.location.replace(window.location.href);
    }}
  }} catch(_) {{ /* cross-origin: top 접근 차단 — 가만히 둠 */ }}
}})();
</script>
<div class="box">
  <div class="icon">⚠</div>
  <div class="title">{title}</div>
  <div class="msg">{message}</div>
  {hint_html}
  <button onclick="{onclick}">{retry_label}</button>
</div>
</body></html>"""


def _xpra_session_error_page() -> str:
    return _friendly_error_page(
        title="Xpra 세션을 찾을 수 없습니다",
        message="세션이 만료되었거나 서버가 재시작되었을 수 있습니다.<br>다시 시도해 주세요.",
        hint="xpra session not found",
        retry_label="다시 시도",
        retry_action="/xpra-go",   # 새 Xpra 세션 즉시 spawn → wrapper redirect
    )


# ── 404 / HTTP 예외 친화 페이지 (Phase 5, 2026-05-24) ───────────────────────
# 잘못된 URL 등 FastAPI 의 default `{"detail":"Not Found"}` JSON 응답을 친화
# HTML 로 교체. /api/* 같은 명시 JSON 경로는 라우트 안에서 직접 응답하므로
# 여기에 안 걸린다.
from starlette.exceptions import HTTPException as _StarletteHTTPException


@app.exception_handler(_StarletteHTTPException)
async def _http_exception_handler(request: Request, exc: _StarletteHTTPException):
    # 404 만 친화 HTML — 다른 코드는 기본 JSON 유지 (라우트 안에서 명시 응답 권장)
    if exc.status_code == 404:
        # /api/ 또는 Accept: application/json 클라이언트는 JSON 유지
        accept = request.headers.get("accept", "")
        if request.url.path.startswith("/api/") or "application/json" in accept and "text/html" not in accept:
            return JSONResponse({"error": "Not Found", "path": request.url.path},
                                status_code=404)
        # Xpra 관련 경로의 404(예: 잘못 결합된 /xpra-go… URL, 만료된 /xpra-wrapped)
        # 는 generic 404 대신 Xpra 전용 친화 페이지(이미지2) 로 — "다시 시도" 가
        # /xpra-go 로 새 세션을 즉시 발급해 자연 복구되도록.
        if request.url.path.startswith("/xpra"):
            return HTMLResponse(_xpra_session_error_page(), status_code=404)
        return HTMLResponse(
            _friendly_error_page(
                title="페이지를 찾을 수 없습니다",
                message=f"요청한 경로가 존재하지 않습니다.<br>URL 을 확인하거나 새 세션을 시작해 주세요.",
                hint=f"404 · {request.url.path[:80]}",
            ),
            status_code=404,
        )
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


# ── Xpra 즉시 진입점 (Phase 5, 2026-05-23) ─────────────────────────────────
# 운영 노VNC 의 `/?sid=new` 와 대등한 UX — 워밍풀 pop 후 wrapper 로 즉시 redirect
# (컨트롤 패널 페이지 skip). 사용자가 자연스럽게 Xpra 환경 사용 가능.
# 운영 dispatcher (/) 는 무변경 → noVNC 기본 유지, Xpra 는 명시 URL 선택.
@app.get("/xpra-go")
async def xpra_go(request: Request, lang: str | None = None):
    if client is None:
        return JSONResponse({"error": "docker 없음"}, status_code=503)
    sid = _xpra_pop_warm()
    if sid:
        log.info(f"[xpra-go] 워밍풀 pop sid={sid[:8]}")
        asyncio.create_task(_xpra_replenish_pool())
    else:
        sid = uuid.uuid4().hex[:16]
        # spawn 재시도 (포트 race 등 일시 실패 대비, 최대 3회)
        res = None
        for attempt in range(3):
            res = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _spawn_xpra_container(sid))
            if res:
                break
            log.warning(f"[xpra-go] spawn 시도 {attempt + 1}/3 실패 → 재시도")
            await asyncio.sleep(1)
        if not res:
            return JSONResponse({"error": "Xpra 컨테이너 생성 실패 (3회 재시도 후)"}, status_code=503)
        cid, port, cname = res
        _xpra_register(sid, cid, port, cname, warm=False)
        log.info(f"[xpra-go] fresh spawn sid={sid[:8]} container={cid[:12]}")
    # lang 유효성 체크 후 forward (F5 시 마지막 선택 언어 유지, 2026-05-27)
    if lang in ("ko", "en", "sl"):
        return RedirectResponse(f"/xpra-wrapped/{sid}?lang={lang}", status_code=302)
    return RedirectResponse(f"/xpra-wrapped/{sid}", status_code=302)


# ── Xpra 환경 한/영 토글 (Phase 3D-3 fix v8, 2026-05-23) ─────────────────────
# Hangul/Shift+Space 키가 OS·브라우저 단에서 가로채일 수 있어 Xpra 까지 도달하지
# 못하는 케이스 우회. 서버 측에서 ibus engine 을 강제 전환한다.
# 운영 noVNC 는 X 디스플레이가 다르고 IME 동작 검증된 상태라 Xpra 세션에만 적용.
@app.get("/ibus-toggle")
async def ibus_toggle_route(sid: str | None = None):
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if info.get("engine") != "xpra":
        return JSONResponse({"ok": False, "error": "xpra 전용"}, status_code=400)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker 없음"}, status_code=503)
    display = info.get("display", ":100")
    try:
        container = client.containers.get(str(info["container_id"]))
        # 현재 엔진 조회
        _, cur_out = container.exec_run(
            ["sh", "-c", "ibus engine 2>/dev/null"],
            environment={"DISPLAY": display},
        )
        cur = (cur_out or b"").decode().strip()
        new = "xkb:us::eng" if cur == "hangul" else "hangul"
        ec, _ = container.exec_run(
            ["sh", "-c", f"ibus engine {new} 2>&1"],
            environment={"DISPLAY": display},
        )
        log.info(f"[{s8(sid)}] ibus engine {cur} → {new} (exit={ec})")
        return JSONResponse({"ok": ec == 0, "prev": cur, "now": new,
                             "label": "한" if new == "hangul" else "EN"})
    except Exception as e:
        log.warning(f"[{s8(sid)}] ibus-toggle 오류: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/pan2")
async def pan2_route(sid: str | None = None, dx: int = 0, dy: int = 0):
    """Hand 드래그 패닝 — QGraphicsView scrollbar 직접 조정 (픽셀 정확)
    scene이 viewport에 맞으면 scrollbar range=0 이라 자동으로 비활성."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    if not (-8192 <= dx <= 8192) or not (-8192 <= dy <= 8192):
        return JSONResponse({"ok": False, "error": "invalid delta"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        # 신호 파일에 "pan:dx,dy" 형식으로 기록 → orange3_launcher 가 QGraphicsView scrollbar 조정
        container.exec_run(["sh", "-c", f"echo 'pan:{dx},{dy}' > /config/.tool_activate"])
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/pan")
async def pan_route(
    sid: str | None = None,
    fx: int = 0, fy: int = 0,
    tx: int = 0, ty: int = 0,
    cur: str = "hand",
):
    """Hand 툴 패닝 — xdotool drag 으로 클릭 지점을 화면 중앙으로 이동.
    cur='select': h키로 임시 전환 → drag → Escape 복원 (오브젝트 선택 방지)
    cur='hand'  : 이미 hand 도구 활성 상태이므로 drag만 수행
    """
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    for v in (fx, fy, tx, ty):
        if not (0 <= v <= 4096):
            return JSONResponse({"ok": False, "error": "invalid coords"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        drag = (
            f"xdotool mousemove --sync {fx} {fy} &&"
            f" xdotool mousedown 1 &&"
            f" sleep 0.05 &&"
            f" xdotool mousemove --sync {tx} {ty} &&"
            f" sleep 0.02 &&"
            f" xdotool mouseup 1"
        )
        if cur == "hand":
            # Orange3에 Hand/Pan 모드가 없어 xdotool drag는 영역 선택만 일으킴
            # → 스크롤 휠 이벤트로 캔버스 패닝 (마우스 드래그 방향 = 콘텐츠 이동 방향)
            #   dx > 0 (fx > tx, 즉 사용자가 왼쪽으로 드래그) → 콘텐츠 왼쪽 이동
            #     = 뷰포트 오른쪽 스크롤 (button 7)
            STEP = 10           # VNC px per scroll click — 작은 STEP으로 부드러운 패닝
            MAX_CLICK = 30
            dx = fx - tx
            dy = fy - ty
            v_n = min(MAX_CLICK, max(0, round(abs(dy) / STEP)))
            h_n = min(MAX_CLICK, max(0, round(abs(dx) / STEP)))
            if v_n == 0 and h_n == 0:
                return JSONResponse({"ok": True})
            v_btn = 5 if dy > 0 else 4   # 5=아래, 4=위
            h_btn = 7 if dx > 0 else 6   # 7=오른쪽, 6=왼쪽
            parts = [f"xdotool mousemove --sync {tx} {ty}"]
            if v_n > 0:
                parts.append(f"xdotool click --clearmodifiers --repeat {v_n} {v_btn}")
            if h_n > 0:
                parts.append(f"xdotool click --clearmodifiers --repeat {h_n} {h_btn}")
            cmd = " && ".join(parts)
        else:
            # 선택 도구 상태:
            #   1) 커서를 메뉴바(5,5)로 옮긴 뒤 h 키 → 도구 전환이 캔버스 밖에서 일어남
            #   2) 드래그
            #   3) 드래그 후 커서를 다시 (5,5)로 이동한 뒤 Escape → 검은 화살표가
            #      캔버스 중앙이 아닌 메뉴바 모서리에 나타나 시각적 충돌 최소화
            cmd = (
                f"xdotool mousemove --sync 5 5 &&"
                f" xdotool key h &&"
                f" sleep 0.08 &&"
                f" {drag} &&"
                f" xdotool mousemove --sync 5 5 &&"
                f" sleep 0.02 &&"
                f" xdotool key Escape"
            )
        exit_code, _ = container.exec_run(
            ["sh", "-c", cmd],
            environment={"DISPLAY": ":0"},
        )
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        log.info(f"[{s8(sid)}] pan: ({fx},{fy})→({tx},{ty}) exit={exit_code}")
        return JSONResponse({"ok": exit_code == 0})
    except Exception as e:
        log.warning(f"[{s8(sid)}] pan 오류: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# Orange3 데이터 카테고리 화이트리스트 — /upload_ows/orange3_data/sample/<cat>/ 폴더명과 동일.
# 새 카테고리 추가 시 이 집합과 프론트엔드 `_ORANGE3_CATS` 동시에 갱신.
ORANGE3_DATA_CATS = {
    "Bioinformatics", "Classification", "Clustering", "Fairness",
    "Hierarchical Clustering", "Scatter Plot", "Survival Analysis", "Text Mining",
}


# 카테고리별 스캔 결과 캐시 — find_cmd → (paths, headers, thumb_set, expires_at).
# .ows 파일은 사용자가 직접 수정하는 일이 거의 없어 60초 캐시면 충분.
# 모달 재오픈 시 docker exec 회피로 ~500ms → 1ms.
_ows_scan_cache: dict[str, tuple] = {}
_OWS_SCAN_CACHE_TTL = 60.0   # 초

def _scan_ows_batch(container, find_cmd: str) -> tuple[list[str], dict[str, bytes], set[str]]:
    """단일 docker exec 으로 .ows 파일 목록 + 각 파일 헤더 4KB + 썸네일 목록 일괄 수집.
    이전 구현은 파일당 head 를 별도 exec 으로 호출해 N+1 라운드트립 발생 (모달 1회 ≈ 70+ exec).
    여기서는 find 결과를 셸 루프로 head 후 고유 문자열 구분자로 합쳐 1회 exec 으로 끝낸다.
    Alpine busybox printf 는 \\x.. hex escape 미지원 → 안전한 ASCII 구분자 사용.
    60s TTL 캐시 — 동일 컨테이너+카테고리 재요청은 즉시 응답 (2026-05-28)."""
    # 캐시 키: 컨테이너 ID + find_cmd (카테고리별 다름)
    cache_key = f"{container.id}|{find_cmd}"
    now = time.time()
    cached = _ows_scan_cache.get(cache_key)
    if cached and cached[3] > now:
        return cached[0], cached[1], cached[2]
    REC = "###--OWS-REC--###"   # 파일 헤더 시작 마커 (파일 사이 구분)
    END = "###--OWS-END--###"   # 파일 헤더 종료 마커
    SEP = "###--OWS-THUMBS--###"  # files 와 thumbs 사이 구분
    batch_cmd = (
        f"({find_cmd}) | while IFS= read -r f; do "
        f"  printf '%s%s\\n' '{REC}' \"$f\"; "
        f"  head -c 4096 \"$f\"; "
        f"  printf '%s' '{END}'; "
        f"done; "
        f"printf '%s' '{SEP}'; "
        # 2026-05-29 v3: 공유 + 세션별 양쪽 thumbs 모두 합쳐서 반환
        # (launcher 가 /shared_thumbs/ 우선 쓰는 경우 대응)
        f"ls -1 /shared_thumbs/ 2>/dev/null; "
        f"ls -1 /config/.thumbs/ 2>/dev/null"
    )
    ec, out = container.exec_run(["sh", "-c", batch_cmd])
    raw = out or b""
    rec_b = REC.encode()
    end_b = END.encode()
    sep_b = SEP.encode()
    # 썸네일 분리
    sep_idx = raw.find(sep_b)
    if sep_idx >= 0:
        files_blob = raw[:sep_idx]
        thumbs_blob = raw[sep_idx + len(sep_b):]
    else:
        files_blob = raw
        thumbs_blob = b""
    thumb_set = set(thumbs_blob.decode(errors="ignore").splitlines())
    # 파일별 분리
    paths: list[str] = []
    headers: dict[str, bytes] = {}
    chunks = files_blob.split(rec_b)
    for chunk in chunks:
        if not chunk:
            continue
        # chunk: "<path>\n<header_bytes><END>"
        nl = chunk.find(b"\n")
        if nl < 0:
            continue
        path = chunk[:nl].decode(errors="ignore").strip()
        hdr = chunk[nl + 1:]
        # END 마커 제거
        e_idx = hdr.find(end_b)
        if e_idx >= 0:
            hdr = hdr[:e_idx]
        if path:
            paths.append(path)
            headers[path] = hdr
    # 캐시 저장 (60s TTL)
    _ows_scan_cache[cache_key] = (paths, headers, thumb_set, now + _OWS_SCAN_CACHE_TTL)
    return paths, headers, thumb_set


def _build_ows_items(paths: list[str], headers: dict[str, bytes],
                     thumb_set: set[str], sid: str) -> list[dict]:
    import re as _re
    from urllib.parse import quote as _q
    items = []
    for p in paths:
        text = headers.get(p, b"").decode(errors="ignore")
        m_title = _re.search(r'title="([^"]*)"', text)
        m_desc = _re.search(r'description="([^"]*)"', text)
        raw_title = m_title.group(1) if m_title else ""
        # 빈 title / "untitled" → 파일명 기반 fallback
        title = raw_title if raw_title and raw_title.lower() != "untitled" else os.path.basename(p)[:-4]
        desc = m_desc.group(1) if m_desc else ""
        desc = desc.replace("&#10;", " ").replace("&amp;", "&").replace("&quot;", '"')
        desc = desc.split("\n")[0][:160]
        base = os.path.basename(p)[:-4]
        thumb_url = None
        if (base + ".svg") in thumb_set:
            thumb_url = f"/basic_thumb?sid={sid}&name={_q(base)}"
        items.append({
            "path": p, "title": title, "desc": desc,
            "filename": os.path.basename(p),
            "thumbnail": thumb_url,
        })
    return items


@app.get("/basic_templates")
@limiter.limit("30/minute")
async def basic_templates(request: Request, sid: str | None = None):
    """Example Workflow (베이직) — Orange3 내장 워크플로우 .ows 메타데이터 + 썸네일 URL.
    실제 SVG 콘텐츠는 /basic_thumb?sid=&name= 으로 별도 서빙 (큰 SVG 효율적 전달).
    배치 스캔으로 docker exec 횟수를 N+2 → 1 로 단축 (2026-05-27 perf)."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    try:
        container = client.containers.get(str(info["container_id"]))
        find_cmd = (
            "find /usr/local/lib/python3.10/dist-packages "
            "-name '*.ows' 2>/dev/null | grep -v -i 'test'"
        )
        paths, headers, thumb_set = _scan_ows_batch(container, find_cmd)
        items = _build_ows_items(paths, headers, thumb_set, sid)
        items.sort(key=lambda x: x["title"])
        return JSONResponse({"ok": True, "items": items})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/orange3_templates")
@limiter.limit("60/minute")
async def orange3_templates(request: Request, sid: str | None = None, cat: str | None = None):
    """Sample 카테고리 — /upload_ows/orange3_data/sample/<cat> 의 .ows 목록 (썸네일 URL 포함).
    /elementary_templates 와 동일 응답 형식. /basic_thumb 재사용.
    cat 화이트리스트 검증 — 임의 폴더 접근 차단."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    if not cat or cat not in ORANGE3_DATA_CATS:
        return JSONResponse({"ok": False, "error": "invalid cat"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    try:
        container = client.containers.get(str(info["container_id"]))
        # cat 폴더명에 공백 포함 가능 (Hierarchical Clustering 등) — 큰따옴표 필수.
        # 화이트리스트 통과한 값이라 셸 인젝션 위험 없지만 안전하게 escape.
        cat_safe = cat.replace('"', '\\"')
        # 파일 구조: /upload_ows/orange3_data/sample/<cat>/*.ows (2026-05-27 v5)
        find_cmd = f'find "/upload_ows/orange3_data/sample/{cat_safe}" -maxdepth 1 -name "*.ows" 2>/dev/null'
        paths, headers, thumb_set = _scan_ows_batch(container, find_cmd)
        items = _build_ows_items(paths, headers, thumb_set, sid)
        items.sort(key=lambda x: x["title"])
        return JSONResponse({"ok": True, "cat": cat, "items": items})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/orange3_templates_all")
@limiter.limit("30/minute")
async def orange3_templates_all(request: Request, sid: str | None = None):
    """모든 Sample 카테고리를 한 번에 반환 (2026-05-29 perf).
    이전: 프론트가 8개 카테고리 × 개별 HTTP 호출 (9건 직렬화)
    신규: 단일 find -maxdepth 2 → 카테고리별 분류 → 1건 응답
    응답: { ok, by_cat: {"Classification": [items...], ...} }"""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    try:
        container = client.containers.get(str(info["container_id"]))
        # 카테고리 폴더는 화이트리스트 (ORANGE3_DATA_CATS) 안에서만 결과 채택.
        # find -maxdepth 2 로 카테고리 단계까지만 깊이 스캔 (test 폴더 제외).
        find_cmd = ('find "/upload_ows/orange3_data/sample" -maxdepth 2 '
                    '-name "*.ows" 2>/dev/null')
        paths, headers, thumb_set = _scan_ows_batch(container, find_cmd)
        # path 형식: /upload_ows/orange3_data/sample/<cat>/<file>.ows
        by_cat: dict[str, list[dict]] = {c: [] for c in ORANGE3_DATA_CATS}
        cat_paths: dict[str, list[str]] = {c: [] for c in ORANGE3_DATA_CATS}
        for p in paths:
            parts = p.split("/")
            # ['', 'upload_ows', 'orange3_data', 'sample', '<cat>', '<file>.ows']
            if len(parts) >= 6 and parts[3] == "sample":
                cat = parts[4]
                if cat in ORANGE3_DATA_CATS:
                    cat_paths[cat].append(p)
        for cat, plist in cat_paths.items():
            items = _build_ows_items(plist, headers, thumb_set, sid)
            items.sort(key=lambda x: x["title"])
            by_cat[cat] = items
        return JSONResponse({"ok": True, "by_cat": by_cat})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/elementary_templates")
@limiter.limit("30/minute")
async def elementary_templates(request: Request, sid: str | None = None):
    """초등 Workflow — /upload_ows/elementary 디렉터리의 .ows 메타데이터 + 썸네일 URL.
    /orange3_templates 와 동일 응답 형식 (썸네일은 /basic_thumb 재사용)."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    try:
        container = client.containers.get(str(info["container_id"]))
        find_cmd = "find /upload_ows/elementary -name '*.ows' 2>/dev/null"
        paths, headers, thumb_set = _scan_ows_batch(container, find_cmd)
        items = _build_ows_items(paths, headers, thumb_set, sid)
        items.sort(key=lambda x: x["title"])
        return JSONResponse({"ok": True, "items": items})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ── 교재 BOOK (2026-05-29) ───────────────────────────────────────────────────
# _upload_ows_/orange3_book/<책 폴더>/ 구조:
#   - 책 폴더명: "[출판사] 책 제목"
#   - 표지 이미지: 폴더 안 첫 .png/.jpg 파일
#   - .ows 파일: 폴더 하위 어디든 (재귀 스캔)
#
# id 는 외부 URL 노출용 안전한 슬러그 — 폴더명 직접 노출 금지 (트래버설 차단).
ORANGE3_BOOKS = [
    {
        "id": "saengnung_orange3_easy_ml",
        # 2026-05-29 폴더명 단순화 — 한글/대괄호 제거 (호환성·인코딩 안정성)
        "folder": "book_01",
        "title": "오렌지3로 쉽게 배우는 머신러닝과 데이터 분석",
        "publisher": "생능출판",
        "author": "이지영, 황석형, 김자미",
        # url: 책 소개 페이지 (사이드 링크 표시)
        "url": "https://www.yes24.com/product/goods/179718045",
        # download_url: 보조자료 zip 다운로드 페이지 (다운로드 버튼)
        "download_url": "https://booksr.co.kr/product/%ec%98%a4%eb%a0%8c%ec%a7%803%eb%a1%9c-%ec%89%bd%ea%b2%8c-%eb%b0%b0%ec%9a%b0%eb%8a%94-%eb%a8%b8%ec%8b%a0%eb%9f%ac%eb%8b%9d%ea%b3%bc-%eb%8d%b0%ec%9d%b4%ed%84%b0-%eb%b6%84%ec%84%9d%ec%a0%84%ec%9e%90/",
        "cover": "book_01.png",
    },
    {
        "id": "cmass_orange3_ai",
        "folder": "book_02",
        "title": "나는 오렌지3로 인공지능한다",
        "publisher": "씨마스",
        "author": "임지영, 안성진, 진주환",
        "url": "https://product.kyobobook.co.kr/detail/S000218667435",
        # 보조자료(소스 코드 다운) 페이지 — 출판사 씨마스에듀몰
        "download_url": "https://cmassedumall.com/product/%eb%82%98%eb%8a%94-%ec%98%a4%eb%a0%8c%ec%a7%803%eb%a1%9c-%ec%9d%b8%ea%b3%b5%ec%a7%80%eb%8a%a5%ed%95%9c%eb%8b%a4/298/",
        "cover": "9791156726340.jpg",
    },
    {
        "id": "cmass_orange3_data",
        "folder": "book_03",
        "title": "나는 오렌지로 데이터 분석한다",
        "publisher": "씨마스",
        "author": "강성주, 박세영, 김자미",
        "url": "https://product.kyobobook.co.kr/detail/S000001744151",
        # 보조자료(오렌지 소스 코드 다운) 페이지 — 출판사 씨마스에듀몰
        "download_url": "https://cmassedumall.com/product/%eb%82%98%eb%8a%94-%ec%98%a4%eb%a0%8c%ec%a7%80%eb%a1%9c-%eb%8d%b0%ec%9d%b4%ed%84%b0-%eb%b6%84%ec%84%9d%ed%95%9c%eb%8b%a4-orange3%eb%a1%9c-%eb%b0%b0%ec%9a%b0%eb%8a%94-%ec%9d%b8%ea%b3%b5%ec%a7%80%eb%8a%a5/168/category/84/display/1/",
        "cover": "book_03.jpg",
    },
]
ORANGE3_BOOKS_BY_ID = {b["id"]: b for b in ORANGE3_BOOKS}
# 호스트 경로 (호스트 마운트에서 직접 읽음 — 컨테이너 안 접근 불필요).
# build_upload_ows_volume() 의 호스트 경로 = UPLOAD_OWS_HOST_PATH 환경변수.
# 컨테이너 마운트 경로: /upload_ows
_BOOK_ROOT_IN_CONTAINER = "/upload_ows/orange3_book"


@app.get("/orange3_books")
@limiter.limit("60/minute")
async def orange3_books(request: Request, sid: str | None = None):
    """교재 BOOK — 책 목록 + 메타데이터.
    각 책의 표지 이미지는 /orange3_book_cover?book=<id> 로 별도 서빙.
    워크플로우 목록은 /orange3_book_workflows?sid=&book=<id>."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    items = []
    for b in ORANGE3_BOOKS:
        items.append({
            "id": b["id"],
            "title": b["title"],
            "publisher": b["publisher"],
            "author": b["author"],
            "url": b["url"],
            "download_url": b.get("download_url") or b["url"],
            "cover_url": f"/orange3_book_cover?book={b['id']}",
        })
    return JSONResponse({"ok": True, "items": items})


@app.get("/orange3_book_cover")
async def orange3_book_cover(book: str | None = None):
    """책 표지 이미지 서빙 — book id (화이트리스트) 로 폴더·파일명 결정.
    sid 검증 없음 — 책 표지는 공개 정적 자산. 캐시 30일."""
    if not book or book not in ORANGE3_BOOKS_BY_ID:
        return JSONResponse({"ok": False, "error": "invalid book"}, status_code=400)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker client 없음"}, status_code=500)
    meta = ORANGE3_BOOKS_BY_ID[book]
    cover_path = f"{_BOOK_ROOT_IN_CONTAINER}/{meta['folder']}/{meta['cover']}"
    # 어떤 워밍풀 컨테이너든 사용 — 모두 같은 호스트 폴더를 ro 마운트.
    try:
        # 첫 번째 사용 가능한 orange3-gui 컨테이너 선택
        all_c = await asyncio.get_event_loop().run_in_executor(
            None, lambda: client.containers.list(
                filters={"ancestor": ORANGE3_IMAGE, "status": "running"}, limit=1))
        if not all_c:
            return JSONResponse({"ok": False, "error": "no warm container"}, status_code=503)
        container = all_c[0]
        bits, _stat = await asyncio.get_event_loop().run_in_executor(
            None, lambda: container.get_archive(cover_path))
        import io as _io, tarfile as _tarfile
        buf = _io.BytesIO()
        for chunk in bits:
            buf.write(chunk)
        buf.seek(0)
        with _tarfile.open(fileobj=buf) as tf:
            member = tf.getmember(os.path.basename(cover_path))
            f = tf.extractfile(member)
            data = f.read() if f else b""
        ext = os.path.splitext(meta["cover"])[1].lower()
        media = {"png": "image/png", "jpg": "image/jpeg",
                 "jpeg": "image/jpeg", "gif": "image/gif"}.get(
            ext.lstrip("."), "application/octet-stream")
        return Response(
            content=data, media_type=media,
            headers={"Cache-Control": "public, max-age=2592000, immutable"})
    except Exception as e:
        log.warning(f"[orange3_book_cover] {book}: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404)


@app.get("/orange3_book_workflows")
@limiter.limit("30/minute")
async def orange3_book_workflows(request: Request, sid: str | None = None,
                                 book: str | None = None):
    """교재 BOOK 의 .ows 워크플로우 목록 — /elementary_templates 와 동일 응답 형식."""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    if not book or book not in ORANGE3_BOOKS_BY_ID:
        return JSONResponse({"ok": False, "error": "invalid book"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    meta = ORANGE3_BOOKS_BY_ID[book]
    try:
        container = client.containers.get(str(info["container_id"]))
        # 책 폴더 안 재귀 스캔. 폴더명에 [ ] 공백 한글 포함 — 큰따옴표 escape.
        folder_safe = meta["folder"].replace('"', '\\"').replace('$', '\\$')
        find_cmd = (f'find "{_BOOK_ROOT_IN_CONTAINER}/{folder_safe}" '
                    f'-name "*.ows" 2>/dev/null')
        paths, headers, thumb_set = _scan_ows_batch(container, find_cmd)
        items = _build_ows_items(paths, headers, thumb_set, sid)
        items.sort(key=lambda x: x["title"])
        return JSONResponse({"ok": True, "book": book, "items": items})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ── 썸네일 빠른 경로 (2026-05-29) ────────────────────────────────────────────
# 기존: 매 호출 container.get_archive() → tar 스트림 추출 (~10-30ms)
# 신규: ① 호스트 디스크 직접 read (CONTAINER_SESSIONS_PATH/<sid>/.thumbs/<name>.svg)
#       ② in-memory lru_cache 로 두 번째 호출부터 ~0ms
#       launcher 가 부팅 시 /config/.thumbs/ 에 사전 생성 → 호스트 ./sessions/<sid>/.thumbs/ 에 즉시 노출
from functools import lru_cache as _lru_cache

_THUMB_BYTES_CACHE: dict[str, bytes] = {}      # 키: "<sid>:<name>" — 5분 TTL 메모리 캐시
_THUMB_BYTES_TS: dict[str, float] = {}
_THUMB_TTL_SEC = 300
_THUMB_CACHE_MAX = 2000                        # 메모리 보호

def _thumb_read_fast(sid: str, name: str) -> bytes | None:
    """1순위 in-memory cache, 2순위 공유 디스크 (/shared_thumbs), 3순위 세션별 디스크.
    실패 시 None. (2026-05-29: 공유 디렉토리 추가 — 세션 무관 공유)"""
    # 공유 디렉토리 hit 은 sid 비의존 → 별도 캐시 키
    shared_key = f"_shared:{name}"
    per_session_key = f"{sid}:{name}"
    now = time.time()
    # 1) in-memory cache hit (공유 우선)
    ts = _THUMB_BYTES_TS.get(shared_key)
    if ts and (now - ts) < _THUMB_TTL_SEC:
        return _THUMB_BYTES_CACHE.get(shared_key)
    ts = _THUMB_BYTES_TS.get(per_session_key)
    if ts and (now - ts) < _THUMB_TTL_SEC:
        return _THUMB_BYTES_CACHE.get(per_session_key)
    # 캐시 정리 헬퍼
    def _store(cache_k: str, data: bytes):
        if len(_THUMB_BYTES_CACHE) >= _THUMB_CACHE_MAX:
            stale = sorted(_THUMB_BYTES_TS.items(), key=lambda x: x[1])[:_THUMB_CACHE_MAX // 4]
            for k, _ in stale:
                _THUMB_BYTES_CACHE.pop(k, None)
                _THUMB_BYTES_TS.pop(k, None)
        _THUMB_BYTES_CACHE[cache_k] = data
        _THUMB_BYTES_TS[cache_k] = now
    # 2) 공유 디렉토리 (모든 세션 공유)
    shared_path = os.path.join(SHARED_THUMBS_LOCAL_PATH, name + ".svg")
    try:
        if os.path.isfile(shared_path):
            with open(shared_path, "rb") as f:
                data = f.read()
            if data:
                _store(shared_key, data)
                return data
    except OSError:
        pass
    # 3) 세션별 디스크 (legacy / 부팅 직후)
    host_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".thumbs", name + ".svg")
    try:
        if os.path.isfile(host_path):
            with open(host_path, "rb") as f:
                data = f.read()
            _store(per_session_key, data)
            return data
    except OSError:
        pass
    return None


@app.get("/basic_thumb")
async def basic_thumb(sid: str | None = None, name: str | None = None):
    """베이직/초등/교재 워크플로우 썸네일 SVG 파일 직접 서빙.
    빠른 경로: 호스트 디스크 직접 read (./sessions/<sid>/.thumbs/<name>.svg)
              + lru-style in-memory cache (5분 TTL).
    Fallback : container.get_archive() — 호스트 경로가 비어 있는 시점(부팅 직후) 대응."""
    if not sid or not name:
        return JSONResponse({"ok": False, "error": "sid/name 없음"}, status_code=400)
    # 디렉터리 트래버설 차단 (한글/공백 파일명 허용)
    if '..' in name or '/' in name or '\\' in name or '\x00' in name:
        return JSONResponse({"ok": False, "error": "invalid name"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    # ── 빠른 경로 ──
    fast = _thumb_read_fast(sid, name)
    if fast is not None:
        return Response(content=fast, media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=2592000, immutable",
                                 "X-Thumb-Source": "host-disk"})
    # ── Fallback: docker tar 추출 (launcher 미완료 시) ──
    try:
        container = client.containers.get(str(info["container_id"]))
        bits, _stat = container.get_archive(f"/config/.thumbs/{name}.svg")
        import io as _io, tarfile as _tarfile
        buf = _io.BytesIO()
        for chunk in bits:
            buf.write(chunk)
        buf.seek(0)
        with _tarfile.open(fileobj=buf) as tf:
            member = tf.getmember(f"{name}.svg")
            f = tf.extractfile(member)
            data = f.read() if f else b""
        # 다음 호출 위해 메모리에도 캐시
        _THUMB_BYTES_CACHE[f"{sid}:{name}"] = data
        _THUMB_BYTES_TS[f"{sid}:{name}"] = time.time()
        return Response(content=data, media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=2592000, immutable",
                                 "X-Thumb-Source": "docker-tar"})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404)


# ── .ows 경로 검증 공통 함수 (2026-05-29) ────────────────────────────────────
# template_blob / open_basic_template 둘 다 사용.
# 정책: 셸 메타문자 denylist + 경로 traversal(..) 차단 + .ows 확장자 강제.
# 한글·대괄호 [] 허용 (교재 BOOK 폴더명 호환). 모든 path 사용처는 array args
# (container.exec_run([...]) / container.get_archive(path)) 라 셸 인터폴레이션
# 자체가 없으나, 방어적으로 위험 문자 사전 차단.
# 2026-05-29 v2: ! # ~ 허용 — 한국어 책 파일명에 일상적으로 등장 (예: "활동1 전복!.ows").
# 셸 single-quote / array args 컨텍스트에서 이 셋은 메타문자 의미 없음.
_OWS_PATH_BAD_CHARS = set(";&|`$\\'\"<>*?(){}\x00\n\r\t")

def _is_safe_ows_path(path: str) -> bool:
    if not isinstance(path, str) or not path:
        return False
    if not path.endswith(".ows"):
        return False
    if ".." in path:
        return False
    if any(c in _OWS_PATH_BAD_CHARS for c in path):
        return False
    # 최대 길이 제한 (DoS 방어)
    if len(path) > 1024:
        return False
    return True


@app.get("/template_blob")
@limiter.limit("60/minute")
async def template_blob(request: Request, sid: str | None = None, path: str | None = None):
    """베이직 템플릿 OWS 파일 내용을 binary 로 반환 (탭 추가용 blob).
    원본 .ows 의 title=""/description="" 가 비어 있으면 파일명/카테고리 기반으로 주입 — 워크플로우 로드 후 'untitled' 로 표시되는 문제 방지.
    2026-05-28 보안 패치: path 정규식 엄격 검증 (셸 메타문자 차단).
    2026-05-29 호환성 확장: 한글·대괄호 허용 (교재 BOOK 폴더명). 셸 메타문자는 denylist 로 차단."""
    if not sid or not path:
        return JSONResponse({"ok": False, "error": "sid/path 없음"}, status_code=400)
    if not _is_safe_ows_path(path):
        return JSONResponse({"ok": False, "error": "invalid path"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    try:
        container = client.containers.get(str(info["container_id"]))
        # 컨테이너 파일을 tar 로 추출
        bits, _stat = container.get_archive(path)
        import io as _io, tarfile as _tarfile
        buf = _io.BytesIO()
        for chunk in bits:
            buf.write(chunk)
        buf.seek(0)
        with _tarfile.open(fileobj=buf) as tf:
            member = tf.getmember(os.path.basename(path))
            f = tf.extractfile(member)
            data = f.read() if f else b""
        # title/description 비어있으면 파일명 기반으로 주입 (sample/<cat>/<basename>.ows)
        try:
            import re as _re
            base = os.path.basename(path)[:-4]  # .ows 제거
            # 카테고리 디렉토리명 (sample/<cat>/...) — Workflow Info description 에 보조 표시
            cat = ""
            _parts = path.split("/")
            if "sample" in _parts:
                _i = _parts.index("sample")
                if _i + 1 < len(_parts):
                    cat = _parts[_i + 1]
            # 파일명 → 사람이 읽기 쉬운 제목 (하이픈/언더스코어 → 공백, 첫 글자 대문자화)
            pretty = _re.sub(r'^\d+[-_\s]*', '', base)  # 선행 숫자 prefix 제거
            pretty = pretty.replace('_', ' ').replace('-', ' ').strip() or base
            pretty = ' '.join(w.capitalize() if w.islower() else w for w in pretty.split())
            desc_text = f"Sample workflow — {cat}: {base}.ows" if cat else f"Sample workflow — {base}.ows"
            text = data.decode("utf-8", errors="ignore")
            # title="" 또는 title="untitled" → 파일명 기반 제목으로 교체.
            # XML escape — & < > " 만 충분 (제목은 영문/숫자/공백 위주).
            def _esc(s: str) -> str:
                return (s.replace("&", "&amp;").replace("<", "&lt;")
                          .replace(">", "&gt;").replace('"', "&quot;"))
            pretty_esc = _esc(pretty)
            desc_esc = _esc(desc_text)
            new_text = _re.sub(
                r'(<scheme\b[^>]*?\btitle=)"(?:|untitled)"',
                lambda m: m.group(1) + '"' + pretty_esc + '"',
                text, count=1,
            )
            new_text = _re.sub(
                r'(<scheme\b[^>]*?\bdescription=)""',
                lambda m: m.group(1) + '"' + desc_esc + '"',
                new_text, count=1,
            )
            if new_text != text:
                data = new_text.encode("utf-8")
                log.info(f"[{s8(sid)}] template_blob 메타 주입: {base}.ows → title='{pretty}'")
            else:
                log.info(f"[{s8(sid)}] template_blob 메타 유지: {base}.ows (원본 보존)")
        except Exception as _e:
            log.warning(f"[{s8(sid)}] template_blob 메타 주입 실패: {_e}")
        # 캐시 비활성화 — 패치 적용 직후 브라우저가 이전 응답을 재사용하지 못하도록.
        return Response(
            content=data, media_type="application/xml",
            headers={"Cache-Control": "no-store, no-cache, must-revalidate",
                     "Pragma": "no-cache"},
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/open_basic_template")
@limiter.limit("30/minute")
async def open_basic_template(request: Request, sid: str | None = None, path: str | None = None):
    """베이직 워크플로우 열기 — 컨테이너 내부 경로의 .ows 파일을 launcher 신호로 열기.
    2026-05-28 보안 패치: shell injection 차단 — 경로 정규식 엄격 검증 + 배열 인자 사용.
    2026-05-29 호환성 확장: 한글·대괄호 허용 (교재 BOOK 폴더명). _is_safe_ows_path 공유."""
    if not sid or not path:
        return JSONResponse({"ok": False, "error": "sid/path 없음"}, status_code=400)
    if not _is_safe_ows_path(path):
        return JSONResponse({"ok": False, "error": "invalid path"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info or client is None:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    try:
        container = client.containers.get(str(info["container_id"]))
        # 보안: 배열 인자 (sh -c 없이) — 셸 인터폴레이션 자체 우회
        ec, _ = container.exec_run(["test", "-f", path])
        if ec != 0:
            return JSONResponse({"ok": False, "error": "file not found"}, status_code=404)
        fname = os.path.basename(path)
        tmp_path = f"/tmp/{fname}"
        # cp 도 배열 인자로 직접 호출
        container.exec_run(["cp", path, tmp_path])
        # 신호 파일 작성 — tmp_path 는 위 정규식 + basename 으로 안전 보장
        container.exec_run(["sh", "-c", f"printf %s {shlex.quote(tmp_path)} > /config/.open_workflow"])
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        log.info(f"[{s8(sid)}] open_basic_template: {fname}")
        return JSONResponse({"ok": True, "filename": fname})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/open-example-workflows")
async def open_example_workflows(sid: str | None = None):
    """Orange3 창 포커스 후 Help > Example Workflows 키 시퀀스 실행"""
    if not sid:
        return JSONResponse({"ok": False, "error": "sid 없음"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=401)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    try:
        container = client.containers.get(str(info["container_id"]))
        # 1) Orange3 창 찾아서 포커스
        # 2) F10 → 메뉴바 활성화
        # 3) Right×6 → Help (File/Edit/View/Widget/Window/Options/Help)
        # 4) Return → Help 메뉴 오픈
        # 5) Down×3 → Example Workflows (About/Welcome/Video Tutorials/→Example Workflows)
        # 6) Return → 실행
        container.exec_run(
            ["sh", "-c", "printf '1' > /config/.open_examples"],
        )
        with _lock:
            sessions[sid]["last_seen"] = time.time()
        log.info(f"[{s8(sid)}] open-example-workflows 실행")
        return JSONResponse({"ok": True})
    except Exception as e:
        log.warning(f"[{s8(sid)}] open-example-workflows 오류: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


def _xpra_apply_language_inplace(sid: str, session_dir: str, lang_name: str,
                                  other_lang: str, container_id: str) -> None:
    """Xpra 세션의 Orange.ini 를 호스트에서 직접 수정 + 컨테이너 재시작.
    startapp.xpra.sh 에는 noVNC startapp.sh 의 .lang_override→Orange.ini 처리
    루프가 없어 신호 파일만으로는 언어가 안 바뀐다. 호스트에서 직접 Orange.ini
    를 갱신한 뒤 컨테이너를 재시작해 Orange3 가 새 언어로 부팅되게 한다."""
    import configparser as _cp
    ini_dir  = os.path.join(session_dir, "xdg", "config", "biolab.si")
    ini_path = os.path.join(ini_dir, "Orange.ini")
    os.makedirs(ini_dir, exist_ok=True)
    # 기존 ini 로드 (없으면 신규 생성)
    cfg = _cp.ConfigParser()
    cfg.optionxform = str  # 키 case 보존 (Orange3 가 case 민감)
    if os.path.isfile(ini_path):
        try:
            cfg.read(ini_path, encoding="utf-8")
        except Exception:
            cfg = _cp.ConfigParser()
            cfg.optionxform = str
    # Orange 는 언어를 [application] 섹션에서 읽는다(startapp.sh 도 [application] 에 기록).
    # 기존엔 [General] 에 써서 Orange 가 무시 → Xpra 언어 변경 미반영 + /language 가
    # [application] 옛값을 읽어 lang-sync 무한 루프("언어 변경 중…" 멈춤). (2026-05-31 수정)
    if "application" not in cfg:
        cfg["application"] = {}
    cfg["application"]["language"] = lang_name
    # ① 언어별 사전 빌드 캐시(/opt/orange3-regcache-<Lang>) 존재 시: 그 캐시를 세션 캐시로
    # 복사하고 last-used 를 새 언어와 일치시켜 재탐색을 건너뛴다(noVNC startapp.sh ① 과 동일).
    # 캐시가 없으면(구 xpra 이미지) 기존 동작(last-used 불일치 + 캐시 삭제 → 재탐색)으로 폴백.
    _c = None
    _has_lang_cache = False
    _src = "/opt/orange3-regcache-" + lang_name
    try:
        _c = client.containers.get(container_id)
        if _c.exec_run(["test", "-d", _src + "/Orange"]).exit_code == 0:
            _has_lang_cache = True
    except Exception as _ce0:
        log.warning(f"[{s8(sid)}] xpra 언어캐시 확인 실패: {_ce0}")
    cfg["application"]["last-used-language"] = lang_name if _has_lang_cache else other_lang
    # 원자 쓰기 — write+rename
    tmp = ini_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        cfg.write(f, space_around_delimiters=False)
    os.replace(tmp, ini_path)
    if _has_lang_cache and _c is not None:
        # 새 언어 캐시 복사(컨테이너 안 /config = 세션 디렉터리 마운트) → 재탐색 skip
        try:
            _c.exec_run(["sh", "-c",
                         "rm -rf /config/xdg/cache/Orange && mkdir -p /config/xdg/cache && "
                         "cp -r " + _src + "/Orange /config/xdg/cache/Orange"])
            log.info(f"[{s8(sid)}] xpra ① 언어캐시 적용: {lang_name} (재탐색 생략)")
        except Exception as _cce:
            log.warning(f"[{s8(sid)}] xpra 언어캐시 복사 실패: {_cce}")
    else:
        # 폴백: 레지스트리 캐시 삭제 → Orange3 가 재탐색
        try:
            cache_dir = os.path.join(session_dir, "xdg", "cache", "Orange")
            if os.path.isdir(cache_dir):
                import shutil as _sh
                _sh.rmtree(cache_dir, ignore_errors=True)
        except Exception as _ce:
            log.warning(f"[{s8(sid)}] xpra cache 정리 실패: {_ce}")
    # 컨테이너 재시작 — startapp.xpra.sh 가 다시 돌면 Orange3 가 새 언어로 기동
    try:
        c = _c or client.containers.get(container_id)
        c.restart(timeout=3)
    except Exception as _re:
        log.warning(f"[{s8(sid)}] xpra container.restart 실패: {_re}")


@app.get("/set-language")
async def set_language(sid: str | None = None, lang: str | None = None):
    """Orange3 언어 설정 변경 후 재시작.
    noVNC: .lang_override + .restart_language 신호 → startapp.sh while 루프가
           Orange.ini 갱신 후 Orange3 재기동.
    xpra:  startapp.xpra.sh 에 신호 처리 루프가 없으므로 Orange.ini 호스트에서
           직접 수정 + 컨테이너 restart.
    """
    LANG_MAP = {"ko": "Korean", "en": "English", "sl": "Slovenian"}
    if not sid or lang not in LANG_MAP:
        return JSONResponse({"ok": False, "error": "invalid params"}, status_code=400)
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, status_code=404)
    if client is None:
        return JSONResponse({"ok": False, "error": "docker not connected"}, status_code=503)
    session_dir    = os.path.join(CONTAINER_SESSIONS_PATH, sid or "")
    app_ready_path = os.path.join(session_dir, ".app_ready")
    restart_sent   = False
    try:
        lang_name  = LANG_MAP[lang or ""]
        other_lang = "English" if lang_name != "English" else "Korean"
        engine = info.get("engine") or "novnc"

        # 1) .lang_override — 호스트 직접 쓰기 (exec_run 없이 즉시 반영)
        with open(os.path.join(session_dir, ".lang_override"), "w") as _f:
            _f.write(f"language={lang_name}\nlast-used-language={other_lang}")

        # 1-a) .clear_history — 재시작 시 최근 워크플로우 이력 삭제 신호
        with open(os.path.join(session_dir, ".clear_history"), "w") as _f:
            _f.write("1")

        # 1-b) .splash_loading — 현재 admin loading splash 설정을 라이브 기록.
        # 재시작되는 launcher 가 env 대신 이 파일을 읽어 토글을 즉시 반영
        # (컨테이너 재생성 불필요). splash UI 만 숨기고 내부 로딩은 유지. (2026-05-31)
        try:
            with open(os.path.join(session_dir, ".splash_loading"), "w") as _f:
                _f.write(_splash_loading_env_val())
        except Exception:
            pass

        # 2) .app_ready 삭제 → /ready 폴링이 즉시 false 반환
        try:
            os.remove(app_ready_path)
        except FileNotFoundError:
            pass

        if engine == "xpra":
            # Xpra: Orange.ini 호스트에서 직접 수정 + 컨테이너 restart
            #       (startapp.xpra.sh 에 .lang_override 처리 루프 없음)
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: _xpra_apply_language_inplace(
                    sid, session_dir, lang_name, other_lang,
                    str(info.get("container_id", "")),
                ),
            )
            restart_sent = True
        else:
            # noVNC: .restart_language 신호 → startapp.sh 루프가 Orange3 재기동
            with open(os.path.join(session_dir, ".restart_language"), "w") as _f:
                _f.write("1")
            restart_sent = True

        with _lock:
            sessions[sid]["last_seen"] = time.time()
        log.info(f"[{s8(sid)}] set-language: {lang_name} engine={engine}")
        return JSONResponse({"ok": True, "lang": lang_name, "engine": engine})
    except Exception as e:
        log.warning(f"[{s8(sid)}] set-language 오류: {e}")
        # 재시작 신호 미전송 시 Orange3 계속 실행 중 → .app_ready 복원
        if not restart_sent:
            try:
                open(app_ready_path, "w").close()
            except Exception:
                pass
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/language")
async def get_language(sid: str | None = None):
    """Orange3 컨테이너의 현재 언어 설정 반환 — initLang 자동 동기화용.
       성능(2026-05-31): docker exec 대신 마운트된 Orange.ini 직접 읽기.
       exec_run 은 컨테이너 부팅 중 수백 ms 걸려 이벤트 루프를 막아 다른 경량 API 를
       줄세웠음(진단보고서 #2). Orange.ini 는 세션 디렉터리에 마운트돼 있어 직접 읽으면
       ~ms 로 끝나고 docker 호출이 없어 비차단."""
    INI_TO_CODE = {"Korean": "ko", "English": "en", "Slovenian": "sl", "Slovenčina": "sl"}
    if not sid:
        return JSONResponse({"lang": "en"})
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"lang": "en"})
    ini_path = os.path.join(CONTAINER_SESSIONS_PATH, sid,
                            "xdg", "config", "biolab.si", "Orange.ini")
    try:
        with open(ini_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("language="):
                    lang_name = line.split("=", 1)[1].strip()
                    return JSONResponse({"lang": INI_TO_CODE.get(lang_name, "en")})
    except OSError:
        pass
    return JSONResponse({"lang": "en"})


# ── 관리자 설정 (Phase 5, 2026-05-24) ────────────────────────────────────────
# 전체 사용자에 일괄 적용되는 메뉴/언어 설정. 영속 저장은 mounted volume 안
# /sessions/admin_settings.json (호스트에서도 직접 편집 가능). 후속 단계에서
# /widget-catalog · /set-language 가 이 설정을 참조하도록 통합 예정.
ADMIN_SETTINGS_PATH = os.path.join(CONTAINER_SESSIONS_PATH, "admin_settings.json")
# A안(2026-06-09): 위젯 가시성 등 admin 기본 설정을 레포에 커밋(admin_settings.default.json)하고,
# 런타임 파일이 없을 때(GitHub 클론·신규 서버 첫 부팅) 이 기본값으로 1회 시드한다.
# → 삭제(숨김)한 위젯이 클론에도 유지됨. 서버별 변경은 이후 sessions/admin_settings.json 에 override.
# (sessions/ 는 .gitignore 라 런타임 파일 자체는 git 에 안 들어감 — 그래서 시드가 필요)
ADMIN_SETTINGS_DEFAULT_PATH = os.environ.get(
    "ADMIN_SETTINGS_DEFAULT_PATH", "/app/admin_settings.default.json")

# 알려진 카테고리 — 시범 서비스 단계별 그룹화 (Phase 5, 2026-05-24).
# 신규 addon 설치 시 해당 단계 그룹에 수동 추가.
_ADMIN_CATEGORY_PHASES = [
    {"phase": 1, "title": "1차 시범 서비스",
     "categories": ["Data", "Transform", "Visualize",
                    "Model", "Evaluate", "Unsupervised"]},
    {"phase": 2, "title": "2차 시범 서비스",
     "categories": ["Image Analytics", "Network", "Time Series",
                    "Text Mining", "Geo"]},
    {"phase": 3, "title": "3차 시범 서비스",
     "categories": ["Single Cell", "Spectroscopy", "Bioinformatics",
                    "Survival Analysis", "Fairness"]},
    # 4차 (2026-05-25) — 3차에서 이동한 3개 + 신규 addon 4종.
    # 사용자 지정 순서: Explain · Educational · Associate · Textable ·
    # Pumice · World Happiness · SNOM
    {"phase": 4, "title": "4차 시범 서비스",
     "categories": ["Explain", "Educational", "Associate",
                    "Textable", "Pumice", "World Happiness", "SNOM"]},
]
_ADMIN_KNOWN_CATEGORIES = [
    cat for g in _ADMIN_CATEGORY_PHASES for cat in g["categories"]
]
_ADMIN_KNOWN_LANGS = [
    {"code": "ko", "label": "한국어"},
    {"code": "en", "label": "English"},
    {"code": "sl", "label": "Slovenčina"},
]

# 카테고리 이름 → canonical(영문) 매핑 — /widget-catalog 응답이 언어별로
# 다른 카테고리명(예: '데이터', 'Podatki')으로 와도 admin_settings.menu 의
# 영문 키와 매칭되도록 정규화.
# 2026-05-29: addon 카테고리(Phase 3/4) 도 한국어 별칭 추가. 컨테이너 안에서
# 일부 addon 위젯이 한국어 category 명으로 등록되는 경우(영문/한국어 듀플) 가
# 발견되어, 한국어 버전도 동일 canonical 로 매칭해 메뉴 필터가 정상 작동하도록 함.
_ADMIN_CAT_LOCALES = {
    # ── Phase 1·2 (내장 카테고리) ─────────────────────────────────────────
    "Data": ["Data", "데이터", "Podatki"],
    "Transform": ["Transform", "변환", "Predelava podatkov"],
    "Visualize": ["Visualize", "시각화", "Vizualizacija"],
    "Model": ["Model", "모델"],
    "Evaluate": ["Evaluate", "평가", "Vrednotenje"],
    "Unsupervised": ["Unsupervised", "비지도", "비지도학습",
                     "Nenadzorovano", "Nenadzorovano učenje"],
    "Image Analytics": ["Image Analytics", "이미지 분석", "Analiza slik"],
    "Network": ["Network", "네트워크", "Mreže"],
    "Time Series": ["Time Series", "시계열", "Časovne serije"],
    "Text Mining": ["Text Mining", "텍스트 마이닝", "Rudarjenje besedil"],
    "Geo": ["Geo", "지리", "Geografija"],
    # ── Phase 3 (3차 시범 서비스 addon) ───────────────────────────────────
    "Single Cell":       ["Single Cell", "단일 세포"],
    "Spectroscopy":      ["Spectroscopy", "분광학"],
    "Bioinformatics":    ["Bioinformatics", "생물정보학"],
    "Survival Analysis": ["Survival Analysis", "생존 분석"],
    "Fairness":          ["Fairness", "공정성"],
    # ── Phase 4 (4차 시범 서비스 addon) ───────────────────────────────────
    "Explain":           ["Explain", "설명"],
    "Educational":       ["Educational", "교육"],
    "Associate":         ["Associate", "연관 규칙"],
    "Textable":          ["Textable", "텍스트 처리"],
    "Pumice":            ["Pumice"],
    "World Happiness":   ["World Happiness", "세계 행복지수"],
    "SNOM":              ["SNOM"],
}
_ADMIN_CAT_ALIASES: dict[str, str] = {}
for _canon, _aliases in _ADMIN_CAT_LOCALES.items():
    for _a in _aliases:
        _ADMIN_CAT_ALIASES[_a] = _canon
for _c in _ADMIN_KNOWN_CATEGORIES:
    _ADMIN_CAT_ALIASES.setdefault(_c, _c)


# ready splash 환영 메시지 기본값 — admin 페이지 placeholder 와 WRAPPER_PAGE
# 에서 동일하게 참조. 빈 문자열로 저장하면 해당 언어 사용자에게 비노출.
_SPLASH_READY_DEFAULT_MSGS = {
    "ko": "오렌지3(Orange3) 기반의 웹 머신러닝·데이터 분석 실습 환경",
    "en": "Web-based machine learning & data analysis platform powered by Orange3",
    "sl": "Spletno okolje za strojno učenje in analizo podatkov, ki temelji na Orange3",
}


def _admin_default_settings() -> dict:
    return {
        "menu": {name: True for name in _ADMIN_KNOWN_CATEGORIES},
        "languages": {
            "available": ["ko", "en", "sl"],
            "default": "en",
        },
        # 워밍풀 사용자 조정값. None → env 기본값(=MAX) 그대로 사용.
        "pools": {
            "main": None,   # noVNC 운영 풀 (WARM_POOL_SIZE)
            "xpra": None,   # Xpra 시범 풀 (XPRA_WARM_POOL_SIZE)
        },
        # 위젯 단위 가시성: { "Data": {"File": True, "Datasets": False, ...}, ... }
        # 카테고리 키는 canonical 영문명 (menu 와 동일). 빈 dict 면 모두 visible.
        "widgets": {},
        # 로딩/완료 splash 설정 (2026-05-25)
        # loading: Orange3 부팅 중 표시되는 splash (add-on 리스트 등) — bool 토글
        # ready: 로딩 완료 후 표시되는 환영 카드 — enabled 토글 + 언어별 메시지.
        #   - enabled=False → 모든 사용자에게 비노출
        #   - enabled=True + 해당 언어 메시지 빈 문자열 → 그 언어 사용자에겐 비노출
        "splashes": {
            "loading": True,
            "ready": {"enabled": True, **_SPLASH_READY_DEFAULT_MSGS},
        },
        "updated_at": "",
    }


def _admin_load_settings() -> dict:
    """파일에서 로드, 없으면 default 생성 후 반환. 잘못된 JSON 은 default."""
    import json as _json
    # 런타임 파일 없음 → 커밋된 기본 설정(admin_settings.default.json)에서 1회 시드 (A안)
    if not os.path.isfile(ADMIN_SETTINGS_PATH):
        try:
            if ADMIN_SETTINGS_DEFAULT_PATH and os.path.isfile(ADMIN_SETTINGS_DEFAULT_PATH):
                os.makedirs(os.path.dirname(ADMIN_SETTINGS_PATH), exist_ok=True)
                import shutil as _sh
                _sh.copyfile(ADMIN_SETTINGS_DEFAULT_PATH, ADMIN_SETTINGS_PATH)
                log.info(f"[admin-settings] 런타임 설정 없음 → 기본값 시드: {ADMIN_SETTINGS_DEFAULT_PATH}")
        except Exception as _se:
            log.warning(f"[admin-settings] 기본값 시드 실패: {_se}")
    if not os.path.isfile(ADMIN_SETTINGS_PATH):
        return _admin_default_settings()
    try:
        with open(ADMIN_SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = _json.load(f)
        # 누락 키 보충 — 신규 카테고리 추가 시 default True 로 자동 포함
        defaults = _admin_default_settings()
        menu = data.get("menu") or {}
        for name in _ADMIN_KNOWN_CATEGORIES:
            menu.setdefault(name, True)
        data["menu"] = menu
        langs = data.get("languages") or {}
        langs.setdefault("available", defaults["languages"]["available"])
        langs.setdefault("default", defaults["languages"]["default"])
        data["languages"] = langs
        pools = data.get("pools") or {}
        pools.setdefault("main", None)
        pools.setdefault("xpra", None)
        data["pools"] = pools
        widgets = data.get("widgets") or {}
        if not isinstance(widgets, dict):
            widgets = {}
        data["widgets"] = widgets
        splashes = data.get("splashes") or {}
        if not isinstance(splashes, dict):
            splashes = {}
        splashes.setdefault("loading", True)
        # ready 필드 마이그레이션 (2026-05-25):
        #   bool         → {enabled: bool, <기본 메시지 또는 빈 메시지>}
        #   dict (구버전, 메시지만)  → {enabled: True, <언어별 메시지>}
        #   dict (신버전, enabled+메시지) → 그대로, 누락 키 보충
        ready_v = splashes.get("ready")
        if isinstance(ready_v, bool):
            msgs = (dict(_SPLASH_READY_DEFAULT_MSGS) if ready_v
                    else {k: "" for k in _SPLASH_READY_DEFAULT_MSGS})
            ready_v = {"enabled": bool(ready_v), **msgs}
        elif isinstance(ready_v, dict):
            enabled = ready_v.get("enabled", True)
            msgs = {k: (str(ready_v.get(k, "")) if ready_v.get(k) is not None else "")
                    for k in _SPLASH_READY_DEFAULT_MSGS}
            ready_v = {"enabled": bool(enabled), **msgs}
        else:
            ready_v = {"enabled": True, **_SPLASH_READY_DEFAULT_MSGS}
        splashes["ready"] = ready_v
        data["splashes"] = splashes
        return data
    except Exception as e:
        log.warning(f"[admin-settings] load failed: {e}; fallback default")
        return _admin_default_settings()


def _admin_save_settings(data: dict) -> None:
    """JSON 저장 — 디렉토리 미존재 시 생성. 원자 쓰기(write+rename) 로 corruption 방지."""
    import json as _json
    from datetime import datetime as _dt
    os.makedirs(os.path.dirname(ADMIN_SETTINGS_PATH), exist_ok=True)
    data["updated_at"] = _dt.utcnow().isoformat(timespec="seconds") + "Z"
    tmp = ADMIN_SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        _json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, ADMIN_SETTINGS_PATH)


@app.get("/api/admin/settings")
async def admin_settings_get():
    """현재 관리자 설정 JSON + 알려진 카테고리/언어 메타 반환."""
    return JSONResponse({
        "ok": True,
        "settings": _admin_load_settings(),
        "known_categories": _ADMIN_KNOWN_CATEGORIES,
        "category_phases": _ADMIN_CATEGORY_PHASES,
        "known_languages": _ADMIN_KNOWN_LANGS,
    })


@app.put("/api/admin/settings")
async def admin_settings_put(request: Request):
    """관리자 설정 저장. body schema:
       { menu: {Data:bool, ...}, languages: {available:[codes], default:code} }
       — 잘못된 키/값은 거부, 유효 필드만 반영.
    """
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid json: {e}"},
                            status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "error": "body must be object"},
                            status_code=400)
    # 검증 + 화이트리스트 적용
    cur = _admin_load_settings()
    menu_in = body.get("menu") or {}
    if isinstance(menu_in, dict):
        new_menu = {}
        for name in _ADMIN_KNOWN_CATEGORIES:
            v = menu_in.get(name)
            new_menu[name] = bool(v) if v is not None else cur["menu"].get(name, True)
        cur["menu"] = new_menu
    lang_in = body.get("languages") or {}
    if isinstance(lang_in, dict):
        valid_codes = {l["code"] for l in _ADMIN_KNOWN_LANGS}
        avail = lang_in.get("available")
        if isinstance(avail, list):
            avail = [c for c in avail if isinstance(c, str) and c in valid_codes]
            if avail:
                cur["languages"]["available"] = avail
        default = lang_in.get("default")
        if isinstance(default, str) and default in valid_codes:
            # default 는 반드시 available 안에 포함되어야 함
            if default in cur["languages"]["available"]:
                cur["languages"]["default"] = default
    # splashes: { "loading": bool, "ready": {ko:str, en:str, sl:str} }
    # ready 는 언어별 환영 메시지. 빈 문자열이면 해당 언어 사용자에게 비노출.
    sp_in = body.get("splashes")
    if isinstance(sp_in, dict):
        cur_sp = cur.get("splashes") or {}
        if "loading" in sp_in:
            cur_sp["loading"] = bool(sp_in["loading"])
        if "ready" in sp_in:
            ready_in = sp_in["ready"]
            cur_ready = cur_sp.get("ready") if isinstance(cur_sp.get("ready"), dict) \
                        else {"enabled": True, **_SPLASH_READY_DEFAULT_MSGS}
            cur_ready.setdefault("enabled", True)
            if isinstance(ready_in, dict):
                if "enabled" in ready_in:
                    cur_ready["enabled"] = bool(ready_in["enabled"])
                for k in _SPLASH_READY_DEFAULT_MSGS:
                    if k in ready_in:
                        v = ready_in[k]
                        cur_ready[k] = str(v).strip() if v is not None else ""
            elif isinstance(ready_in, bool):
                cur_ready["enabled"] = bool(ready_in)
            cur_sp["ready"] = cur_ready
        cur["splashes"] = cur_sp
    # widgets: { "Data": {"File": true, ...}, ... } — 카테고리별 부분 업데이트 지원
    widgets_in = body.get("widgets")
    if isinstance(widgets_in, dict):
        cur_w = cur.get("widgets") or {}
        for cat, wmap in widgets_in.items():
            if not isinstance(cat, str) or not isinstance(wmap, dict):
                continue
            canon = _ADMIN_CAT_ALIASES.get(cat, cat)
            cur_w[canon] = {
                str(wname): bool(v) for wname, v in wmap.items()
                if isinstance(wname, str)
            }
        cur["widgets"] = cur_w
    try:
        _admin_save_settings(cur)
    except Exception as e:
        log.warning(f"[admin-settings] save failed: {e}")
        return JSONResponse({"ok": False, "error": f"save failed: {e}"},
                            status_code=500)
    log.info(f"[admin-settings] saved by {request.client.host if request.client else '?'}")
    return JSONResponse({"ok": True, "settings": cur})


# ── 위젯 카탈로그 캐시 + admin 위젯 가시성 API (2026-05-24) ───────────────────
# admin/widgets 페이지가 모든 카테고리·위젯 목록을 보여주려면 워밍풀 컨테이너
# 에서 한 번 가져와 호스트에 캐시. registry-cache 는 변경 거의 없어 long TTL.
ADMIN_WIDGET_CATALOG_PATH = os.path.join(
    CONTAINER_SESSIONS_PATH, "admin_widget_catalog.json")


async def _fetch_widget_catalog_via_warm() -> dict | None:
    """워밍풀에서 컨테이너 하나 빌려 widget-catalog 한 번 가져온 뒤 캐시.
    워밍풀에서 pop 하지 않고 그냥 살아있는 컨테이너 ID 로 직접 신호 파일 작성.
    호출 비용 ~5-15초 (Orange3 main thread busy 시 더). 결과는 long-lived 캐시."""
    import json as _json
    # 살아있는 xpra 워밍 sid 하나 선택 (xpra_warm_pool 에서)
    with _xpra_lock:
        sid = _xpra_warm_pool[0] if _xpra_warm_pool else None
    if not sid:
        # 없으면 일반 noVNC 워밍풀에서
        with _warm_lock:
            sid = _warm_pool[0] if _warm_pool else None
    if not sid:
        return None
    sess_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)
    query_path    = os.path.join(sess_dir, ".widget_catalog_query")
    response_path = os.path.join(sess_dir, ".widget_catalog.json")
    try:
        if os.path.isfile(response_path):
            os.remove(response_path)
    except OSError:
        pass
    try:
        os.makedirs(sess_dir, exist_ok=True)
        with open(query_path, "w") as f:
            f.write("1")
    except OSError as e:
        log.warning(f"[admin-widget-catalog] signal write failed: {e}")
        return None
    # 응답 대기 — 워밍풀은 이미 부팅 끝났으니 빠름 (보통 1-3s)
    deadline = time.time() + 20.0
    while time.time() < deadline:
        if os.path.isfile(response_path):
            try:
                with open(response_path, "r", encoding="utf-8") as f:
                    return _json.load(f)
            except Exception as e:
                log.warning(f"[admin-widget-catalog] parse failed: {e}")
                return None
        await asyncio.sleep(0.15)
    return None


def _save_admin_widget_catalog(data: dict) -> None:
    import json as _json
    from datetime import datetime as _dt
    data["cached_at"] = _dt.utcnow().isoformat(timespec="seconds") + "Z"
    tmp = ADMIN_WIDGET_CATALOG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        _json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, ADMIN_WIDGET_CATALOG_PATH)


def _load_admin_widget_catalog() -> dict | None:
    import json as _json
    if not os.path.isfile(ADMIN_WIDGET_CATALOG_PATH):
        return None
    try:
        with open(ADMIN_WIDGET_CATALOG_PATH, "r", encoding="utf-8") as f:
            return _json.load(f)
    except Exception:
        return None


@app.get("/api/admin/widgets")
async def admin_widgets_get(refresh: int = 0):
    """admin/widgets 페이지용. 위젯 카탈로그(카테고리별 위젯 목록) + 현재
    visibility 설정 반환. refresh=1 이면 캐시 무시 후 워밍풀에서 재조회."""
    cat = _load_admin_widget_catalog() if not refresh else None
    if cat is None:
        cat = await _fetch_widget_catalog_via_warm()
        if cat is None:
            return JSONResponse({
                "ok": False,
                "error": "no warm container available — try again in a moment",
            }, status_code=503)
        try:
            _save_admin_widget_catalog(cat)
        except Exception as _e:
            log.warning(f"[admin-widgets] cache save failed: {_e}")
    settings = _admin_load_settings()
    widgets_vis = settings.get("widgets") or {}
    menu_vis = settings.get("menu") or {}
    # 카테고리별 위젯 + 현재 visibility 정리. canonical 영문 키 → 데이터.
    cat_map: dict[str, dict] = {}
    for c in cat.get("categories", []):
        cname = c.get("name", "")
        canon = _ADMIN_CAT_ALIASES.get(cname, cname)
        wmap = widgets_vis.get(canon, {}) or {}
        widgets = []
        for w in c.get("widgets", []) or []:
            wname = w.get("name", "")
            qname = w.get("qualified_name", "")
            widgets.append({
                "name": wname,
                "qualified_name": qname,
                "visible": bool(wmap.get(wname, True)),
            })
        # 중복 canonical 처리: 마지막이 덮어쓰지 않게 widgets 병합
        if canon in cat_map:
            cat_map[canon]["widgets"].extend(widgets)
            cat_map[canon]["widget_count"] = len(cat_map[canon]["widgets"])
        else:
            cat_map[canon] = {
                "category_localized": cname,
                "category": canon,
                "widget_count": len(widgets),
                "widgets": widgets,
                # 메뉴 관리에서의 visibility (False 면 카테고리 자체가 사용자에게 숨김)
                "menu_visible": bool(menu_vis.get(canon, True)),
            }
    # 메뉴관리와 동일한 phase 그룹 + 순서로 정렬된 출력 구성
    out_groups = []
    seen = set()
    for ph in _ADMIN_CATEGORY_PHASES:
        items = []
        for name in ph["categories"]:
            if name in cat_map:
                items.append(cat_map[name])
                seen.add(name)
            else:
                # 카탈로그엔 없지만 메뉴엔 있는 카테고리 — 빈 placeholder
                items.append({
                    "category_localized": name,
                    "category": name,
                    "widget_count": 0,
                    "widgets": [],
                    "menu_visible": bool(menu_vis.get(name, True)),
                    "missing_in_catalog": True,
                })
                seen.add(name)
        out_groups.append({
            "phase": ph["phase"],
            "title": ph["title"],
            "categories": items,
        })
    # phase 미정의 카테고리 (Orange Obsolete 등) — "기타" 그룹
    others = [v for k, v in cat_map.items() if k not in seen]
    if others:
        out_groups.append({
            "phase": 0,
            "title": "기타",
            "categories": others,
        })
    return JSONResponse({
        "ok": True,
        "language": cat.get("language"),
        "cached_at": cat.get("cached_at"),
        "phase_groups": out_groups,
    })


# ── 세션 메타 패널 (Orange 버전 / 활성 위젯 수 / 제공방식) ──────────────────
# WRAPPER_PAGE 좌하단 정보 패널이 호출. 버전은 워밍풀 컨테이너에서 1회 조회해
# 메모리 캐시 (이미지 lifetime 동안 변경 없음).

_orange_version_cache: dict = {"v": None, "ts": 0.0}


def _exec_orange_version_in_container(container_id: str) -> str | None:
    """docker-py 로 컨테이너 내 Orange 버전 조회. 실패 시 None.
    (session-manager 안엔 docker CLI 가 없어 subprocess 대신 socket 사용.)"""
    try:
        c = client.containers.get(container_id)
        rc, out = c.exec_run(
            ["python3", "-c", "import Orange; print(Orange.__version__)"],
            demux=False,
        )
        if rc == 0:
            if isinstance(out, (bytes, bytearray)):
                out = out.decode("utf-8", errors="replace")
            v = (out or "").strip()
            return v or None
    except Exception as e:
        log.warning(f"[meta] orange version exec failed: {e}")
        return None
    return None


async def _get_orange_version() -> str:
    """워밍풀 컨테이너에서 Orange.__version__ 한 번 조회 후 캐시.
    1시간 TTL. 캐시 실패 시 "—" 반환."""
    import time as _t
    if _orange_version_cache["v"] and (_t.time() - _orange_version_cache["ts"]) < 3600:
        return _orange_version_cache["v"]
    # 컨테이너 id 확보 — main 워밍풀 우선
    cid = None
    try:
        with _warm_lock:
            sid = _warm_pool[0] if _warm_pool else None
        if sid:
            with _lock:
                inf = sessions.get(sid)
                cid = inf.get("container_id") if inf else None
        if not cid:
            with _xpra_lock:
                xsid = _xpra_warm_pool[0] if _xpra_warm_pool else None
            if xsid and xsid in xpra_sessions:
                cid = xpra_sessions[xsid].get("container_id")
    except Exception as e:
        log.warning(f"[meta] cid lookup failed: {e}")
    if cid:
        v = await asyncio.get_event_loop().run_in_executor(
            None, _exec_orange_version_in_container, cid)
        if v:
            _orange_version_cache["v"] = v
            _orange_version_cache["ts"] = _t.time()
            return v
    return _orange_version_cache.get("v") or "—"


def _count_active_widgets() -> int:
    """admin 카탈로그 + admin_settings 기반 활성 위젯 수.
    카탈로그 캐시 없으면 0 반환 (페이지가 ' — ' 로 폴백 표시)."""
    cat = _load_admin_widget_catalog()
    if not cat:
        return 0
    settings = _admin_load_settings()
    widgets_vis = settings.get("widgets") or {}
    menu_vis = settings.get("menu") or {}
    count = 0
    for c in cat.get("categories", []) or []:
        cname = c.get("name", "")
        canon = _ADMIN_CAT_ALIASES.get(cname, cname)
        if not menu_vis.get(canon, True):
            continue
        wmap = widgets_vis.get(canon) or {}
        for w in (c.get("widgets") or []):
            wname = w.get("name", "")
            if wmap.get(wname, True):
                count += 1
    return count


@app.get("/api/session/meta")
async def session_meta(engine: str = "basic"):
    """WRAPPER_PAGE 좌하단 패널이 호출.
    engine: "basic" (noVNC) | "pilot" (Xpra). 기타 값은 basic 으로 정규화."""
    eng = "Pilot" if engine.lower() in ("pilot", "xpra") else "Basic"
    version = await _get_orange_version()
    count = _count_active_widgets()
    return JSONResponse({
        "ok": True,
        "version": version,
        "active_widgets": count,
        "engine": eng,
    })


@app.post("/api/admin/widgets/refresh")
async def admin_widgets_refresh():
    """카탈로그 캐시 강제 재생성 (신규 addon 설치 시 사용)."""
    cat = await _fetch_widget_catalog_via_warm()
    if cat is None:
        return JSONResponse({"ok": False,
            "error": "no warm container available"}, status_code=503)
    try:
        _save_admin_widget_catalog(cat)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"save failed: {e}"},
                            status_code=500)
    # 레지스트리 변경됨 → widget-catalog raw 캐시 무효화 (메모리+디스크, #3)
    _wcat_clear_all()
    return JSONResponse({"ok": True,
        "total_categories": len(cat.get("categories", [])),
        "cached_at": cat.get("cached_at")})


# ── 워밍풀 동적 조정 (2026-05-24) ─────────────────────────────────────────────
# env 의 WARM_POOL_SIZE / XPRA_WARM_POOL_SIZE 는 MAX 로 캡처되어 있고
# 실제 사용값은 admin 페이지에서 0..MAX 범위로 줄일 수 있다. 변경값은
# admin_settings.json 의 "pools" 필드에 영속. 재시작 시 자동 복원.

def _apply_admin_pool_overrides() -> None:
    """startup 또는 PUT 직후 호출 — admin_settings.pools 값을 runtime 변수에 반영."""
    global WARM_POOL_SIZE, WARM_POOL_SIZE_IDLE, XPRA_WARM_POOL_SIZE, XPRA_WARM_POOL_SIZE_IDLE
    s = _admin_load_settings()
    pools = s.get("pools") or {}
    m = pools.get("main")
    if isinstance(m, int) and 0 <= m <= WARM_POOL_SIZE_MAX:
        WARM_POOL_SIZE = m
        if WARM_POOL_SIZE_IDLE > m:
            WARM_POOL_SIZE_IDLE = m
    x = pools.get("xpra")
    if isinstance(x, int) and 0 <= x <= XPRA_WARM_POOL_SIZE_MAX:
        XPRA_WARM_POOL_SIZE = x
        if XPRA_WARM_POOL_SIZE_IDLE > x:
            XPRA_WARM_POOL_SIZE_IDLE = x


@app.get("/api/admin/pool")
async def api_admin_pool_get():
    """현재 풀 상태 + 상한(MAX). admin/sessions 페이지가 조회."""
    return JSONResponse({
        "ok": True,
        "main": {
            "current": WARM_POOL_SIZE,
            "current_idle": WARM_POOL_SIZE_IDLE,
            "max": WARM_POOL_SIZE_MAX,
            "in_pool": len(_warm_pool),
            "in_flight": _warm_inflight,
            "effective_target": _effective_pool_size(),
        },
        "xpra": {
            "current": XPRA_WARM_POOL_SIZE,
            "current_idle": XPRA_WARM_POOL_SIZE_IDLE,
            "max": XPRA_WARM_POOL_SIZE_MAX,
            "in_pool": len(_xpra_warm_pool),
            "in_flight": _xpra_warm_inflight,
            "effective_target": _xpra_effective_pool_size(),
        },
    })


@app.put("/api/admin/pool")
async def api_admin_pool_put(request: Request):
    """풀 크기 변경. body: {"main": int|null, "xpra": int|null}
       null 또는 키 누락 → 해당 풀 변경 없음. 값은 0..MAX 범위만 수용.
       MAX 초과 또는 음수면 400.
    """
    global WARM_POOL_SIZE, WARM_POOL_SIZE_IDLE, XPRA_WARM_POOL_SIZE
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid json: {e}"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "error": "body must be object"}, status_code=400)
    cur = _admin_load_settings()
    pools = cur.get("pools") or {"main": None, "xpra": None}
    # main
    if "main" in body and body["main"] is not None:
        try:
            n = int(body["main"])
        except (TypeError, ValueError):
            return JSONResponse({"ok": False, "error": "main must be int"}, status_code=400)
        if not (0 <= n <= WARM_POOL_SIZE_MAX):
            return JSONResponse({"ok": False,
                "error": f"main out of range: 0..{WARM_POOL_SIZE_MAX}"}, status_code=400)
        pools["main"] = n
        WARM_POOL_SIZE = n
        if WARM_POOL_SIZE_IDLE > n:
            WARM_POOL_SIZE_IDLE = n
    # xpra
    if "xpra" in body and body["xpra"] is not None:
        try:
            n = int(body["xpra"])
        except (TypeError, ValueError):
            return JSONResponse({"ok": False, "error": "xpra must be int"}, status_code=400)
        if not (0 <= n <= XPRA_WARM_POOL_SIZE_MAX):
            return JSONResponse({"ok": False,
                "error": f"xpra out of range: 0..{XPRA_WARM_POOL_SIZE_MAX}"}, status_code=400)
        pools["xpra"] = n
        XPRA_WARM_POOL_SIZE = n
    cur["pools"] = pools
    try:
        _admin_save_settings(cur)
    except Exception as e:
        log.warning(f"[admin-pool] save failed: {e}")
        return JSONResponse({"ok": False, "error": f"save failed: {e}"}, status_code=500)
    # 변경 후 워밍풀 자동 재조정: 새로 줄였으면 cleanup_loop 가 잉여 컨테이너 제거.
    # 늘렸으면 즉시 _replenish 호출.
    try:
        if WARM_POOL_SIZE > len(_warm_pool) + _warm_inflight:
            asyncio.create_task(_replenish_pool())
        if XPRA_WARM_POOL_SIZE > len(_xpra_warm_pool) + _xpra_warm_inflight:
            asyncio.create_task(_xpra_replenish_pool())
    except Exception:
        pass
    log.info(f"[admin-pool] main={WARM_POOL_SIZE}/{WARM_POOL_SIZE_MAX} "
             f"xpra={XPRA_WARM_POOL_SIZE}/{XPRA_WARM_POOL_SIZE_MAX} "
             f"by {request.client.host if request.client else '?'}")
    return JSONResponse({
        "ok": True,
        "main": {"current": WARM_POOL_SIZE, "max": WARM_POOL_SIZE_MAX},
        "xpra": {"current": XPRA_WARM_POOL_SIZE, "max": XPRA_WARM_POOL_SIZE_MAX},
    })


@app.get("/api/admin/nginx")
async def api_admin_nginx_get():
    """Nginx 리버스 프록시 상태 조회 — admin/sessions 페이지가 표시.
    구성: docker-compose.nginx.yml (opt-in 오버레이)
    역할: 정적 자산 alias + reverse proxy (포트 8889 → upstream session-manager:8080)
    반환: 실행 여부, 컨테이너 정보, 호스트/내부 포트, 헬스, 업타임.
    """
    info: dict = {"ok": True, "running": False, "container_name": "orange3-nginx"}
    if client is None:
        info["error"] = "docker client 미설정"
        return JSONResponse(info)
    try:
        try:
            c = await asyncio.get_event_loop().run_in_executor(
                None, lambda: client.containers.get("orange3-nginx"))
        except Exception:
            return JSONResponse(info)
        await asyncio.get_event_loop().run_in_executor(None, c.reload)
        attrs = c.attrs or {}
        state = attrs.get("State") or {}
        info["running"] = bool(state.get("Running"))
        info["status"] = state.get("Status", "?")
        # 헬스체크 (compose 에서 healthcheck 정의됨)
        hc = (state.get("Health") or {}).get("Status")
        info["healthy"] = (hc == "healthy") if hc else None
        info["health_status"] = hc or "—"
        # 가동시간 (StartedAt ISO 8601)
        started = state.get("StartedAt", "")
        if started:
            try:
                from datetime import datetime as _dt, timezone as _tz
                # docker 는 "2026-05-29T00:43:32.123456789Z" 형식 → 나노초 제거
                s = started.split(".")[0].rstrip("Z")
                dt = _dt.fromisoformat(s).replace(tzinfo=_tz.utc)
                info["started_at"] = started
                info["uptime_sec"] = int(
                    (_dt.now(_tz.utc) - dt).total_seconds())
            except Exception:
                pass
        # 포트 매핑 (예: 8889 → 80)
        ports = (attrs.get("NetworkSettings") or {}).get("Ports") or {}
        host_port = None
        for cont_port, bindings in ports.items():
            if cont_port.startswith("80/") and bindings:
                try:
                    host_port = int(bindings[0].get("HostPort"))
                    break
                except Exception:
                    pass
        info["internal_port"] = 80
        info["host_port"] = host_port
        # 이미지
        info["image"] = (attrs.get("Config") or {}).get("Image", "?")
        # Upstream — nginx.conf 에 하드코딩된 값
        info["upstream"] = "orange3-session-manager:8080"

        # 풀 수(upstream 블록 개수) + 접속 수(stub_status) — nginx 컨테이너 내부 조회
        def _nginx_pools_conns():
            import re as _re
            pools_n = conns = None
            extra: dict = {}
            try:
                rc, out = c.exec_run(
                    ["sh", "-c", "grep -cE '^[[:space:]]*upstream ' /etc/nginx/nginx.conf"])
                if rc == 0:
                    pools_n = int(out.decode().strip())
            except Exception:
                pass
            try:
                rc, out = c.exec_run(["wget", "-qO-", "http://127.0.0.1/nginx-status"])
                txt = out.decode() if rc == 0 else ""
                m = _re.search(r"Active connections:\s*(\d+)", txt)
                if m:
                    conns = int(m.group(1))
                m2 = _re.search(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)", txt)
                if m2:
                    extra = {"reading": int(m2.group(1)), "writing": int(m2.group(2)),
                             "waiting": int(m2.group(3))}
            except Exception:
                pass
            return pools_n, conns, extra
        try:
            _p, _conn, _extra = await asyncio.get_event_loop().run_in_executor(
                None, _nginx_pools_conns)
            info["pools"] = _p
            info["active_connections"] = _conn
            if _extra:
                info["conn_detail"] = _extra
        except Exception:
            info["pools"] = info["active_connections"] = None

        return JSONResponse(info)
    except Exception as e:
        log.warning(f"[admin-nginx] 조회 실패: {e}")
        info["error"] = str(e)
        return JSONResponse(info)


@app.post("/api/admin/nginx/reload")
async def api_admin_nginx_reload(request: Request):
    """Nginx 설정 핫리로드 — `nginx -s reload` 실행.
    호스트 nginx/nginx.conf 변경 후 컨테이너 재시작 없이 적용 가능."""
    if client is None:
        return JSONResponse({"ok": False, "error": "docker client 미설정"},
                            status_code=500)
    try:
        c = await asyncio.get_event_loop().run_in_executor(
            None, lambda: client.containers.get("orange3-nginx"))
    except Exception:
        return JSONResponse({"ok": False, "error": "nginx 컨테이너 없음"},
                            status_code=404)
    try:
        # 1) 설정 검증
        rc, out = await asyncio.get_event_loop().run_in_executor(
            None, lambda: c.exec_run(["nginx", "-t"], demux=False))
        if rc != 0:
            return JSONResponse({
                "ok": False,
                "error": "nginx -t 실패",
                "detail": (out or b"").decode("utf-8", "replace")[:500],
            }, status_code=400)
        # 2) 리로드
        rc2, out2 = await asyncio.get_event_loop().run_in_executor(
            None, lambda: c.exec_run(["nginx", "-s", "reload"], demux=False))
        if rc2 != 0:
            return JSONResponse({
                "ok": False,
                "error": "nginx -s reload 실패",
                "detail": (out2 or b"").decode("utf-8", "replace")[:500],
            }, status_code=500)
        log.info(f"[admin-nginx] reload 성공 "
                 f"by {request.client.host if request.client else '?'}")
        return JSONResponse({"ok": True, "message": "Nginx 설정 리로드 완료"})
    except Exception as e:
        log.warning(f"[admin-nginx] reload 실패: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/admin/sessions/terminate-all")
async def api_admin_terminate_all(request: Request):
    """일괄 종료. body: {"kind": "main" | "xpra"}
       main → noVNC 운영 세션 전체 (sessions[] 안 항목 모두 remove_session).
       xpra → xpra 컨테이너 전체 종료 (사용자 세션 + 워밍풀 포함).
       관리자 보호: request.client.host 와 동일 IP 로 바인딩된 세션은 스킵
       (관리자가 자신의 Orange3 세션을 함께 죽이지 않도록).
    """
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"invalid json: {e}"}, status_code=400)
    kind = (body or {}).get("kind")
    if kind not in ("main", "xpra"):
        return JSONResponse({"ok": False, "error": "kind must be 'main' or 'xpra'"},
                            status_code=400)
    admin_ip = request.client.host if request.client else None
    killed: list = []
    skipped: list = []  # 관리자 자신의 세션 보호
    errs: list = []
    if kind == "main":
        with _lock:
            # 운영 noVNC 세션만 대상 — xpra 미러는 별도 분기에서 처리
            sids = [sid for sid, info in sessions.items()
                    if info.get("engine") != "xpra"]
            ip_by_sid = {sid: sessions[sid].get("client_ip") for sid in sids}
        for sid in sids:
            if admin_ip and ip_by_sid.get(sid) == admin_ip:
                skipped.append(sid)
                continue
            try:
                remove_session(sid)
                killed.append(sid)
            except Exception as e:
                errs.append(f"{s8(sid)}: {e}")
        # 워밍풀은 사용자 바인딩 없음 — 안전하게 전체 정리
        with _warm_lock:
            warm_sids = list(_warm_pool)
            _warm_pool.clear()
        for sid in warm_sids:
            try:
                remove_session(sid)
                killed.append(sid)
            except Exception as e:
                errs.append(f"warm {s8(sid)}: {e}")
    else:  # xpra
        with _lock:
            ip_by_sid = {sid: info.get("client_ip") for sid, info in sessions.items()}
        with _xpra_lock:
            xsids = list(xpra_sessions.keys())
        for sid in xsids:
            if admin_ip and ip_by_sid.get(sid) == admin_ip:
                skipped.append(sid)
                continue
            try:
                info = xpra_sessions.get(sid)
                if info:
                    try:
                        c = client.containers.get(info["container_id"])
                        c.stop(timeout=3)
                        c.remove()
                    except Exception:
                        pass
                with _xpra_lock:
                    xpra_sessions.pop(sid, None)
                with _lock:
                    sessions.pop(sid, None)
                killed.append(sid)
            except Exception as e:
                errs.append(f"{s8(sid)}: {e}")
        # 워밍풀 정리 (사용자 바인딩 없음 — 관리자 세션 영향 없음)
        with _xpra_lock:
            _xpra_warm_pool.clear()
    log.info(f"[admin-terminate-all] kind={kind} killed={len(killed)} "
             f"skipped(admin)={len(skipped)} errors={len(errs)} "
             f"admin_ip={admin_ip} by {admin_ip or '?'}")
    # 종료 후 즉시 풀 보충 트리거
    try:
        if kind == "main" and WARM_POOL_SIZE > 0:
            asyncio.create_task(_replenish_pool())
        elif kind == "xpra" and XPRA_WARM_POOL_SIZE > 0:
            asyncio.create_task(_xpra_replenish_pool())
    except Exception:
        pass
    return JSONResponse({"ok": True, "kind": kind,
                         "killed": len(killed),
                         "skipped_admin": len(skipped),
                         "admin_ip": admin_ip,
                         "errors": errs[:10]})


# ── 관리자 페이지 공통 chrome (3-탭: 메뉴 관리 / 언어 설정 / 활성 세션) ────────
_ADMIN_BASE_CSS = """
body{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Malgun Gothic",sans-serif;background:#fafafa;color:#1a1a1c}
.wrap{max-width:880px;margin:30px auto;padding:0 20px 40px}
h1{font-size:22px;margin:0 0 6px;color:#1a1a1c}
.sub{font-size:13px;color:#6b7280;margin-bottom:24px}
.sub-bullets{margin:0 0 24px 0;padding-left:20px;line-height:1.65}
.sub-bullets li{margin:0}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:22px 26px;margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,0.03)}
h2{font-size:16px;margin:0 0 4px;color:#1a1a1c}
.section-desc{font-size:12.5px;color:#6b7280;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px 18px}
@media (max-width:680px){.grid{grid-template-columns:repeat(2,1fr)}}
.row{display:flex;align-items:center;gap:8px;padding:6px 4px;border-radius:6px}
.row:hover{background:#f5f5f7}
.row label{cursor:pointer;font-size:13.5px;flex:1;user-select:none}
.row input[type=checkbox],.row input[type=radio]{cursor:pointer;width:16px;height:16px;flex-shrink:0}
#menu-grid{display:block}
.phase-group .grid{grid-template-columns:repeat(auto-fill,minmax(170px,1fr))}
.phase-group{margin-bottom:18px;padding:12px 14px;border:2px solid #e5e7eb;border-radius:8px;background:#fafafb}
.phase-group:last-child{margin-bottom:0}
/* 단계별 컬러 배경 제거 → 회색으로 통일 (2026-05-30) */
.phase-group.phase-1,.phase-group.phase-2,.phase-group.phase-3,.phase-group.phase-4{border-color:#e5e7eb;background:#fafafb}
.phase-title{font-size:13.5px;font-weight:700;margin:0 0 10px;display:flex;align-items:center;gap:8px}
.phase-1 .phase-title,.phase-2 .phase-title,.phase-3 .phase-title,.phase-4 .phase-title{color:#4b5563}
.phase-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;background:#fff;border:1px solid currentColor}
.lang-row{display:flex;align-items:center;gap:14px;padding:8px 4px;border-radius:6px}
.lang-row:hover{background:#f5f5f7}
.lang-chk,.lang-def{display:flex;align-items:center;gap:6px;font-size:13.5px;cursor:pointer;user-select:none}
.lang-label{flex:1;font-size:14px;font-weight:500}
.lang-hdr{display:grid;grid-template-columns:1fr auto auto;gap:24px;padding:8px 4px;font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:0.4px;border-bottom:1px solid #e5e7eb;margin-bottom:6px}
.lang-list .lang-row{display:grid;grid-template-columns:1fr auto auto;gap:24px;align-items:center}
.actions{display:flex;gap:10px;justify-content:flex-end;margin-top:8px;padding-top:18px;border-top:1px solid #ececef;background:#fff;position:sticky;bottom:0}
button{padding:10px 22px;border-radius:7px;border:1px solid #e5e7eb;background:#fff;color:#1a1a1c;cursor:pointer;font-size:13.5px;font-weight:600}
button:hover{background:#f5f5f7}
button.primary{background:#F47B20;color:#fff;border-color:#F47B20}
button.primary:hover{background:#d96b10}
button:disabled{opacity:0.55;cursor:not-allowed}
.toast{position:fixed;left:50%;bottom:30px;transform:translateX(-50%) translateY(20px);background:#1a1a1c;color:#fff;padding:10px 18px;border-radius:8px;font-size:13.5px;opacity:0;transition:all .25s;pointer-events:none;z-index:9999}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
.meta{margin-top:18px;font-size:11.5px;color:#9ca3af;font-family:Consolas,monospace}
.quick-bar{display:flex;gap:8px;margin-bottom:14px}
.quick-bar button{padding:5px 12px;font-size:12px;font-weight:500}
/* 전체 선택/해제 버튼을 제목 줄 오른쪽으로 정렬 (2026-05-30) */
.menu-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.menu-head .quick-bar{margin-bottom:0;flex-shrink:0}
.phase-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:10px}
.phase-head .phase-title{margin:0}
.phase-head .quick-bar{margin-bottom:0;flex-shrink:0}
.admin-tabs{display:flex;gap:0;border-bottom:1px solid #e5e7eb;margin:0 0 24px}
.admin-tabs a{padding:11px 18px;font-size:13.5px;font-weight:600;color:#6b7280;text-decoration:none;border-bottom:2px solid transparent;transition:color .12s,border-color .12s}
.admin-tabs a:hover{color:#1a1a1c}
.admin-tabs a.active{color:#F47B20;border-bottom-color:#F47B20}
.info-note{display:flex;gap:12px;align-items:flex-start;padding:10px 14px;border-radius:7px;margin:0 0 12px;font-size:12.5px;border:1px solid #e5e7eb;background:transparent}
.info-note .info-note-title{flex-shrink:0;font-weight:700;min-width:64px;color:inherit}
.info-note .info-note-body{line-height:1.55;color:inherit}
.info-note.method,.info-note.warn{background:transparent;border-color:#e5e7eb}
.info-note.method .info-note-title,.info-note.warn .info-note-title{color:inherit}
.info-note.warn .info-note-body b{color:inherit;font-weight:700}
/* 위젯 설정 페이지 — 카테고리 카드 + 카드별 저장 버튼 (2026-05-24) */
/* phase-group 안에 wcat-card 가 들어갈 때: 카드 사이 간격 축소 + 배경 투명 */
.phase-group.phase-other{border-color:#e5e7eb;background:#fafafb}
.phase-group.phase-other .phase-title{color:#4b5563}
.phase-group .wcat-card{margin-bottom:8px}
.phase-group .wcat-card:last-child{margin-bottom:0}
.cat-hidden-mark{font-size:11px;color:#9ca3af;font-weight:500}
.cat-missing-mark{font-size:11px;color:#dc2626;font-weight:500;margin-left:4px}
.wcat-card{margin-bottom:14px;border:1px solid #e5e7eb;border-radius:9px;background:#fff;overflow:hidden}
.wcat-head{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none;background:#fafafb;border-bottom:1px solid #ececef}
.wcat-head:hover{background:#f5f5f7}
.wcat-head .wcat-toggle{font-size:11px;color:#9ca3af;width:14px}
.wcat-head .wcat-name{flex:1;font-size:14px;font-weight:700;color:#1a1a1c}
.wcat-head .wcat-count{font-size:12px;color:#6b7280;font-weight:500}
.wcat-head .wcat-dirty{display:none;font-size:11px;color:#F47B20;font-weight:700;padding:2px 8px;border:1px solid #F47B20;border-radius:10px}
.wcat-card.is-dirty .wcat-head .wcat-dirty{display:inline-block}
.wcat-body{padding:14px 16px;display:none}
.wcat-card.is-open .wcat-body{display:block}
.wcat-card.is-open .wcat-toggle::before{content:'▾'}
.wcat-card:not(.is-open) .wcat-toggle::before{content:'▸'}
.wcat-tools{display:flex;gap:6px;margin-bottom:10px}
.wcat-tools button{padding:4px 10px;font-size:12px;font-weight:500;border-radius:5px;border:1px solid #e5e7eb;background:#fff;cursor:pointer}
.wcat-tools button:hover{background:#f5f5f7}
.wcat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:4px 14px}
.wcat-grid .row{padding:4px 4px}
.wcat-grid .row label{font-size:12.5px}
.wcat-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:12px;padding-top:12px;border-top:1px solid #f1f1f3}
.wcat-actions button{padding:6px 14px;font-size:12.5px}
.wcat-empty{padding:24px;text-align:center;color:#9ca3af;font-size:13px}
.wcat-loading{padding:24px;text-align:center;color:#6b7280;font-size:13px}
.wcat-refresh{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.wcat-refresh .cached-at{font-size:11.5px;color:#9ca3af;font-family:Consolas,monospace}
"""

# ── 관리자 Firebase 로그인 UI (2026-05-30) ───────────────────────────────────
# _admin_nav_html() 및 세션 페이지에 주입되어 모든 관리자 페이지를 가린다.
# - Firebase SDK(compat) 로드 + 로그인 오버레이
# - window.fetch 인터셉터: /api/admin/* 요청에 ID 토큰 자동 첨부(기존 fetch 무수정)
# - onAuthStateChanged: 미로그인 시 오버레이로 .wrap 가림
# __FIREBASE_WEB_CONFIG__ 는 _admin_auth_html() 이 env JSON(없으면 null)으로 치환.
# (f-string 아님 — JS 의 중괄호 그대로 사용)
_ADMIN_AUTH_TEMPLATE = """
<style>
#fb-login-overlay{position:fixed;inset:0;z-index:100000;background:#fafafa;display:none;align-items:center;justify-content:center}
#fb-login-card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;box-shadow:0 6px 30px rgba(0,0,0,.08);padding:30px 32px;width:340px;max-width:90vw}
#fb-login-card h2{margin:0 0 4px;font-size:19px;color:#1a1a1c}
#fb-login-card .d{font-size:12.5px;color:#6b7280;margin-bottom:18px}
#fb-login-card .fb-brand{display:flex;flex-direction:row;align-items:center;justify-content:center;gap:10px;margin-bottom:20px}
#fb-login-card .fb-brand img{height:34px;width:auto;object-fit:contain}
#fb-login-card .fb-brand-txt{font-size:20px;font-weight:700;color:#F47B20;letter-spacing:.3px}
#fb-login-card input{width:100%;box-sizing:border-box;padding:10px 12px;margin-bottom:10px;border:1px solid #e5e7eb;border-radius:7px;font-size:14px}
#fb-login-card button{width:100%;padding:11px;background:#fff;color:#1a1a1c;border:1px solid #e5e7eb;border-radius:7px;font-size:14px;font-weight:600;cursor:pointer}
#fb-login-card button:hover{background:#f5f5f7}
#fb-remember-row{display:flex;align-items:center;gap:7px;margin:2px 0 12px;font-size:13px;color:#374151;cursor:pointer;user-select:none}
#fb-remember-row input{width:15px;height:15px;margin:0;cursor:pointer;flex-shrink:0}
#fb-login-err{color:#dc2626;font-size:12.5px;margin-top:10px;min-height:16px}
#fb-logout-btn{position:fixed;top:14px;right:18px;z-index:99999;display:none;padding:6px 14px;font-size:12.5px;font-weight:600;background:#fff;border:1px solid #e5e7eb;border-radius:7px;cursor:pointer;color:#374151}
#fb-logout-btn:hover{background:#f5f5f7}
</style>
<div id="fb-login-overlay"><div id="fb-login-card">
  <div class="fb-brand"><img src="/logo" alt="Orange 3"><span class="fb-brand-txt">Orange 3</span></div>
  <form id="fb-login-form" autocomplete="on">
    <input id="fb-email" type="email" placeholder="이메일" autocomplete="username" maxlength="40" required>
    <input id="fb-pass" type="password" placeholder="비밀번호" autocomplete="current-password" maxlength="40" required>
    <label id="fb-remember-row"><input id="fb-remember" type="checkbox"> 아이디 저장</label>
    <button type="submit">로그인</button>
    <div id="fb-login-err"></div>
  </form>
</div></div>
<button id="fb-logout-btn" onclick="window.__fbLogout&&window.__fbLogout()">로그아웃</button>
<script src="https://www.gstatic.com/firebasejs/10.12.5/firebase-app-compat.js"></script>
<script src="https://www.gstatic.com/firebasejs/10.12.5/firebase-auth-compat.js"></script>
<script>
(function(){
  var cfg = __FIREBASE_WEB_CONFIG__;
  var _state; // true=로그인 표시, false=내용 표시
  function whenReady(fn){ if(document.readyState!=='loading'){ fn(); } else { document.addEventListener('DOMContentLoaded', fn); } }
  function setWrap(vis){ var w=document.querySelector('.wrap'); if(w) w.style.visibility = vis?'visible':'hidden'; }
  function apply(){ if(_state===undefined) return;
    var ov=document.getElementById('fb-login-overlay'); if(ov) ov.style.display = _state?'flex':'none';
    var lo=document.getElementById('fb-logout-btn'); if(lo) lo.style.display = _state?'none':'block';
    setWrap(!_state); }
  if(!cfg || !cfg.apiKey){ console.warn('[admin-auth] Firebase config 미설정 — 로그인 비활성(개발 모드)'); return; }
  if(typeof firebase==='undefined'){ console.error('[admin-auth] Firebase SDK 로드 실패'); return; }
  // 오버레이·로그아웃 버튼은 .wrap 안에 주입되므로, .wrap 을 visibility:hidden 으로
  // 가리면 자식인 오버레이까지 숨겨진다 → body 직속으로 이동시켜 분리.
  whenReady(function(){
    var ov=document.getElementById('fb-login-overlay'), lo=document.getElementById('fb-logout-btn');
    if(ov && ov.parentNode!==document.body) document.body.appendChild(ov);
    if(lo && lo.parentNode!==document.body) document.body.appendChild(lo);
    apply(); // 이동 후 현재 상태 재반영
  });
  setWrap(false); whenReady(function(){ setWrap(false); }); // 인증 확인 전 내용 가림(플래시 방지)
  firebase.initializeApp(cfg);
  var auth = firebase.auth();
  var _of = window.fetch.bind(window);
  // 인증 상태가 처음 확정될 때까지 기다리는 게이트 — reload 직후 세션 복원 전에
  // /api/admin 요청이 토큰 없이 나가 401 나는 레이스 방지.
  var _authResolved=false, _authReadyResolve, _authReady=new Promise(function(r){ _authReadyResolve=r; });
  window.fetch = function(input, init){
    init = init || {};
    var u = (typeof input==='string') ? input : (input && input.url) || '';
    if(u.indexOf('/api/admin')!==-1 || u.indexOf('/admin/sessions/')!==-1){
      return _authReady.then(function(){
        var user = auth.currentUser;
        if(user){ return user.getIdToken().then(function(t){
          init.headers = Object.assign({}, init.headers||{}, {Authorization:'Bearer '+t});
          return _of(input, init); }); }
        return _of(input, init);
      });
    }
    return _of(input, init);
  };
  auth.onAuthStateChanged(function(user){
    _state = !user;
    if(!_authResolved){ _authResolved=true; _authReadyResolve(); }
    whenReady(apply);
  });
  whenReady(function(){
    // 저장된 아이디 불러오기 → 이메일 채우고 체크박스 자동 체크
    try {
      var saved = localStorage.getItem('admin_saved_email') || '';
      if(saved){
        var emEl=document.getElementById('fb-email'); if(emEl) emEl.value=saved;
        var rm=document.getElementById('fb-remember'); if(rm) rm.checked=true;
      }
    } catch(e){}
    var f=document.getElementById('fb-login-form');
    if(f) f.addEventListener('submit', function(e){
      e.preventDefault();
      var em=document.getElementById('fb-email').value.trim(), pw=document.getElementById('fb-pass').value;
      // 아이디 저장 체크 시 이메일 보관, 해제 시 삭제
      try {
        var rmEl=document.getElementById('fb-remember');
        if(rmEl && rmEl.checked) localStorage.setItem('admin_saved_email', em);
        else localStorage.removeItem('admin_saved_email');
      } catch(e2){}
      document.getElementById('fb-login-err').textContent='';
      auth.signInWithEmailAndPassword(em,pw).then(function(){ location.reload(); })
        .catch(function(err){ document.getElementById('fb-login-err').textContent='로그인 실패: '+(err.code||err.message); });
    });
  });
  window.__fbLogout = function(){ auth.signOut().then(function(){ location.reload(); }); };
})();
</script>
"""


def _admin_auth_html() -> str:
    """관리자 페이지에 주입할 Firebase 로그인 블록. FIREBASE_WEB_CONFIG(JSON) 주입.
       config 미설정 시 null → 클라 측 인증 비활성(개발 모드)."""
    cfg = FIREBASE_WEB_CONFIG if FIREBASE_WEB_CONFIG else "null"
    return _ADMIN_AUTH_TEMPLATE.replace("__FIREBASE_WEB_CONFIG__", cfg)


def _admin_nav_html(active: str) -> str:
    """공통 5-탭 nav + Firebase 로그인 블록. active ∈ {'menu','widgets','language','splash','sessions'}."""
    def cls(name): return ' class="active"' if active == name else ''
    return (
        '<nav class="admin-tabs">'
        f'<a href="/admin/menu"{cls("menu")}>메뉴 설정</a>'
        f'<a href="/admin/widgets"{cls("widgets")}>위젯 설정</a>'
        f'<a href="/admin/language"{cls("language")}>언어 설정</a>'
        f'<a href="/admin/splash"{cls("splash")}>로딩 이미지 설정</a>'
        f'<a href="/admin/sessions"{cls("sessions")}>활성 세션</a>'
        '</nav>'
    ) + _admin_auth_html()


@app.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings_legacy():
    """기존 URL 호환 — 메뉴 설정 페이지로 리다이렉트."""
    return RedirectResponse("/admin/menu", status_code=302)


@app.get("/admin/menu", response_class=HTMLResponse)
async def admin_menu_page():
    """메뉴 설정 — 카테고리 노출 여부 + 저장."""
    nav = _admin_nav_html("menu")
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<title>메뉴 설정 — 관리자</title>
<style>{_ADMIN_BASE_CSS}</style></head><body>
<div class="wrap">
  <h1>메뉴 설정</h1>
  <div class="sub">위젯 사이드바·패널에 노출할 메뉴를 선택합니다. 체크 해제 시 모든 사용자에게서 숨김.</div>
  {nav}

  <div class="card">
    <div class="menu-head">
      <div>
        <h2>메뉴 노출 설정</h2>
        <div class="section-desc">시범 서비스 단계별로 그룹화되어 있습니다.</div>
      </div>
      <div class="quick-bar">
        <button onclick="setAllMenu(true)">전체 선택</button>
        <button onclick="setAllMenu(false)">전체 해제</button>
      </div>
    </div>
    <div class="grid" id="menu-grid"></div>
  </div>

  <div class="actions">
    <button onclick="loadMenu()">되돌리기</button>
    <button id="save-btn" onclick="saveMenu()">저장</button>
  </div>

  <div class="meta" id="meta"></div>
</div>
<div class="toast" id="toast"></div>

<script>
let _settings = null, _knownCats = [], _catPhases = [];

function esc(s){{return String(s==null?'':s).replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}})[c]);}}
function toast(msg, ms){{
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(window._tt);
  window._tt = setTimeout(()=>t.classList.remove('show'), ms||2200);
}}

async function loadMenu(){{
  try {{
    const r = await fetch('/api/admin/settings', {{cache:'no-store'}});
    const d = await r.json();
    if (!d.ok) {{ toast('로드 실패'); return; }}
    _settings = d.settings;
    _knownCats = d.known_categories;
    _catPhases = d.category_phases || [];
    renderMenu();
    document.getElementById('meta').textContent = _settings.updated_at
      ? 'updated_at: ' + _settings.updated_at : '(저장 전)';
  }} catch(e) {{ toast('로드 오류: ' + e.message); }}
}}

function renderMenu(){{
  const g = document.getElementById('menu-grid');
  const grouped = new Set();
  let html = '';
  _catPhases.forEach(ph => {{
    html += `<div class="phase-group phase-${{ph.phase}}">
      <div class="phase-head">
        <div class="phase-title"><span class="phase-badge">${{ph.phase}}차</span>${{esc(ph.title)}}</div>
        <div class="quick-bar">
          <button onclick="setPhaseMenu(${{ph.phase}}, true)">전체 선택</button>
          <button onclick="setPhaseMenu(${{ph.phase}}, false)">전체 해제</button>
        </div>
      </div>
      <div class="grid">`;
    ph.categories.forEach(name => {{
      grouped.add(name);
      html += `<div class="row">
        <input type="checkbox" id="cat-${{esc(name)}}" data-phase="${{ph.phase}}" ${{_settings.menu[name] ? 'checked' : ''}}>
        <label for="cat-${{esc(name)}}">${{esc(name)}}</label>
      </div>`;
    }});
    html += `</div></div>`;
  }});
  // Orange Obsolete 계열은 admin 위젯 설정의 "기타" 그룹에도 노출하지 않음 (2026-06-02)
  const _hiddenAdminCats = {{ 'Orange Obsolete': 1, 'Orange 사용 중단됨': 1, 'Zastarelo': 1 }};
  const orphans = _knownCats.filter(n => !grouped.has(n) && !_hiddenAdminCats[n]);
  if (orphans.length) {{
    html += `<div class="phase-group">
      <div class="phase-title">기타</div><div class="grid">`;
    orphans.forEach(name => {{
      html += `<div class="row">
        <input type="checkbox" id="cat-${{esc(name)}}" ${{_settings.menu[name] ? 'checked' : ''}}>
        <label for="cat-${{esc(name)}}">${{esc(name)}}</label>
      </div>`;
    }});
    html += `</div></div>`;
  }}
  g.innerHTML = html;
}}

function setAllMenu(val){{
  document.querySelectorAll('#menu-grid input[type=checkbox]').forEach(cb => {{ cb.checked = val; }});
}}

function setPhaseMenu(phase, val){{
  document.querySelectorAll(`#menu-grid input[type=checkbox][data-phase="${{phase}}"]`).forEach(cb => {{ cb.checked = val; }});
}}

async function saveMenu(){{
  const menu = {{}};
  _knownCats.forEach(name => {{
    const cb = document.getElementById('cat-' + name);
    menu[name] = cb ? cb.checked : true;
  }});
  const btn = document.getElementById('save-btn');
  btn.disabled = true; btn.textContent = '저장 중...';
  try {{
    const r = await fetch('/api/admin/settings', {{
      method:'PUT', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{menu}}),
    }});
    const d = await r.json();
    if (d.ok) {{
      _settings = d.settings;
      document.getElementById('meta').textContent = 'updated_at: ' + _settings.updated_at;
      toast('메뉴 설정 저장 완료');
    }} else {{
      toast('저장 실패: ' + (d.error || 'unknown'));
    }}
  }} catch(e) {{ toast('저장 오류: ' + e.message); }}
  finally {{ btn.disabled = false; btn.textContent = '저장'; }}
}}

loadMenu();
</script>
</body></html>""")


@app.get("/admin/widgets", response_class=HTMLResponse)
async def admin_widgets_page():
    """위젯 설정 — 카테고리별 위젯 가시성 토글. 카드(=카테고리) 단위로 저장."""
    nav = _admin_nav_html("widgets")
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<title>위젯 설정 — 관리자</title>
<style>{_ADMIN_BASE_CSS}</style></head><body>
<div class="wrap">
  <h1>위젯 설정</h1>
  <ul class="sub sub-bullets">
    <li>위젯 비활성화 처리 메뉴</li>
    <li>메뉴별 위젯의 노출 여부를 개별 토글 메뉴</li>
    <li>메뉴 단위로 저장 버튼이 분리되어 있어 변경한 메뉴만 즉시 저장</li>
    <li>위젯을 삭제하는 기능이 아니며, 비활성화(미선택) 기능</li>
    <li>위젯을 완전히 미 노출이 필요한 경우는, 위젯 개별 소스에서 비노출 처리 진행 필요</li>
  </ul>
  {nav}

  <div class="card">
    <div class="wcat-refresh">
      <button onclick="refreshCatalog()">📦 메뉴 불러오기</button>
      <span class="cached-at" id="cached-at">—</span>
    </div>
    <div class="section-desc">위젯 목록은 워밍풀 컨테이너의 Orange3 레지스트리에서 가져옵니다. 신규 addon 설치 후엔 새로고침 필요.</div>
  </div>

  <div id="wcat-list">
    <div class="wcat-loading">로딩 중…</div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
let _groups = [];
let _byCanon = {{}};  // canon → category obj (메모리 reset 용)
let _dirty = {{}};   // {{ canon: true }} — 변경됐지만 미저장인 카테고리

function esc(s){{return String(s==null?'':s).replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}})[c]);}}
function toast(msg, ms){{
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(window._tt);
  window._tt = setTimeout(()=>t.classList.remove('show'), ms||2200);
}}

async function loadCatalog(refresh){{
  const list = document.getElementById('wcat-list');
  list.innerHTML = '<div class="wcat-loading">' + (refresh?'카탈로그 재생성 중…':'로딩 중…') + '</div>';
  try {{
    const url = '/api/admin/widgets' + (refresh ? '?refresh=1' : '');
    const r = await fetch(url, {{cache:'no-store'}});
    const d = await r.json();
    if (!d.ok) {{
      list.innerHTML = '<div class="wcat-empty">카탈로그 로드 실패: ' + esc(d.error||'unknown') + '<br><small>워밍풀이 비어 있으면 잠시 후 새로고침하세요.</small></div>';
      return;
    }}
    _groups = d.phase_groups || [];
    _byCanon = {{}};
    _groups.forEach(g => g.categories.forEach(c => {{ _byCanon[c.category] = c; }}));
    document.getElementById('cached-at').textContent = d.cached_at
      ? ('cached_at: ' + d.cached_at + ' · lang=' + (d.language||'?'))
      : '';
    renderCatalog();
  }} catch(e) {{
    list.innerHTML = '<div class="wcat-empty">오류: ' + esc(e.message) + '</div>';
  }}
}}

async function refreshCatalog(){{
  await loadCatalog(true);
  toast('메뉴 불러오기 완료');
}}

function renderCatalog(){{
  const list = document.getElementById('wcat-list');
  if (!_groups.length) {{ list.innerHTML = '<div class="wcat-empty">카테고리가 비어 있습니다.</div>'; return; }}
  let html = '';
  _groups.forEach(g => {{
    const phaseCls = g.phase ? ('phase-' + g.phase) : 'phase-other';
    const badge = g.phase
      ? `<span class="phase-badge">${{g.phase}}차</span>`
      : '';
    html += `<div class="phase-group ${{phaseCls}}">
      <div class="phase-title">${{badge}}${{esc(g.title)}}</div>`;
    g.categories.forEach(cat => {{
      const canon = cat.category;
      const checked = cat.widgets.filter(w => w.visible).length;
      const total = cat.widgets.length;
      const hiddenMark = cat.menu_visible ? '' : ' <span class="cat-hidden-mark">(미노출)</span>';
      const missingMark = cat.missing_in_catalog ? ' <span class="cat-missing-mark">(카탈로그 없음)</span>' : '';
      const bodyHtml = cat.missing_in_catalog
        ? '<div class="wcat-empty" style="padding:14px">이 카테고리는 현재 워밍풀 컨테이너의 레지스트리에 없습니다. addon 설치 후 카탈로그 새로고침 필요.</div>'
        : `<div class="wcat-tools">
            <button onclick="setAllInCat('${{esc(canon)}}', true)">전체 선택</button>
            <button onclick="setAllInCat('${{esc(canon)}}', false)">전체 해제</button>
          </div>
          <div class="wcat-grid">` +
            cat.widgets.map(w => {{
              const wid = 'w-' + esc(canon) + '-' + esc(w.name);
              return `<div class="row">
                <input type="checkbox" id="${{wid}}" data-canon="${{esc(canon)}}" data-wname="${{esc(w.name)}}"
                       ${{w.visible ? 'checked' : ''}} onchange="markDirty('${{esc(canon)}}')">
                <label for="${{wid}}">${{esc(w.name)}}</label>
              </div>`;
            }}).join('') +
          `</div>
          <div class="wcat-actions">
            <button onclick="resetCat('${{esc(canon)}}')">되돌리기</button>
            <button onclick="saveCat('${{esc(canon)}}')">저장</button>
          </div>`;
      html += `<div class="wcat-card" data-canon="${{esc(canon)}}">
        <div class="wcat-head" onclick="toggleCard('${{esc(canon)}}')">
          <span class="wcat-toggle"></span>
          <span class="wcat-name">${{esc(canon)}}${{hiddenMark}}${{missingMark}}</span>
          <span class="wcat-count" id="cnt-${{esc(canon)}}">${{checked}}/${{total}} 노출</span>
          <span class="wcat-dirty">변경됨</span>
        </div>
        <div class="wcat-body">${{bodyHtml}}</div>
      </div>`;
    }});
    html += `</div>`;
  }});
  list.innerHTML = html;
}}

function toggleCard(canon){{
  const card = document.querySelector(`.wcat-card[data-canon="${{cssEscape(canon)}}"]`);
  if (card) card.classList.toggle('is-open');
}}

function cssEscape(s){{ return (window.CSS && CSS.escape) ? CSS.escape(s) : s.replace(/"/g,'\\\\"'); }}

function setAllInCat(canon, val){{
  document.querySelectorAll(`.wcat-card[data-canon="${{cssEscape(canon)}}"] input[type=checkbox]`).forEach(cb => {{
    cb.checked = val;
  }});
  markDirty(canon);
  updateCount(canon);
}}

function updateCount(canon){{
  const total = document.querySelectorAll(`.wcat-card[data-canon="${{cssEscape(canon)}}"] input[type=checkbox]`).length;
  const checked = document.querySelectorAll(`.wcat-card[data-canon="${{cssEscape(canon)}}"] input[type=checkbox]:checked`).length;
  const el = document.getElementById('cnt-' + canon);
  if (el) el.textContent = checked + '/' + total + ' 노출';
}}

function markDirty(canon){{
  _dirty[canon] = true;
  const card = document.querySelector(`.wcat-card[data-canon="${{cssEscape(canon)}}"]`);
  if (card) card.classList.add('is-dirty');
  updateCount(canon);
}}

function resetCat(canon){{
  const cat = _byCanon[canon];
  if (!cat) return;
  cat.widgets.forEach(w => {{
    const cb = document.querySelector(`input[data-canon="${{cssEscape(canon)}}"][data-wname="${{cssEscape(w.name)}}"]`);
    if (cb) cb.checked = w.visible;
  }});
  delete _dirty[canon];
  const card = document.querySelector(`.wcat-card[data-canon="${{cssEscape(canon)}}"]`);
  if (card) card.classList.remove('is-dirty');
  updateCount(canon);
}}

async function saveCat(canon){{
  const wmap = {{}};
  document.querySelectorAll(`.wcat-card[data-canon="${{cssEscape(canon)}}"] input[type=checkbox]`).forEach(cb => {{
    wmap[cb.dataset.wname] = cb.checked;
  }});
  const payload = {{ widgets: {{ [canon]: wmap }} }};
  try {{
    const r = await fetch('/api/admin/settings', {{
      method:'PUT', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify(payload)
    }});
    const d = await r.json();
    if (d.ok) {{
      const cat = _byCanon[canon];
      if (cat) cat.widgets.forEach(w => {{ if (wmap[w.name] !== undefined) w.visible = !!wmap[w.name]; }});
      delete _dirty[canon];
      const card = document.querySelector(`.wcat-card[data-canon="${{cssEscape(canon)}}"]`);
      if (card) card.classList.remove('is-dirty');
      toast('"' + canon + '" 저장 완료');
    }} else {{
      toast('저장 실패: ' + (d.error||'unknown'));
    }}
  }} catch(e) {{
    toast('저장 오류: ' + e.message);
  }}
}}

// 페이지 떠나기 전 미저장 변경 경고
window.addEventListener('beforeunload', function(e){{
  if (Object.keys(_dirty).length) {{
    e.preventDefault(); e.returnValue = '저장 안 된 변경이 있습니다.';
    return e.returnValue;
  }}
}});

loadCatalog(false);
</script>
</body></html>""")


@app.get("/admin/splash", response_class=HTMLResponse)
async def admin_splash_page():
    """로딩 이미지 설정 — 로딩 splash 와 완료 splash 의 노출 토글."""
    nav = _admin_nav_html("splash")
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<title>로딩 이미지 설정 — 관리자</title>
<style>{_ADMIN_BASE_CSS}
.splash-card{{display:flex;gap:18px;align-items:flex-start;padding:14px;margin-bottom:14px;
  border:1px solid #e5e7eb;border-radius:9px;background:#fafafb}}
.splash-preview{{flex-shrink:0;width:220px;background:#fff;border:1px solid #e5e7eb;
  border-radius:8px;padding:8px;display:flex;align-items:center;justify-content:center}}
.splash-preview img{{max-width:100%;max-height:140px;display:block}}
.splash-body{{flex:1;min-width:0}}
.splash-body h3{{font-size:14px;margin:0 0 4px;color:#1a1a1c}}
.splash-body .desc{{font-size:12.5px;color:#6b7280;margin-bottom:10px;line-height:1.5}}
.splash-toggle{{display:flex;align-items:center;gap:10px;margin-top:8px;font-size:13px}}
.splash-toggle input[type=checkbox]{{width:18px;height:18px;cursor:pointer}}
.splash-toggle label{{cursor:pointer;font-weight:500}}
.ready-msgs{{display:flex;flex-direction:column;gap:10px;margin-top:8px}}
.ready-msg-row{{display:flex;flex-direction:column;gap:4px}}
.ready-msg-row label{{font-size:12.5px;color:#374151;font-weight:600}}
.ready-msg-row textarea{{width:100%;box-sizing:border-box;min-height:48px;resize:vertical;
  border:1px solid #d1d5db;border-radius:6px;padding:8px 10px;font-size:13px;
  font-family:inherit;line-height:1.5;color:#1a1a1c;background:#fff}}
.ready-msg-row textarea:focus{{outline:none;border-color:#9ca3af;box-shadow:0 0 0 3px rgba(0,0,0,0.04)}}
.ready-msg-row .hint{{font-size:11.5px;color:#9ca3af}}
</style></head><body>
<div class="wrap">
  <h1>로딩 이미지 설정</h1>
  <ul class="sub sub-bullets">
    <li>세션 로딩 중 / 완료 시 표시되는 splash 이미지 노출 여부 설정</li>
    <li>각 이미지 별 체크 해제 시 즉시 비활성 — 새 세션부터 적용</li>
  </ul>
  {nav}

  <div class="card">
    <h2>이미지 노출 설정</h2>
    <div class="section-desc">세션 로딩 단계별 splash 이미지의 노출 여부를 설정합니다.</div>

    <div class="splash-card">
      <div class="splash-preview">
        <img src="/splash-loading" alt="로딩 중" onerror="this.style.display='none';this.parentNode.textContent='(이미지 없음)';">
      </div>
      <div class="splash-body">
        <h3>① 세션 로딩 중 (Loading splash)</h3>
        <div class="desc">Orange3 컨테이너 부팅 중 표시되는 splash. Orange3 버전·addon 리스트 등이 보임.</div>
        <div class="splash-toggle">
          <input type="checkbox" id="splash-loading">
          <label for="splash-loading">노출 사용</label>
        </div>
        <div class="wcat-actions">
          <button onclick="resetLoading()">되돌리기</button>
          <button id="save-loading-btn" onclick="saveLoading()">저장</button>
        </div>
      </div>
    </div>

    <div class="splash-card">
      <div class="splash-preview">
        <img src="/splash-mascot" alt="완료" onerror="this.style.display='none';this.parentNode.textContent='(이미지 없음)';">
      </div>
      <div class="splash-body">
        <h3>② 로딩 완료 후 (Ready splash)</h3>
        <div class="desc">사이드바 메뉴 로딩 완료 시 표시되는 환영 카드. <b>노출 사용 체크 시 표시, 해제 시 비노출.</b> 언어별 메시지는 선택 입력 — 입력하면 해당 언어 사용자에게 메시지가 함께 표시되고, 비우면 마스코트 카드만 표시됩니다.</div>
        <div class="splash-toggle">
          <input type="checkbox" id="splash-ready-enabled">
          <label for="splash-ready-enabled">노출 사용</label>
        </div>
        <div class="ready-msgs">
          <div class="ready-msg-row">
            <label for="ready-msg-ko">한국어 (ko)</label>
            <textarea id="ready-msg-ko" rows="2" placeholder="비워두면 마스코트 카드만 표시 (선택 입력)"></textarea>
          </div>
          <div class="ready-msg-row">
            <label for="ready-msg-en">English (en)</label>
            <textarea id="ready-msg-en" rows="2" placeholder="Leave blank to show mascot card only (optional)"></textarea>
          </div>
          <div class="ready-msg-row">
            <label for="ready-msg-sl">Slovenčina (sl)</label>
            <textarea id="ready-msg-sl" rows="2" placeholder="Pustite prazno za prikaz samo kartice z maskoto (izbirno)"></textarea>
          </div>
        </div>
        <div class="wcat-actions">
          <button onclick="resetReady()">되돌리기</button>
          <button id="save-ready-btn" onclick="saveReady()">저장</button>
        </div>
      </div>
    </div>
  </div>

  <div class="meta" id="meta"></div>
</div>
<div class="toast" id="toast"></div>

<script>
let _settings = null;

function toast(msg, ms){{
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(window._tt);
  window._tt = setTimeout(()=>t.classList.remove('show'), ms||2200);
}}

// 카드별 저장/되돌리기 — Loading 카드와 Ready 카드는 각각 PUT 요청으로 분리.
// _settings 는 마지막으로 서버에서 받은 값(되돌리기 기준점).

function applyLoading(){{
  const sp = (_settings && _settings.splashes) || {{}};
  document.getElementById('splash-loading').checked = !!sp.loading;
}}

function applyReady(){{
  const sp = (_settings && _settings.splashes) || {{}};
  const ready = (sp.ready && typeof sp.ready === 'object') ? sp.ready : {{}};
  document.getElementById('splash-ready-enabled').checked = (ready.enabled !== false);
  document.getElementById('ready-msg-ko').value = ready.ko || '';
  document.getElementById('ready-msg-en').value = ready.en || '';
  document.getElementById('ready-msg-sl').value = ready.sl || '';
}}

function updateMeta(){{
  document.getElementById('meta').textContent = _settings && _settings.updated_at
    ? 'updated_at: ' + _settings.updated_at : '(저장 전)';
}}

async function initLoad(){{
  try {{
    const r = await fetch('/api/admin/settings', {{cache:'no-store'}});
    const d = await r.json();
    if (!d.ok) {{ toast('로드 실패'); return; }}
    _settings = d.settings;
    applyLoading();
    applyReady();
    updateMeta();
  }} catch(e) {{ toast('로드 오류: ' + e.message); }}
}}

function resetLoading(){{ applyLoading(); toast('변경 사항 되돌림 (Loading)'); }}
function resetReady(){{ applyReady(); toast('변경 사항 되돌림 (Ready)'); }}

async function _putSplashPartial(payload, btnId, okMsg){{
  const btn = document.getElementById(btnId);
  btn.disabled = true; btn.textContent = '저장 중...';
  try {{
    const r = await fetch('/api/admin/settings', {{
      method:'PUT', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify(payload),
    }});
    const d = await r.json();
    if (d.ok) {{
      _settings = d.settings;
      updateMeta();
      toast(okMsg);
    }} else {{
      toast('저장 실패: ' + (d.error || 'unknown'));
    }}
  }} catch(e) {{ toast('저장 오류: ' + e.message); }}
  finally {{ btn.disabled = false; btn.textContent = '저장'; }}
}}

function saveLoading(){{
  _putSplashPartial(
    {{splashes: {{loading: document.getElementById('splash-loading').checked}}}},
    'save-loading-btn',
    'Loading splash 설정 저장 완료'
  );
}}

function saveReady(){{
  _putSplashPartial(
    {{splashes: {{ready: {{
      enabled: document.getElementById('splash-ready-enabled').checked,
      ko: document.getElementById('ready-msg-ko').value.trim(),
      en: document.getElementById('ready-msg-en').value.trim(),
      sl: document.getElementById('ready-msg-sl').value.trim(),
    }}}}}},
    'save-ready-btn',
    'Ready splash 설정 저장 완료'
  );
}}

initLoad();
</script>
</body></html>""")


@app.get("/splash-loading")
async def splash_loading_image():
    """로딩 중 splash 이미지 (Orange3 자체 시작 화면 캡처 등).
    파일: html/splash-loading.png — 없으면 404."""
    candidates = [
        ("/app/html/splash-loading.png", "image/png"),
        ("/app/html/splash-loading.jpg", "image/jpeg"),
        ("/app/html/orange-splash-01.png", "image/png"),
    ]
    for path, mime in candidates:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()
            return Response(
                content=data, media_type=mime,
                headers={"Cache-Control": "public, max-age=3600"},
            )
    return Response(status_code=404)


@app.get("/admin/language", response_class=HTMLResponse)
async def admin_language_page():
    """언어 설정 — 사용 가능 언어 + 기본 언어 + 저장."""
    nav = _admin_nav_html("language")
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<title>언어 설정 — 관리자</title>
<style>{_ADMIN_BASE_CSS}</style></head><body>
<div class="wrap">
  <h1>언어 설정</h1>
  <div class="sub">전체 사용자에게 적용되는 사용 가능 언어와 기본 언어를 지정합니다.</div>
  {nav}

  <div class="card">
    <h2>언어 노출 · 기본 언어</h2>
    <div class="section-desc">기본 언어는 반드시 사용 가능 목록에 포함되어야 합니다. 신규 사용자는 기본 언어로 페이지가 로딩되며, 컨테이너 Orange3 도 자동 정렬됩니다.</div>

    <div class="info-note method">
      <div class="info-note-title">적용 방식</div>
      <div class="info-note-body">Orange.ini 를 호스트에서 직접 수정 + 컨테이너 재시작</div>
    </div>

    <div class="info-note warn">
      <div class="info-note-title">참고</div>
      <div class="info-note-body">언어 설정 변경은 가능하지만, 풀 조정으로 10초 지연 발생. <b>Orange.ini 직접 수정 방식 추천</b></div>
    </div>

    <div class="lang-hdr">
      <span>언어</span>
      <span>사용</span>
      <span>기본</span>
    </div>
    <div class="lang-list" id="lang-list"></div>
  </div>

  <div class="actions">
    <button onclick="loadLang()">되돌리기</button>
    <button id="save-btn" onclick="saveLang()">저장</button>
  </div>

  <div class="meta" id="meta"></div>
</div>
<div class="toast" id="toast"></div>

<script>
let _settings = null, _knownLangs = [];

function esc(s){{return String(s==null?'':s).replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}})[c]);}}
function toast(msg, ms){{
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(window._tt);
  window._tt = setTimeout(()=>t.classList.remove('show'), ms||2200);
}}

async function loadLang(){{
  try {{
    const r = await fetch('/api/admin/settings', {{cache:'no-store'}});
    const d = await r.json();
    if (!d.ok) {{ toast('로드 실패'); return; }}
    _settings = d.settings;
    _knownLangs = d.known_languages;
    renderLangs();
    document.getElementById('meta').textContent = _settings.updated_at
      ? 'updated_at: ' + _settings.updated_at : '(저장 전)';
  }} catch(e) {{ toast('로드 오류: ' + e.message); }}
}}

function renderLangs(){{
  const list = document.getElementById('lang-list');
  list.innerHTML = _knownLangs.map(l => {{
    const inAvail = _settings.languages.available.includes(l.code);
    const isDefault = _settings.languages.default === l.code;
    return `
      <div class="lang-row">
        <span class="lang-label">${{esc(l.label)}} <span style="color:#9ca3af;font-size:11px">(${{esc(l.code)}})</span></span>
        <span class="lang-chk"><input type="checkbox" data-lang="${{esc(l.code)}}" ${{inAvail?'checked':''}}></span>
        <span class="lang-def"><input type="radio" name="default-lang" data-lang="${{esc(l.code)}}" ${{isDefault?'checked':''}}></span>
      </div>
    `;
  }}).join('');
  // 사용 체크 해제 시 → 해당 radio 도 자동 해제, 다른 항목으로 default 이동 제안
  list.querySelectorAll('input[type=checkbox]').forEach(cb => {{
    cb.addEventListener('change', function() {{
      if (!cb.checked) {{
        const code = cb.dataset.lang;
        const rd = list.querySelector('input[type=radio][data-lang="' + code + '"]');
        if (rd && rd.checked) {{ rd.checked = false; }}
      }}
    }});
  }});
  // default radio 선택 시 → 해당 사용 체크가 꺼져 있으면 자동 켜기
  list.querySelectorAll('input[type=radio]').forEach(rd => {{
    rd.addEventListener('change', function() {{
      if (rd.checked) {{
        const code = rd.dataset.lang;
        const cb = list.querySelector('input[type=checkbox][data-lang="' + code + '"]');
        if (cb && !cb.checked) cb.checked = true;
      }}
    }});
  }});
}}

async function saveLang(){{
  const available = [];
  document.querySelectorAll('#lang-list input[type=checkbox]').forEach(cb => {{
    if (cb.checked) available.push(cb.dataset.lang);
  }});
  let def = null;
  const r = document.querySelector('#lang-list input[type=radio]:checked');
  if (r) def = r.dataset.lang;
  if (!available.length) {{ toast('사용 가능한 언어를 1개 이상 선택해야 합니다'); return; }}
  if (!def || !available.includes(def)) {{
    toast('기본 언어를 사용 목록 안에서 선택해야 합니다'); return;
  }}
  const btn = document.getElementById('save-btn');
  btn.disabled = true; btn.textContent = '저장 중...';
  try {{
    const resp = await fetch('/api/admin/settings', {{
      method:'PUT', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{languages: {{available, default: def}}}}),
    }});
    const d = await resp.json();
    if (d.ok) {{
      _settings = d.settings;
      document.getElementById('meta').textContent = 'updated_at: ' + _settings.updated_at;
      toast('언어 설정 저장 완료');
    }} else {{
      toast('저장 실패: ' + (d.error || 'unknown'));
    }}
  }} catch(e) {{ toast('저장 오류: ' + e.message); }}
  finally {{ btn.disabled = false; btn.textContent = '저장'; }}
}}

loadLang();
</script>
</body></html>""")


@app.get("/api/admin/sessions")
async def api_admin_sessions(request: Request):
    """활성 세션 + xpra 세션 + 워밍풀 스냅샷 — admin/sessions 페이지가 폴링.
    client_ip: SID-IP 바인딩 미들웨어가 첫 접근 IP 를 sessions[sid] 에 기록.
    워밍풀 컨테이너는 아직 사용자 접근 전이라 None.
    admin_viewer 플래그: 해당 세션의 client_ip 가 지금 admin 페이지를 보는 요청자의
    IP 와 같으면 True — UI 에서 "관리자 접근 중" 배지로 강조."""
    now = time.time()
    admin_ip = request.client.host if request.client else None
    out_main = []
    with _lock:
        for sid, info in sessions.items():
            if info.get("engine") == "xpra":
                continue
            running = container_running(info["container_id"])
            age = int(now - info.get("last_seen", now))
            remain = max(0, SESSION_TIMEOUT - age)
            cip = info.get("client_ip")
            out_main.append({
                "sid": sid,
                "kind": "noVNC",
                "client_ip": cip,
                "admin_viewer": bool(admin_ip and cip and cip == admin_ip),
                "port": info.get("port"),
                "container_id": str(info.get("container_id", ""))[:12],
                "running": running,
                "age_sec": age,
                "remain_sec": remain,
            })
        ip_by_sid = {sid: info.get("client_ip") for sid, info in sessions.items()}
    out_xpra = []
    try:
        with _xpra_lock:
            for sid, info in xpra_sessions.items():
                running = container_running(info.get("container_id", ""))
                age = int(now - info.get("last_seen", now)) if info.get("last_seen") else 0
                cip = ip_by_sid.get(sid)
                out_xpra.append({
                    "sid": sid,
                    "kind": "Xpra",
                    "client_ip": cip,
                    "admin_viewer": bool(admin_ip and cip and cip == admin_ip),
                    "port": info.get("port"),
                    "container_id": str(info.get("container_id", ""))[:12],
                    "warm": bool(info.get("warm", False)),
                    "running": running,
                    "age_sec": age,
                })
    except Exception:
        pass
    return JSONResponse({
        "ok": True,
        "ts": int(now),
        "session_timeout": SESSION_TIMEOUT,
        "admin_ip": admin_ip,
        "sessions": out_main,
        "xpra_sessions": out_xpra,
    })


@app.get("/admin/sessions", response_class=HTMLResponse)
async def admin_sessions():
    """활성 세션 현황 — settings 페이지와 동일 톤. 5초 자동 새로고침 + 강제종료 버튼."""
    return HTMLResponse("""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<title>활성 세션 — 관리자</title>
<style>
body{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Malgun Gothic",sans-serif;background:#fafafa;color:#1a1a1c}
.wrap{max-width:1100px;margin:30px auto;padding:0 20px 40px}
h1{font-size:22px;margin:0 0 6px;color:#1a1a1c}
.sub{font-size:13px;color:#6b7280;margin-bottom:24px}
.sub-bullets{margin:0 0 24px 0;padding-left:20px;line-height:1.65}
.sub-bullets li{margin:0}
.admin-tabs{display:flex;gap:0;border-bottom:1px solid #e5e7eb;margin:0 0 24px}
.admin-tabs a{padding:11px 18px;font-size:13.5px;font-weight:600;color:#6b7280;text-decoration:none;border-bottom:2px solid transparent;transition:color .12s,border-color .12s}
.admin-tabs a:hover{color:#1a1a1c}
.admin-tabs a.active{color:#F47B20;border-bottom-color:#F47B20}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:22px 26px;margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,0.03)}
h2{font-size:16px;margin:0 0 4px;color:#1a1a1c;display:flex;align-items:center;gap:10px}
.section-desc{font-size:12.5px;color:#6b7280;margin-bottom:14px}
.count-badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11.5px;font-weight:700;background:#eff6ff;color:#1e40af;border:1px solid #bfdbfe}
.count-badge.xpra{background:#fef2f2;color:#b91c1c;border-color:#fecaca}
.count-badge.nginx{background:#ecfdf5;color:#047857;border-color:#a7f3d0}
.count-badge.nginx.down{background:#f3f4f6;color:#6b7280;border-color:#d1d5db}
.count-badge.nginx.unhealthy{background:#fffbeb;color:#b45309;border-color:#fde68a}
/* Nginx 카드 */
.nginx-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:4px}
.nginx-stat{padding:12px 16px;border:1px solid #e5e7eb;border-radius:8px;background:#fafafb}
.nginx-stat .label{font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:0.4px;margin-bottom:6px}
.nginx-stat .value{font-size:13.5px;color:#1f2937;font-family:Consolas,monospace;word-break:break-all}
.nginx-stat.healthy{border-color:#a7f3d0;background:#ecfdf5}
.nginx-stat.unhealthy{border-color:#fde68a;background:#fffbeb}
.nginx-stat.down{border-color:#fecaca;background:#fef2f2}
.nginx-stat.healthy .value{color:#047857}
.nginx-stat.unhealthy .value{color:#b45309}
.nginx-stat.down .value{color:#b91c1c}
.nginx-empty{padding:18px 14px;text-align:center;color:#9ca3af;font-size:13px;background:#fafafb;border:1px dashed #e5e7eb;border-radius:8px}
.nginx-empty code{background:#fff;padding:2px 6px;border-radius:4px;border:1px solid #e5e7eb;font-size:12px;color:#1f2937}
.section-desc code{background:#f5f5f7;padding:1px 6px;border-radius:4px;font-size:11.5px;color:#1f2937;font-family:Consolas,monospace}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}
thead th{text-align:left;padding:9px 12px;font-size:11.5px;text-transform:uppercase;letter-spacing:0.4px;color:#6b7280;font-weight:600;border-bottom:1px solid #e5e7eb;background:#fafafb}
tbody td{padding:10px 12px;border-bottom:1px solid #f1f1f3;vertical-align:middle}
tbody tr:hover{background:#fafafb}
tbody tr:last-child td{border-bottom:none}
.sid{font-family:Consolas,monospace;font-size:12.5px;color:#1f2937}
.pill{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600}
.pill.run{background:#dcfce7;color:#15803d}
.pill.stop{background:#fee2e2;color:#b91c1c}
.pill.warm{background:#fff7ed;color:#9a3412;border:1px solid #fed7aa}
.pill.live{background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe}
.pill.admin{background:#fef3c7;color:#92400e;border:1px solid #fcd34d;margin-left:6px}
tbody tr.admin-row{background:#fffbeb}
tbody tr.admin-row:hover{background:#fef3c7}
.kill-btn{padding:5px 12px;border-radius:6px;border:1px solid #fecaca;background:#fff;color:#b91c1c;cursor:pointer;font-size:12px;font-weight:600}
.kill-btn:hover{background:#fef2f2}
.kill-btn:disabled{opacity:0.55;cursor:not-allowed}
.killall-btn{padding:6px 14px;border-radius:6px;border:1px solid #b91c1c;background:#b91c1c;color:#fff;cursor:pointer;font-size:12.5px;font-weight:600}
.killall-btn:hover{background:#991b1b;border-color:#991b1b}
.killall-btn:disabled{opacity:0.55;cursor:not-allowed}
.empty{padding:24px;text-align:center;color:#9ca3af;font-size:13px}
.toolbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px}
.toolbar .right{display:flex;align-items:center;gap:10px;color:#6b7280;font-size:12px;flex-wrap:wrap}
.toolbar button{padding:6px 14px;border-radius:6px;border:1px solid #e5e7eb;background:#fff;cursor:pointer;font-size:12.5px;font-weight:600}
.toolbar button:hover{background:#f5f5f7}
/* 풀 컨트롤 (2026-05-24) */
.pool-card{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.pool-box{padding:14px 16px;border:1px solid #e5e7eb;border-radius:8px;background:#fafafb}
.pool-box.main{border-color:#bfdbfe;background:#eff6ff}
.pool-box.xpra{border-color:#fecaca;background:#fef2f2}
.pool-title{font-size:13.5px;font-weight:700;margin:0 0 10px;display:flex;align-items:center;gap:8px}
.pool-box.main .pool-title{color:#1e40af}
.pool-box.xpra .pool-title{color:#b91c1c}
.pool-stats{display:grid;grid-template-columns:auto 1fr;gap:6px 12px;font-size:12.5px;color:#374151;margin-bottom:12px}
.pool-stats .k{color:#6b7280;font-weight:600}
.pool-stats .v{font-family:Consolas,monospace}
.pool-input-row{display:flex;align-items:center;gap:8px;margin-top:8px}
.pool-input-row label{font-size:12px;color:#374151;font-weight:600}
.pool-input-row input[type=number]{width:72px;padding:6px 8px;border:1px solid #d1d5db;border-radius:5px;font-size:13px;font-family:Consolas,monospace;text-align:right}
.pool-input-row input[type=number]:focus{outline:none;border-color:#F47B20}
.pool-input-row .max-hint{font-size:11.5px;color:#9ca3af;font-family:Consolas,monospace}
.pool-input-row button{padding:6px 14px;border-radius:5px;border:1px solid #F47B20;background:#F47B20;color:#fff;cursor:pointer;font-size:12px;font-weight:600}
.pool-input-row button:hover{background:#d96b10;border-color:#d96b10}
.pool-input-row button:disabled{opacity:0.55;cursor:not-allowed}
.toast{position:fixed;left:50%;bottom:30px;transform:translateX(-50%) translateY(20px);background:#1a1a1c;color:#fff;padding:10px 18px;border-radius:8px;font-size:13.5px;opacity:0;transition:all .25s;pointer-events:none;z-index:9999}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
.meta{margin-top:14px;font-size:11.5px;color:#9ca3af;font-family:Consolas,monospace}
</style></head><body>
<div class="wrap">
  <h1>활성 세션</h1>
  <div class="sub">현재 실행 중인 Orange3 세션 현황입니다. 5초마다 자동 갱신.</div>
  <nav class="admin-tabs">
    <a href="/admin/menu">메뉴 설정</a>
    <a href="/admin/widgets">위젯 설정</a>
    <a href="/admin/language">언어 설정</a>
    <a href="/admin/splash">로딩 이미지 설정</a>
    <a href="/admin/sessions" class="active">활성 세션</a>
  </nav>
  __FB_AUTH_BLOCK__

  <div class="card">
    <div class="toolbar">
      <h2>워밍풀 크기</h2>
      <div class="right">
        <span id="auto-status">⟳ 5초 자동 갱신</span>
        <button onclick="loadAll()">지금 새로고침</button>
      </div>
    </div>
    <div class="section-desc">env 로 정의된 풀 크기가 상한(MAX). 0..MAX 범위 안에서만 줄일 수 있습니다. 컨테이너 재시작 후에도 유지.</div>
    <div class="pool-card" id="pool-card"></div>
  </div>

  <div class="card">
    <div class="toolbar">
      <h2>Nginx 리버스 프록시 <span class="count-badge nginx" id="nginx-state">조회 중…</span></h2>
      <div class="right">
        <button onclick="nginxReload()" id="nginx-reload-btn">설정 리로드</button>
      </div>
    </div>
    <div class="section-desc">정적 자산 alias + reverse proxy. opt-in 오버레이 (<code>docker-compose.nginx.yml</code>) 로 구동. 호스트 <code>nginx/nginx.conf</code> 수정 후 「설정 리로드」 로 컨테이너 재시작 없이 반영.</div>
    <div id="nginx-info"></div>
  </div>

  <div class="card">
    <div class="toolbar">
      <h2>운영 세션 <span class="count-badge" id="cnt-main">0</span></h2>
      <div class="right">
        <button class="killall-btn" id="kill-all-main" onclick="terminateAll('main')">운영 세션 일괄 종료</button>
      </div>
    </div>
    <div class="section-desc">사용자가 접속 중인 noVNC Orange3 세션. 강제 종료 시 사용자의 워크플로우가 자동 저장되며 즉시 끊깁니다. 일괄 종료는 워밍풀까지 비웁니다(자동 재보충).</div>
    <div id="tbl-main"></div>
  </div>

  <div class="card">
    <div class="toolbar">
      <h2>Xpra 세션 · 워밍풀 <span class="count-badge xpra" id="cnt-xpra">0</span></h2>
      <div class="right">
        <button class="killall-btn" id="kill-all-xpra" onclick="terminateAll('xpra')">Xpra 세션·워밍풀 일괄 종료</button>
      </div>
    </div>
    <div class="section-desc">Xpra 전환 트랙 세션 + 즉시 응답용 사전 부팅 컨테이너(워밍풀). 일괄 종료는 모든 컨테이너 제거(자동 재보충).</div>
    <div id="tbl-xpra"></div>
  </div>

  <div class="meta" id="meta"></div>
</div>
<div class="toast" id="toast"></div>

<script>
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"})[c]);}
function fmtAge(sec){
  if (sec < 60) return sec + '초 전';
  if (sec < 3600) return Math.floor(sec/60) + '분 ' + (sec%60) + '초 전';
  return Math.floor(sec/3600) + '시간 ' + Math.floor((sec%3600)/60) + '분 전';
}
function fmtRemain(sec){
  if (sec <= 0) return '만료됨';
  if (sec < 60) return sec + '초';
  if (sec < 3600) return Math.floor(sec/60) + '분';
  return Math.floor(sec/3600) + '시간 ' + Math.floor((sec%3600)/60) + '분';
}
function toast(msg, ms){
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(window._tt);
  window._tt = setTimeout(()=>t.classList.remove('show'), ms||2200);
}

async function loadSessions(){
  try {
    const r = await fetch('/api/admin/sessions', {cache:'no-store'});
    const d = await r.json();
    if (!d.ok) { toast('로드 실패'); return; }
    renderMain(d.sessions || []);
    renderXpra(d.xpra_sessions || []);
    const ts = new Date((d.ts||0)*1000);
    document.getElementById('meta').textContent =
      'snapshot: ' + ts.toLocaleString('ko-KR') + ' · session_timeout=' + d.session_timeout + 's';
  } catch(e) { toast('로드 오류: ' + e.message); }
}

function fmtIp(ip, isAdminViewer){
  if (!ip) return '<span style="color:#9ca3af">—</span>';
  const badge = isAdminViewer
    ? '<span class="pill admin" title="이 IP 에서 admin 페이지를 조회 중 — 일괄 종료에서 자동 제외됨">관리자 접근 중</span>'
    : '';
  return '<span class="sid">' + esc(ip) + '</span>' + badge;
}

function renderMain(rows){
  document.getElementById('cnt-main').textContent = rows.length + '개';
  const c = document.getElementById('tbl-main');
  if (!rows.length) { c.innerHTML = '<div class="empty">현재 활성 noVNC 세션이 없습니다.</div>'; return; }
  let html = '<table><thead><tr>'
    + '<th>세션 ID</th><th>컨테이너</th><th>접근 IP</th><th>포트</th><th>상태</th>'
    + '<th>마지막 접속</th><th>남은 시간</th><th>액션</th>'
    + '</tr></thead><tbody>';
  rows.forEach(s => {
    const run = s.running
      ? '<span class="pill run">실행 중</span>'
      : '<span class="pill stop">중지됨</span>';
    const trCls = s.admin_viewer ? ' class="admin-row"' : '';
    html += `<tr${trCls}>
      <td class="sid">${esc(s.sid.slice(0,12))}…</td>
      <td class="sid">${esc(s.container_id)}</td>
      <td>${fmtIp(s.client_ip, s.admin_viewer)}</td>
      <td>${esc(String(s.port||''))}</td>
      <td>${run}</td>
      <td>${esc(fmtAge(s.age_sec))}</td>
      <td>${esc(fmtRemain(s.remain_sec))}</td>
      <td><button class="kill-btn" onclick="killSession('${esc(s.sid)}','noVNC')">종료</button></td>
    </tr>`;
  });
  html += '</tbody></table>';
  c.innerHTML = html;
}

function renderXpra(rows){
  document.getElementById('cnt-xpra').textContent = rows.length + '개';
  const c = document.getElementById('tbl-xpra');
  if (!rows.length) { c.innerHTML = '<div class="empty">현재 Xpra 세션 / 워밍풀이 비어 있습니다.</div>'; return; }
  let html = '<table><thead><tr>'
    + '<th>세션 ID</th><th>컨테이너</th><th>접근 IP</th><th>포트</th><th>유형</th>'
    + '<th>상태</th><th>마지막 접속</th><th>액션</th>'
    + '</tr></thead><tbody>';
  rows.forEach(s => {
    const run = s.running
      ? '<span class="pill run">실행 중</span>'
      : '<span class="pill stop">중지됨</span>';
    const kind = s.warm
      ? '<span class="pill warm">워밍풀</span>'
      : '<span class="pill live">사용 중</span>';
    const trCls = s.admin_viewer ? ' class="admin-row"' : '';
    html += `<tr${trCls}>
      <td class="sid">${esc(s.sid.slice(0,12))}…</td>
      <td class="sid">${esc(s.container_id)}</td>
      <td>${fmtIp(s.client_ip, s.admin_viewer)}</td>
      <td>${esc(String(s.port||''))}</td>
      <td>${kind}</td>
      <td>${run}</td>
      <td>${esc(fmtAge(s.age_sec))}</td>
      <td><button class="kill-btn" onclick="killSession('${esc(s.sid)}','Xpra')">종료</button></td>
    </tr>`;
  });
  html += '</tbody></table>';
  c.innerHTML = html;
}

async function killSession(sid, kind){
  if (!confirm(kind + ' 세션 ' + sid.slice(0,8) + '… 을(를) 종료합니다.\\n사용자가 접속 중이면 즉시 끊기게 됩니다. 진행할까요?')) return;
  try {
    let r;
    if (kind === 'Xpra') {
      r = await fetch('/xpra-end?sid=' + encodeURIComponent(sid));
    } else {
      r = await fetch('/admin/sessions/' + encodeURIComponent(sid), {method:'DELETE'});
    }
    if (r.ok) { toast('종료 요청 전송'); loadAll(); }
    else { toast('종료 실패: HTTP ' + r.status); }
  } catch(e) { toast('종료 오류: ' + e.message); }
}

async function terminateAll(kind){
  const label = (kind === 'main') ? '운영 세션' : 'Xpra 세션·워밍풀';
  if (!confirm(label + ' 전체를 일괄 종료합니다.\\n현재 사용 중인 사용자도 즉시 끊깁니다. 진행할까요?')) return;
  const btn = document.getElementById(kind === 'main' ? 'kill-all-main' : 'kill-all-xpra');
  if (btn) { btn.disabled = true; btn.textContent = '종료 중...'; }
  try {
    const r = await fetch('/api/admin/sessions/terminate-all', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({kind})
    });
    const d = await r.json();
    if (d.ok) {
      let msg = label + ' ' + d.killed + '개 종료';
      if (d.skipped_admin > 0) msg += ' (관리자 IP ' + d.skipped_admin + '개 보호)';
      toast(msg, 3500);
      loadAll();
    } else { toast('일괄 종료 실패: ' + (d.error || 'unknown')); }
  } catch(e) { toast('일괄 종료 오류: ' + e.message); }
  finally {
    if (btn) { btn.disabled = false;
      btn.textContent = (kind === 'main') ? '운영 세션 일괄 종료' : 'Xpra 세션·워밍풀 일괄 종료'; }
  }
}

let _pool = null;
async function loadPool(){
  try {
    const r = await fetch('/api/admin/pool', {cache:'no-store'});
    const d = await r.json();
    if (!d.ok) return;
    _pool = d;
    renderPools(d);
  } catch(e) {}
}

function renderPools(d){
  const c = document.getElementById('pool-card');
  c.innerHTML =
    poolBox('main', '운영 세션 풀 (noVNC)', d.main) +
    poolBox('xpra', 'Xpra 풀 (시범)', d.xpra);
}

function poolBox(kind, title, p){
  const inputId = 'pool-input-' + kind;
  const idleRow = (p.current_idle !== undefined)
    ? `<span class="k">유휴 시간 목표</span><span class="v">${p.current_idle}</span>`
    : '';
  const effRow = (p.effective_target !== undefined)
    ? `<span class="k">현재 시각 적용</span><span class="v">${p.effective_target}</span>`
    : '';
  return `<div class="pool-box ${kind}">
    <div class="pool-title">${esc(title)}</div>
    <div class="pool-stats">
      <span class="k">설정값(피크)</span><span class="v">${p.current} / ${p.max}</span>
      ${idleRow}
      ${effRow}
      <span class="k">현재 풀</span><span class="v">${p.in_pool}개 (보충 중 ${p.in_flight})</span>
    </div>
    <div class="pool-input-row">
      <label for="${inputId}">변경:</label>
      <input type="number" id="${inputId}" min="0" max="${p.max}" value="${p.current}">
      <span class="max-hint">/ ${p.max} (MAX)</span>
      <button onclick="savePool('${kind}')">적용</button>
    </div>
  </div>`;
}

async function savePool(kind){
  const inp = document.getElementById('pool-input-' + kind);
  if (!inp) return;
  const v = parseInt(inp.value, 10);
  const max = _pool && _pool[kind] ? _pool[kind].max : 0;
  if (!Number.isFinite(v) || v < 0 || v > max) {
    toast('값은 0..' + max + ' 범위여야 합니다'); return;
  }
  try {
    const body = {}; body[kind] = v;
    const r = await fetch('/api/admin/pool', {
      method:'PUT', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const d = await r.json();
    if (d.ok) { toast('풀 크기 변경 완료'); loadPool(); }
    else { toast('변경 실패: ' + (d.error || 'unknown')); }
  } catch(e) { toast('변경 오류: ' + e.message); }
}

function fmtUptime(sec){
  if (sec == null || sec < 0) return '—';
  if (sec < 60) return sec + '초';
  if (sec < 3600) return Math.floor(sec/60) + '분 ' + (sec%60) + '초';
  if (sec < 86400) return Math.floor(sec/3600) + '시간 ' + Math.floor((sec%3600)/60) + '분';
  return Math.floor(sec/86400) + '일 ' + Math.floor((sec%86400)/3600) + '시간';
}

async function loadNginx(){
  try {
    const r = await fetch('/api/admin/nginx', {cache:'no-store'});
    const d = await r.json();
    renderNginx(d);
  } catch(e) {
    renderNginx({ok:false, running:false, error:e.message});
  }
}

function renderNginx(d){
  const stateBadge = document.getElementById('nginx-state');
  const reloadBtn = document.getElementById('nginx-reload-btn');
  const info = document.getElementById('nginx-info');
  if (!d.running) {
    stateBadge.textContent = '중지됨';
    stateBadge.className = 'count-badge nginx down';
    if (reloadBtn) reloadBtn.disabled = true;
    info.innerHTML = `<div class="nginx-empty">
      Nginx 컨테이너가 실행 중이 아닙니다.<br>
      기동: <code>docker compose -f docker-compose.yml -f docker-compose.nginx.yml up -d nginx</code>
    </div>`;
    return;
  }
  const healthy = d.healthy === true;
  const unhealthy = d.healthy === false;
  if (healthy) {
    stateBadge.textContent = '실행 중 (healthy)';
    stateBadge.className = 'count-badge nginx';
  } else if (unhealthy) {
    stateBadge.textContent = '실행 중 (unhealthy)';
    stateBadge.className = 'count-badge nginx unhealthy';
  } else {
    stateBadge.textContent = '실행 중';
    stateBadge.className = 'count-badge nginx';
  }
  if (reloadBtn) reloadBtn.disabled = false;
  const cls = healthy ? 'healthy' : (unhealthy ? 'unhealthy' : '');
  const hostPort = d.host_port ? (d.host_port + ' → ' + d.internal_port + ' (내부)') : '—';
  info.innerHTML = `<div class="nginx-grid">
    <div class="nginx-stat ${cls}">
      <div class="label">상태</div>
      <div class="value">${esc(d.health_status || d.status || '—')}</div>
    </div>
    <div class="nginx-stat">
      <div class="label">컨테이너</div>
      <div class="value">${esc(d.container_name || '—')}</div>
    </div>
    <div class="nginx-stat">
      <div class="label">접근 포트</div>
      <div class="value">${esc(hostPort)}</div>
    </div>
    <div class="nginx-stat">
      <div class="label">Upstream</div>
      <div class="value">${esc(d.upstream || '—')}</div>
    </div>
    <div class="nginx-stat">
      <div class="label">이미지</div>
      <div class="value">${esc(d.image || '—')}</div>
    </div>
    <div class="nginx-stat">
      <div class="label">가동 시간</div>
      <div class="value">${esc(fmtUptime(d.uptime_sec))}</div>
    </div>
    <div class="nginx-stat">
      <div class="label">풀 수 (upstream)</div>
      <div class="value">${d.pools != null ? d.pools + '개' : '—'}</div>
    </div>
    <div class="nginx-stat">
      <div class="label">접속 수 (active)</div>
      <div class="value">${d.active_connections != null ? d.active_connections : '—'}${d.conn_detail ? ' <span style="font-size:11px;color:#6b7280;font-weight:400">R'+d.conn_detail.reading+' W'+d.conn_detail.writing+' 대기'+d.conn_detail.waiting+'</span>' : ''}</div>
    </div>
  </div>`;
}

async function nginxReload(){
  if (!confirm('Nginx 설정을 리로드합니다.\\n호스트 nginx/nginx.conf 변경 사항이 즉시 반영됩니다. 진행할까요?')) return;
  const btn = document.getElementById('nginx-reload-btn');
  if (btn) { btn.disabled = true; btn.textContent = '리로드 중...'; }
  try {
    const r = await fetch('/api/admin/nginx/reload', {method:'POST'});
    const d = await r.json();
    if (d.ok) { toast(d.message || 'Nginx 리로드 완료'); loadNginx(); }
    else { toast('리로드 실패: ' + (d.error || 'unknown') + (d.detail ? ' — ' + d.detail.slice(0,100) : '')); }
  } catch(e) { toast('리로드 오류: ' + e.message); }
  finally {
    if (btn) { btn.disabled = false; btn.textContent = '설정 리로드'; }
  }
}

async function loadAll(){
  await Promise.all([loadSessions(), loadPool(), loadNginx()]);
}

loadAll();
setInterval(loadAll, 5000);
</script>
</body></html>""".replace("__FB_AUTH_BLOCK__", _admin_auth_html()))


@app.delete("/admin/sessions/{sid}")
async def delete_session(sid: str):
    if sid not in sessions:
        return {"error": "세션 없음"}
    remove_session(sid)
    return {"status": "삭제됨"}

