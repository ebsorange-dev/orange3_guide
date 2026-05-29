import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from starlette.middleware.gzip import GZipMiddleware

app = FastAPI(title="Orange3 Web API")
# 4KB 이상 응답에만 gzip — index.html(~4.2KB)·JSON 응답에 효과
app.add_middleware(GZipMiddleware, minimum_size=1024)


# ── 보안 헤더 ────────────────────────────────────────────────────────────────
# Tier A1 (2026-05-21): 진단보고서 S5/U5 대응
# - X-Content-Type-Options: MIME 스니핑 방지
# - X-Frame-Options: 클릭재킹 방지 (이 페이지를 외부에서 iframe 금지)
# - Referrer-Policy: SID가 URL에 노출되는 동안 Referer 헤더로 SID 유출 차단
# HSTS·CSP는 HTTPS 도입 후 추가 (사내망 IP HTTP 환경 가정)
@app.middleware("http")
async def _add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


# ── Cache-Control 헤더 ───────────────────────────────────────────────────────
# Tier A2 (2026-05-21): 진단보고서 P4 대응
# - 정적 자산(.png/.svg/.css/.js/...): 1년 immutable (파일명 해시 ?v= 사용 시 안전)
# - HTML/API: no-store / no-cache (동적 응답)
_STATIC_EXTS = (".png", ".svg", ".ico", ".jpg", ".jpeg", ".gif",
                ".woff", ".woff2", ".ttf", ".css", ".js", ".map")

@app.middleware("http")
async def _add_cache_headers(request, call_next):
    response = await call_next(request)
    if "Cache-Control" in response.headers:
        return response  # 라우터에서 명시 설정한 경우 존중
    path = request.url.path
    if path.endswith(_STATIC_EXTS):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    else:
        response.headers["Cache-Control"] = "no-cache"
    return response

_INDEX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")

# index.html을 모듈 import 시 1회만 디스크에서 읽어 메모리에 보관.
# Dockerfile.webserver는 index.html을 ro 볼륨으로 마운트하므로 호스트에서 수정 시
# 컨테이너 재시작이 필요하지만, 그 대신 매 요청 디스크 IO 0회.
with open(_INDEX_PATH, "r", encoding="utf-8") as _f:
    _INDEX_HTML = _f.read()

# iris 데이터셋 정보를 1회만 계산 (Orange import + Table 로드는 ~수백 ms).
# 동일 응답이므로 캐싱 안전 — 변하지 않는 read-only 빌트인 데이터셋.
_IRIS_INFO_CACHE: dict | None = None


def _load_iris_info() -> dict:
    try:
        import Orange
        data = Orange.data.Table("iris")
        return {
            "status": "success",
            "data": {
                "name": data.name,
                "instances": len(data),
                "attributes": [v.name for v in data.domain.attributes],
                "class_var": data.domain.class_var.name if data.domain.class_var else None,
            },
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.on_event("startup")
def _warm_iris_cache():
    """앱 시작 시 iris를 미리 로드 — 첫 API 요청도 즉시 응답."""
    global _IRIS_INFO_CACHE
    _IRIS_INFO_CACHE = _load_iris_info()


@app.get("/")
def read_root():
    # 매 요청 디스크 IO 없음 — 메모리 캐시 응답
    return HTMLResponse(content=_INDEX_HTML)


@app.get("/api/dataset/info")
def get_dataset_info():
    # 시작 시 캐시 실패한 경우만 lazy load
    global _IRIS_INFO_CACHE
    if _IRIS_INFO_CACHE is None:
        _IRIS_INFO_CACHE = _load_iris_info()
    return _IRIS_INFO_CACHE


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=9508, reload=True)
