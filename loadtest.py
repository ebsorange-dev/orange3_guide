# -*- coding: utf-8 -*-
"""EBS Orange3 session-manager HTTP 계층 부하 테스트 (④ 부하 테스트, 2026-05-22).

컨테이너를 새로 띄우지 않는 경량 엔드포인트(GET /)만 부하를 줘서
FastAPI/uvicorn 프런트엔드의 동시 요청 처리 용량을 측정한다.
 - 컨테이너 프로비저닝(무거움)은 테스트 대상에서 제외 — 호스트 보호
 - 측정: 성공률, p50/p95/p99 지연, 처리량(req/s)

사용:  python loadtest.py [base_url]   (기본 http://127.0.0.1:8888)
"""
import sys, time, statistics, concurrent.futures, urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8888"
TARGET = BASE + "/"          # 경량 dispatch 응답 — 컨테이너 미생성
TIMEOUT = 15


def one_request():
    t0 = time.time()
    try:
        with urllib.request.urlopen(TARGET, timeout=TIMEOUT) as r:
            r.read()
            return (time.time() - t0) * 1000, r.status
    except Exception:
        return (time.time() - t0) * 1000, 0


def run(concurrency, total):
    lat, codes = [], []
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        for ms, code in ex.map(lambda _: one_request(), range(total)):
            lat.append(ms)
            codes.append(code)
    elapsed = time.time() - t0
    lat.sort()
    ok = sum(1 for c in codes if c == 200)

    def pct(p):
        return lat[min(len(lat) - 1, int(len(lat) * p))]

    print(f"  동시 {concurrency:>3} | 요청 {total:>5} | "
          f"성공 {ok:>5}/{total} ({ok / total * 100:5.1f}%) | "
          f"{total / elapsed:7.1f} req/s | "
          f"p50 {pct(0.50):6.1f}ms  p95 {pct(0.95):6.1f}ms  "
          f"p99 {pct(0.99):6.1f}ms  max {lat[-1]:6.1f}ms")


if __name__ == "__main__":
    print(f"대상: {TARGET}")
    print("=" * 96)
    # 워밍업
    run(10, 100)
    # 동시성 단계별 측정
    for c in (50, 100, 200, 300):
        run(c, c * 20)
    print("=" * 96)
