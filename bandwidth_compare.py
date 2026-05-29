# -*- coding: utf-8 -*-
"""Phase 4 (A/B 검증, 2026-05-23) — noVNC vs Xpra 대역폭·CPU 비교.

같은 작업 시나리오를 noVNC 컨테이너와 Xpra 컨테이너에서 각각 수행한 뒤,
컨테이너의 송수신 바이트와 CPU 사용량 시간 추이를 비교한다.

전제:
 - 운영 noVNC 컨테이너 1개 + Xpra 컨테이너 1개가 동시에 가동 중이며
   사용자가 두 탭에서 동일한 시나리오를 동일 시점에 실행한다.
 - 본 스크립트는 측정자 — 두 컨테이너의 NET/CPU 를 N 초간 1 초 간격으로
   샘플링하고 종료 시 요약을 출력한다 (csv 저장 옵션 포함).

사용:
  # 1) 운영 noVNC: 브라우저에서 http://localhost:8888/  (sid 받음)
  # 2) Xpra: http://localhost:8888/xpra → "운영 UI로 열기" 클릭 (sid 받음)
  # 3) 두 컨테이너 이름 확인: `docker ps | grep -E "orange3-gui|orange3-xpra"`
  # 4) 본 스크립트 실행 (60s 측정)
  python bandwidth_compare.py --novnc <novnc_container> --xpra <xpra_container> \
      --duration 60 --csv out.csv

  # 자동 탐지(가장 최근 시작된 각각 1개):
  python bandwidth_compare.py --auto --duration 60

  # 활동 탐지(사용자 접속 중인 컨테이너 자동 선택 — 워밍풀 환경에서 권장):
  #   먼저 두 탭(noVNC + Xpra) 열어 캔버스 보이게 한 다음 실행.
  python bandwidth_compare.py --active --duration 60 --csv ab.csv
"""
from __future__ import annotations
import argparse
import csv
import subprocess
import sys
import time
from typing import List, Dict, Optional

# Windows PowerShell(cp949) 에서 한글 출력이 깨지는 것 방지 — stdout 을 UTF-8 로 재구성.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _docker(args: List[str]) -> str:
    """`docker` 호출 — 공백 trim 한 stdout 반환. 실패 시 빈 문자열."""
    try:
        r = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception as e:
        print(f"[!] docker {args}: {e}", file=sys.stderr)
        return ""


def _auto_detect() -> Dict[str, Optional[str]]:
    """가장 최근 시작된 orange3-gui · orange3-xpra:poc 컨테이너 1개씩 자동 선택.
    `--auto` 의 기본 — 활동 중인 컨테이너 정밀 탐지가 필요하면 `--active` 사용."""
    novnc = _docker([
        "ps", "--filter", "ancestor=orange3-gui",
        "--format", "{{.Names}}", "-l"
    ])
    xpra = _docker([
        "ps", "--filter", "ancestor=orange3-xpra:poc",
        "--format", "{{.Names}}", "-l"
    ])
    return {"novnc": novnc or None, "xpra": xpra or None}


def _active_detect(probe_sec: int = 5) -> Dict[str, Optional[str]]:
    """`probe_sec` 초간 송신량 델타 측정 → 가장 활동적인 컨테이너 선택.
    워밍풀에 idle 컨테이너가 많을 때, 사용자가 실제 접속 중인 컨테이너를
    트래픽 발생량으로 식별. 두 환경 모두 1개 이상 컨테이너 활동 필요."""
    novnc_all = _docker(["ps", "--filter", "ancestor=orange3-gui",
                         "--format", "{{.Names}}"]).splitlines()
    xpra_all = _docker(["ps", "--filter", "ancestor=orange3-xpra:poc",
                        "--format", "{{.Names}}"]).splitlines()
    if not novnc_all and not xpra_all:
        return {"novnc": None, "xpra": None}
    print(f"활동 탐지 — {probe_sec}s 간 송신량 비교 (noVNC {len(novnc_all)}개, Xpra {len(xpra_all)}개)")
    t0 = {n: _net_cpu_sample(n) for n in novnc_all + xpra_all}
    time.sleep(probe_sec)
    t1 = {n: _net_cpu_sample(n) for n in novnc_all + xpra_all}

    def best(names):
        if not names:
            return None
        rated = []
        for n in names:
            a, b = t0.get(n), t1.get(n)
            if not (a and b):
                continue
            rated.append((n, b["tx_bytes"] - a["tx_bytes"]))
        if not rated:
            return None
        rated.sort(key=lambda x: -x[1])
        top = rated[0]
        print(f"  {top[0]}  활동 tx={_human(top[1])} / {probe_sec}s  (후보 {len(rated)}개 중 1위)")
        return top[0] if top[1] > 0 else (rated[0][0] if rated else None)

    return {"novnc": best(novnc_all), "xpra": best(xpra_all)}


def _net_cpu_sample(container: str) -> Optional[Dict[str, float]]:
    """`docker stats --no-stream` 1 회 측정. CPU%, NET I/O (송수신 bytes) 반환."""
    out = _docker([
        "stats", "--no-stream", "--format",
        "{{.CPUPerc}}|{{.NetIO}}|{{.MemUsage}}",
        container
    ])
    if not out:
        return None
    try:
        cpu_s, net_s, mem_s = out.split("|", 2)
        cpu = float(cpu_s.rstrip("%"))
        # NetIO: "rx_human / tx_human" 형태 — bytes 로 변환
        rx_s, tx_s = [s.strip() for s in net_s.split("/", 1)]
        return {
            "cpu_pct": cpu,
            "rx_bytes": _human_to_bytes(rx_s),
            "tx_bytes": _human_to_bytes(tx_s),
            "mem_bytes": _human_to_bytes(mem_s.split("/", 1)[0].strip()),
        }
    except Exception as e:
        print(f"[!] parse '{out}': {e}", file=sys.stderr)
        return None


_UNITS = {"B": 1, "kB": 1e3, "KB": 1024, "KiB": 1024,
          "MB": 1e6, "MiB": 1024**2,
          "GB": 1e9, "GiB": 1024**3,
          "TB": 1e12, "TiB": 1024**4}


def _human_to_bytes(s: str) -> float:
    s = s.strip()
    if not s:
        return 0.0
    # 끝에서 단위 분리
    for unit in sorted(_UNITS, key=len, reverse=True):
        if s.endswith(unit):
            try:
                return float(s[: -len(unit)].strip()) * _UNITS[unit]
            except ValueError:
                return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def _human(n: float) -> str:
    for u, v in [("GB", 1e9), ("MB", 1e6), ("KB", 1e3)]:
        if n >= v:
            return f"{n / v:.2f} {u}"
    return f"{n:.0f} B"


def run(novnc: str, xpra: str, duration: int, csv_path: Optional[str]) -> None:
    print(f"측정 대상: noVNC={novnc}  Xpra={xpra}  duration={duration}s")
    print("두 컨테이너에서 동일 시나리오를 지금 시작하세요. 측정은 1s 간격.\n")

    # baseline
    base_n = _net_cpu_sample(novnc)
    base_x = _net_cpu_sample(xpra)
    if not base_n or not base_x:
        print("[!] baseline 측정 실패 — 컨테이너 이름 확인", file=sys.stderr)
        sys.exit(1)
    print(f"  t=0  noVNC rx/tx = {_human(base_n['rx_bytes'])} / {_human(base_n['tx_bytes'])}  "
          f"|  Xpra rx/tx = {_human(base_x['rx_bytes'])} / {_human(base_x['tx_bytes'])}")

    rows: List[List[float]] = []
    rows.append([0.0, base_n["cpu_pct"], 0, 0, base_x["cpu_pct"], 0, 0])

    t0 = time.time()
    last_n, last_x = base_n, base_x
    for i in range(1, duration + 1):
        # 다음 초까지 정확히 sleep
        target = t0 + i
        sleep_for = max(0.0, target - time.time())
        time.sleep(sleep_for)

        sn = _net_cpu_sample(novnc)
        sx = _net_cpu_sample(xpra)
        if not sn or not sx:
            print(f"  t={i}s [!] 측정 누락 — skip")
            continue

        d_rx_n = sn["rx_bytes"] - base_n["rx_bytes"]
        d_tx_n = sn["tx_bytes"] - base_n["tx_bytes"]
        d_rx_x = sx["rx_bytes"] - base_x["rx_bytes"]
        d_tx_x = sx["tx_bytes"] - base_x["tx_bytes"]
        rows.append([i, sn["cpu_pct"], d_rx_n, d_tx_n, sx["cpu_pct"], d_rx_x, d_tx_x])

        # 10초마다 중간 보고
        if i % 10 == 0:
            print(f"  t={i:>3}s  noVNC CPU={sn['cpu_pct']:5.1f}% "
                  f"Δtx={_human(d_tx_n):>10} Δrx={_human(d_rx_n):>10}  |  "
                  f"Xpra CPU={sx['cpu_pct']:5.1f}% "
                  f"Δtx={_human(d_tx_x):>10} Δrx={_human(d_rx_x):>10}")
        last_n, last_x = sn, sx

    # 최종 요약
    tot_tx_n = last_n["tx_bytes"] - base_n["tx_bytes"]
    tot_tx_x = last_x["tx_bytes"] - base_x["tx_bytes"]
    tot_rx_n = last_n["rx_bytes"] - base_n["rx_bytes"]
    tot_rx_x = last_x["rx_bytes"] - base_x["rx_bytes"]
    avg_cpu_n = sum(r[1] for r in rows) / len(rows)
    avg_cpu_x = sum(r[4] for r in rows) / len(rows)
    ratio_tx = (tot_tx_x / tot_tx_n * 100) if tot_tx_n > 0 else 0.0

    print(f"\n=== {duration}s 요약 ===")
    print(f"  noVNC : tx={_human(tot_tx_n):>10}  rx={_human(tot_rx_n):>10}  avg CPU={avg_cpu_n:5.1f}%")
    print(f"  Xpra  : tx={_human(tot_tx_x):>10}  rx={_human(tot_rx_x):>10}  avg CPU={avg_cpu_x:5.1f}%")
    print(f"  Xpra/noVNC tx 비율 = {ratio_tx:.1f}%   (절감 = {100 - ratio_tx:.1f}%)")

    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["t_sec", "novnc_cpu_pct", "novnc_dRX_bytes", "novnc_dTX_bytes",
                        "xpra_cpu_pct", "xpra_dRX_bytes", "xpra_dTX_bytes"])
            w.writerows(rows)
        print(f"  CSV 저장: {csv_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="noVNC vs Xpra 대역폭·CPU 비교")
    ap.add_argument("--novnc", help="noVNC 컨테이너 이름 (생략 시 --auto 권장)")
    ap.add_argument("--xpra", help="Xpra 컨테이너 이름 (생략 시 --auto 권장)")
    ap.add_argument("--auto", action="store_true",
                    help="가장 최근 시작된 orange3-gui / orange3-xpra:poc 컨테이너 자동 선택")
    ap.add_argument("--active", action="store_true",
                    help="5초 송신량 측정 후 실제 활동 중(사용자 접속 중)인 컨테이너 자동 선택 [권장]")
    ap.add_argument("--probe", type=int, default=5,
                    help="--active 모드 송신량 측정 시간(초) [5]")
    ap.add_argument("--duration", type=int, default=60, help="측정 시간(초) [60]")
    ap.add_argument("--csv", help="시간 추이 CSV 저장 경로")
    a = ap.parse_args()

    novnc, xpra = a.novnc, a.xpra
    if a.active:
        d = _active_detect(a.probe)
        novnc = novnc or d["novnc"]
        xpra = xpra or d["xpra"]
    elif a.auto or not (novnc and xpra):
        d = _auto_detect()
        novnc = novnc or d["novnc"]
        xpra = xpra or d["xpra"]
    if not novnc or not xpra:
        ap.error("noVNC / Xpra 컨테이너를 찾지 못함 — --novnc/--xpra 또는 --auto")

    run(novnc, xpra, a.duration, a.csv)


if __name__ == "__main__":
    main()
