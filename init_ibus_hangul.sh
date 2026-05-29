#!/bin/bash
# Phase 1 (R1, 2026-05-23) — ibus-daemon 기동 후 hangul 엔진을 활성 엔진으로 전환.
#
# startapp.xpra.sh 의 xpra --start 로 ibus-daemon -drx 가 실행되지만
# ibus 의 active engine 기본값은 xkb:us::eng — `ibus engine hangul` 을
# 명시 호출해야 Orange3 Qt 위젯에서 한글 조합이 가능해진다 (운영 startapp.sh 와 동일 패턴).
export DISPLAY=:100

# ibus-daemon 이 D-Bus 에 자기 등록을 완료할 때까지 대기 (최대 10s).
for i in $(seq 1 20); do
    if ibus list-engine >/dev/null 2>&1; then break; fi
    sleep 0.5
done

ibus engine hangul 2>&1 && echo "[ibus] active engine -> hangul" || \
    echo "[ibus] failed to switch engine to hangul (current: $(ibus engine 2>/dev/null))"
