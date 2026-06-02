#!/bin/bash
# Phase 3B (2026-05-23) — Orange Canvas 메인 윈도우 자동 최대화.
#
# 어려움 정리:
#  (1) Qt5(PyQt5)는 _NET_WM_NAME 만 set, WM_NAME 미설정 →
#      xdotool `--name` 필터(WM_NAME 기반)가 메인 창을 못 찾음.
#      → iterate + getwindowname 우회.
#  (2) Orange3 가 띄우는 가시 윈도우 4 종 중 main 식별:
#      "Qt Selection Owner for Orange"      → 헬퍼
#      "Qt Clipboard Requestor Window — Orange" → 헬퍼
#      "Orange"                              → 헬퍼 (단독 이름)
#      "Untitled  — Orange"                  → ★ 메인 캔버스
#      → 1순위 "Untitled" 매칭, 2순위 헬퍼 제외 + 길이 필터.
#  (3) xdotool `windowstate` 명령은 이 버전(Ubuntu 22.04)에 없음.
#      → wmctrl EWMH _NET_WM_STATE_MAXIMIZED_* 사용 (live 테스트 검증).
export DISPLAY=:100

# 언어 변경 재시작 등으로 남은 stale .app_ready 제거 — 아래 창 준비 후 재생성.
# (noVNC startapp.sh 와 달리 xpra 는 app_ready 생성 로직이 없어, 언어 변경 후
#  LOADING_PAGE 의 /ready 폴링이 끝나지 않던 무한 로딩 문제 수정. 2026-06-02)
rm -f /config/.app_ready

# Phase 5 (2026-05-24): X11 root window 흰색 강제. Xpra+Xvfb 의 root 기본은
# 어두운 회색 — Orange3 캔버스 영역 양옆/위/아래에 노출됨. 재시도 루프로
# X 서버 ready 직후 적용 보장. 운영 Dockerfile 의 /etc/openbox/autostart 와
# 별개로 Xpra 환경에서 명시 적용.
for i in $(seq 1 30); do
    xsetroot -solid white 2>/dev/null && { xsetroot -cursor_name left_ptr 2>/dev/null; break; }
    sleep 0.3
done

find_orange_window() {
    # 1순위: "Untitled" 가 들어간 이름 (Orange3 가 자동 생성하는 기본 워크플로우)
    for w in $(xdotool search --onlyvisible "" 2>/dev/null); do
        n=$(xdotool getwindowname "$w" 2>/dev/null)
        case "$n" in *Untitled*Orange*) echo "$w|$n"; return 0 ;; esac
    done
    # 2순위: 헬퍼 제외 + 단독 "Orange" 제외 + 길이 7 이상 (저장된 워크플로우 케이스)
    for w in $(xdotool search --onlyvisible "" 2>/dev/null); do
        n=$(xdotool getwindowname "$w" 2>/dev/null)
        case "$n" in
            ""|"Orange"|*Selection*|*Clipboard*|*Requestor*) continue ;;
            *Orange*)
                [ ${#n} -gt 6 ] && { echo "$w|$n"; return 0; }
                ;;
        esac
    done
    return 1
}

apply_max() {
    # wmctrl EWMH maximize — openbox 가 화면 전체로 확대 (live 테스트 검증됨)
    wmctrl -i -r "$1" -b add,maximized_vert,maximized_horz 2>/dev/null
    # Phase 5 (2026-05-23): 윈도우 데코레이션(타이틀바·테두리) 제거 —
    # Xpra+openbox 환경에서 "Untitled — Orange" 타이틀바가 메인 캔버스 위에 노출됨.
    # _MOTIF_WM_HINTS = {flags=DECORATIONS, functions=0, decorations=0, ...}
    # 운영 노VNC(Xvnc) 는 default decoration 없음, Xpra(Xvfb+openbox) 만 영향.
    xprop -id "$1" -f _MOTIF_WM_HINTS 32c \
        -set _MOTIF_WM_HINTS "0x2, 0x0, 0x0, 0x0, 0x0" 2>/dev/null
}

for i in $(seq 1 90); do
    sleep 1
    R=$(find_orange_window)
    if [ -n "$R" ]; then
        WIN="${R%|*}"
        NAME="${R#*|}"
        apply_max "$WIN"
        # xpra geometry sync 여유 — 1.5s 후 한 번 더 확정 (안정성)
        sleep 1.5
        apply_max "$WIN"
        GEO=$(xdotool getwindowgeometry "$WIN" 2>/dev/null | tr '\n' ' ')
        echo "[max] Orange3 maximized: win=$WIN name='$NAME' after ${i}s | $GEO"
        # GUI(메인 캔버스) 준비 완료 → .app_ready 생성 (LOADING_PAGE 의 /ready 폴링 종료 신호)
        touch /config/.app_ready
        echo "[max] .app_ready 생성됨"
        break
    fi
done
